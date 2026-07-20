package proxy_test

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// fakePostgres is a minimal in-process PostgreSQL server that accepts ONLY
// wantPass. It records the password it was handed and the queries it received,
// then answers each simple query with an empty successful result. It stands in
// for a real database, so a passing test proves the proxy authenticated the
// upstream with the vaulted secret — never the operator's PAM key.
type fakePostgres struct {
	addr string
	mu   sync.Mutex
	pass string
	qs   []string
}

// startFakePostgres launches the fake upstream on an ephemeral port.
func startFakePostgres(t *testing.T, wantPass string) *fakePostgres {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakePostgres{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, wantPass)
		}
	}()
	return f
}

// serve handles one upstream connection: startup, cleartext auth (accepting only
// wantPass), then a simple-query loop.
func (f *fakePostgres) serve(conn net.Conn, wantPass string) {
	defer conn.Close()
	be := pgproto3.NewBackend(conn, conn)
	for started := false; !started; {
		msg, err := be.ReceiveStartupMessage()
		if err != nil {
			return
		}
		switch msg.(type) {
		case *pgproto3.SSLRequest, *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{'N'}); err != nil { // no TLS on the fake
				return
			}
		case *pgproto3.StartupMessage:
			started = true
		default:
			return
		}
	}
	be.Send(&pgproto3.AuthenticationCleartextPassword{})
	if be.Flush() != nil {
		return
	}
	if be.SetAuthType(pgproto3.AuthTypeCleartextPassword) != nil {
		return
	}
	m, err := be.Receive()
	if err != nil {
		return
	}
	pw, ok := m.(*pgproto3.PasswordMessage)
	if !ok {
		return
	}
	f.mu.Lock()
	f.pass = pw.Password
	f.mu.Unlock()
	if pw.Password != wantPass {
		be.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"})
		_ = be.Flush()
		return
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16.0"})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 2}})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if be.Flush() != nil {
		return
	}
	for {
		m, err := be.Receive()
		if err != nil {
			return
		}
		switch msg := m.(type) {
		case *pgproto3.Query:
			f.mu.Lock()
			f.qs = append(f.qs, msg.String)
			f.mu.Unlock()
			be.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if be.Flush() != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

// password returns the password the fake was handed by the proxy.
func (f *fakePostgres) password() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pass
}

// lastQuery returns the most recent query the fake received.
func (f *fakePostgres) lastQuery() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.qs) == 0 {
		return ""
	}
	return f.qs[len(f.qs)-1]
}

// serveDBProxy serves dbx on an ephemeral port and returns its address, waiting
// in cleanup for Serve to fully return (mirrors serveProxy for the SSH proxy).
func serveDBProxy(t *testing.T, dbx *proxy.DBProxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = dbx.Serve(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ln.Addr().String()
}

// seedPGTarget creates a "pg-01" postgres target pointing at addr, plus a vaulted
// password credential (dbuser / upstreamSecret).
func seedPGTarget(t *testing.T, st store.Store, v *vault.Vault, addr string) {
	t.Helper()
	ctx := context.Background()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	target := &store.Target{Name: "pg-01", Host: host, Port: port, OSType: "linux", Protocol: "postgres"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	cred := &store.Credential{TargetID: target.ID, Username: "dbuser", SecretType: "password"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	enc, err := v.Encrypt(ctx, upstreamSecret, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateCredentialSecretEnc(ctx, cred.ID, enc); err != nil {
		t.Fatal(err)
	}
}

// waitReady reads relayed backend messages until ReadyForQuery, failing on an
// ErrorResponse or transport error.
func waitReady(t *testing.T, fe *pgproto3.Frontend) {
	t.Helper()
	for {
		msg, err := fe.Receive()
		if err != nil {
			t.Fatalf("frontend receive: %v", err)
		}
		switch m := msg.(type) {
		case *pgproto3.ReadyForQuery:
			return
		case *pgproto3.ErrorResponse:
			t.Fatalf("server error: %s", m.Message)
		}
	}
}

// TestDBProxyJITInjection proves the Postgres proxy injects the vaulted
// credential just-in-time: the operator authenticates with the PAM key, yet the
// upstream (which accepts ONLY the vaulted secret) runs the query — so the
// operator never held the database password — and the SQL is audited.
func TestDBProxyJITInjection(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePostgres(t, upstreamSecret)
	seedPGTarget(t, st, v, fake.addr)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	dbx, err := proxy.NewDB(st, v, resolver, proxy.DBConfig{RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveDBProxy(t, dbx)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "dbuser@pg-01", "database": "appdb"},
	})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}

	// The proxy asks for a password; send the PAM key — NOT the vaulted secret.
	msg, err := fe.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := msg.(*pgproto3.AuthenticationCleartextPassword); !ok {
		t.Fatalf("expected cleartext-password request, got %T", msg)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: proxyAPIKey})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}

	waitReady(t, fe) // AuthenticationOk + upstream params relayed
	fe.Send(&pgproto3.Query{String: "SELECT 1"})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	waitReady(t, fe)
	fe.Send(&pgproto3.Terminate{})
	_ = fe.Flush()

	// The upstream must have been authenticated with the VAULTED secret.
	if got := fake.password(); got != upstreamSecret {
		t.Fatalf("upstream password %q; the proxy did not inject the vaulted secret", got)
	}
	if fake.password() == proxyAPIKey {
		t.Fatal("the operator's PAM key reached the database")
	}
	if got := fake.lastQuery(); got != "SELECT 1" {
		t.Fatalf("upstream saw query %q, want SELECT 1", got)
	}

	// The SQL and the session start are audited.
	assertDBAudit(t, st, "db.query", "SELECT 1")
	assertDBAudit(t, st, "db.session.start", "pg-01")
}

// TestDBProxyWrongKeyRejected proves an unauthenticated operator (bad PAM key)
// is refused before any upstream credential is touched.
func TestDBProxyWrongKeyRejected(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePostgres(t, upstreamSecret)
	seedPGTarget(t, st, v, fake.addr)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	dbx, err := proxy.NewDB(st, v, resolver, proxy.DBConfig{RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveDBProxy(t, dbx)

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "dbuser@pg-01", "database": "appdb"},
	})
	_ = fe.Flush()
	if _, err := fe.Receive(); err != nil { // cleartext request
		t.Fatal(err)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: "wrong-key"})
	_ = fe.Flush()

	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("expected an ErrorResponse, got transport error: %v", err)
	}
	if _, ok := msg.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("expected ErrorResponse for a bad key, got %T", msg)
	}
	if fake.password() != "" {
		t.Fatal("upstream was contacted for an unauthenticated operator")
	}
}

// assertDBAudit fails unless some audit event has the given action and a detail
// containing want.
func assertDBAudit(t *testing.T, st store.Store, action, want string) {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == action && strings.Contains(e.Detail, want) {
			return
		}
	}
	t.Fatalf("no audit event action=%q containing %q (have %d events)", action, want, len(events))
}
