package proxy_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestDBProxyEnrollOnlyRejected proves the database proxy refuses an MFA
// enrollment-only session (scope "enroll") — mirroring the SSH proxy and the HTTP
// API — so a mandatory-MFA (PAM_MFA_REQUIRED) policy cannot be bypassed by
// connecting to a database target before completing enrollment.
func TestDBProxyEnrollOnlyRejected(t *testing.T) {
	st := memstore.New()
	v := mustVault(t)
	fake := startFakePostgres(t, upstreamSecret)
	seedPGTarget(t, st, v, fake.addr)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	// An enrollment-only login session for a connect-capable user.
	const enrollToken = "enroll-session-token-abc123"
	sum := sha256.Sum256([]byte(enrollToken))
	if err := st.CreateSession(context.Background(), &store.Session{
		Username: "alice", Role: "user", Scope: auth.SessionScopeEnroll,
		TokenHash: hex.EncodeToString(sum[:]), ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}); err != nil {
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
	fe.Send(&pgproto3.PasswordMessage{Password: enrollToken})
	_ = fe.Flush()

	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("expected an ErrorResponse, got transport error: %v", err)
	}
	if _, ok := msg.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("expected ErrorResponse for an enroll-only session, got %T", msg)
	}
	if fake.password() != "" {
		t.Fatal("upstream was contacted for an enroll-only (MFA-pending) session")
	}
}
