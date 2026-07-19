package proxy_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

const (
	proxyAPIKey    = "proxy-bootstrap-key"
	upstreamSecret = "the-vaulted-upstream-password"
	upstreamUser   = "root"
	targetOutput   = "hello-from-target\n"
)

func mustSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustVault(t *testing.T) *vault.Vault {
	t.Helper()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// startUpstream launches a minimal in-process SSH server that accepts ONLY
// (wantUser, wantPass) and answers every exec/shell with fixed output. It
// stands in for a real target machine.
func startUpstream(t *testing.T, wantUser, wantPass, output string) (host string, port int) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == wantUser && string(pass) == wantPass {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("upstream: auth denied")
		},
	}
	cfg.AddHostKey(mustSigner(t))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveUpstream(conn, cfg, output)
		}
	}()

	h, p, _ := net.SplitHostPort(ln.Addr().String())
	pn, _ := strconv.Atoi(p)
	return h, pn
}

func serveUpstream(conn net.Conn, cfg *ssh.ServerConfig, output string) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range chReqs {
				switch req.Type {
				case "exec", "shell":
					if req.WantReply {
						req.Reply(true, nil)
					}
					io.WriteString(ch, output)
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{0}))
					ch.Close()
				default:
					if req.WantReply {
						req.Reply(true, nil)
					}
				}
			}
		}()
	}
}

// startProxy launches the proxy on an ephemeral port and returns its address.
func startProxy(t *testing.T, st store.Store, v *vault.Vault, recDir string) string {
	t.Helper()
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey:      mustSigner(t),
		RecordingDir: recDir,
		DialTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go px.Serve(ctx, ln)
	return ln.Addr().String()
}

func dialProxy(t *testing.T, addr, login, password string) (*ssh.Client, error) {
	t.Helper()
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            login,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
}

func seedTarget(t *testing.T, st store.Store, v *vault.Vault, host string, port int) *store.Target {
	t.Helper()
	ctx := context.Background()
	target := &store.Target{Name: "web-01", Host: host, Port: port, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	enc, err := v.Encrypt(context.Background(), upstreamSecret, store.CredentialAAD(target.ID))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCredential(ctx, &store.Credential{
		TargetID: target.ID, Username: upstreamUser, SecretType: "password", SecretEnc: enc,
	}); err != nil {
		t.Fatal(err)
	}
	return target
}

// TestJITInjection is the flagship proof: the client authenticates to the
// proxy with the PAM API key and never learns upstreamSecret, yet the command
// runs on an upstream server that accepts ONLY upstreamSecret. The credential
// can only have come from the vault, injected just-in-time by the proxy.
func TestJITInjection(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	recDir := t.TempDir()
	addr := startProxy(t, st, v, recDir)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	out, err := sess.Output("whoami")
	if err != nil {
		t.Fatalf("exec through proxy: %v", err)
	}
	if string(out) != targetOutput {
		t.Fatalf("output = %q, want %q", out, targetOutput)
	}
	// Close the connection so the deferred session.end audit fires.
	sess.Close()
	client.Close()

	// Audit trail must record start, end and the recording.
	seen, recDetail := waitForAudit(t, st, "session.start", "session.end", "session.record")
	for _, want := range []string{"session.start", "session.end", "session.record"} {
		if !seen[want] {
			t.Fatalf("missing audit action %q; got %v", want, seen)
		}
	}

	// The recording exists and its on-disk SHA-256 matches the audited hash.
	file := fieldAfter(recDetail, "file:")
	wantHash := fieldAfter(recDetail, "sha256:")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != wantHash {
		t.Fatalf("recording hash mismatch: file=%s audit=%s", hex.EncodeToString(sum[:]), wantHash)
	}
	if !strings.Contains(string(data), "hello-from-target") {
		t.Fatalf("recording missing target output:\n%s", data)
	}
}

func TestWrongProxyKeyRejected(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	addr := startProxy(t, st, v, t.TempDir())

	if c, err := dialProxy(t, addr, "web-01", "wrong-key"); err == nil {
		c.Close()
		t.Fatal("proxy accepted a wrong API key")
	}
}

func TestUnknownTargetDenied(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	addr := startProxy(t, st, v, t.TempDir())

	client, err := dialProxy(t, addr, "does-not-exist", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth should pass (api key valid): %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err == nil {
		sess.Close()
		t.Fatal("session to unknown target should be rejected")
	}
}

func TestSpecificCredentialSelector(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	addr := startProxy(t, st, v, t.TempDir())

	// "root@web-01" selects the credential whose username is root.
	client, err := dialProxy(t, addr, upstreamUser+"@web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("id")
	if err != nil || string(out) != targetOutput {
		t.Fatalf("cred selector flow failed: out=%q err=%v", out, err)
	}
}

// waitForAudit polls the store until all wanted actions appear (or times
// out), returning the set of seen actions and the session.record detail.
func waitForAudit(t *testing.T, st store.Store, want ...string) (map[string]bool, string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		events, err := st.ListAudit(context.Background(), 50)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		recDetail := ""
		for _, e := range events {
			seen[e.Action] = true
			if e.Action == "session.record" {
				recDetail = e.Detail
			}
		}
		all := true
		for _, w := range want {
			if !seen[w] {
				all = false
				break
			}
		}
		if all || time.Now().After(deadline) {
			return seen, recDetail
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestAuditorCannotConnect verifies the RBAC gate on the proxy: an auditor
// authenticates (valid token) but may not open a session.
func TestAuditorCannotConnect(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)

	// Register an auditor user with a known token.
	const auditorToken = "pamt-auditor-token"
	sum := sha256.Sum256([]byte(auditorToken))
	if err := st.CreateUser(context.Background(), &store.User{
		Username: "theo", Role: "auditor", TokenHash: hex.EncodeToString(sum[:]),
	}); err != nil {
		t.Fatal(err)
	}
	addr := startProxy(t, st, v, t.TempDir())

	client, err := dialProxy(t, addr, "web-01", auditorToken)
	if err != nil {
		t.Fatalf("auditor auth should pass: %v", err)
	}
	defer client.Close()
	if sess, err := client.NewSession(); err == nil {
		sess.Close()
		t.Fatal("auditor must not be able to open a proxied session")
	}

	seen, _ := waitForAudit(t, st, "session.denied")
	if !seen["session.denied"] {
		t.Fatal("auditor connect attempt must be audited as session.denied")
	}
}

// TestTargetGrantDeniesUngranted verifies per-target authorization: a user who
// is not granted access to a target may authenticate but not connect to it.
func TestTargetGrantDeniesUngranted(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)

	const aliceToken = "pamt-alice-token"
	sum := sha256.Sum256([]byte(aliceToken))
	if err := st.CreateUser(context.Background(), &store.User{
		Username: "alice", Role: "user", TokenHash: hex.EncodeToString(sum[:]),
	}); err != nil {
		t.Fatal(err)
	}
	// Grant the target to "bob" only — alice is excluded.
	if err := st.CreateTargetGrant(context.Background(), &store.TargetGrant{
		TargetID: target.ID, SubjectType: "user", Subject: "bob",
	}); err != nil {
		t.Fatal(err)
	}
	addr := startProxy(t, st, v, t.TempDir())

	client, err := dialProxy(t, addr, "web-01", aliceToken)
	if err != nil {
		t.Fatalf("alice auth should pass: %v", err)
	}
	defer client.Close()
	if sess, err := client.NewSession(); err == nil {
		sess.Close()
		t.Fatal("ungranted user must not open a session to the target")
	}
	if seen, _ := waitForAudit(t, st, "session.denied"); !seen["session.denied"] {
		t.Fatal("target-policy denial must be audited")
	}
}

// TestApprovalGateProxy proves the proxy honors the 4-eyes approval gate: with
// RequireApproval on, a session is denied until an approved access request
// exists for the actor+target.
func TestApprovalGateProxy(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		RequireApproval: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go px.Serve(ctx, ln)
	addr := ln.Addr().String()

	// No approval yet: authentication passes but the session is denied.
	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth should pass: %v", err)
	}
	if sess, err := client.NewSession(); err == nil {
		sess.Close()
		client.Close()
		t.Fatal("session must be denied without an approved request")
	}
	client.Close()

	// Seed an approved, unexpired request for the proxy actor (bootstrap-admin).
	if err := st.CreateAccessRequest(context.Background(), &store.AccessRequest{
		Requester: "bootstrap-admin", TargetID: target.ID, Status: "approved",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	client2, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth should pass: %v", err)
	}
	defer client2.Close()
	sess, err := client2.NewSession()
	if err != nil {
		t.Fatalf("session must be allowed after approval: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("run")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if string(out) != targetOutput {
		t.Fatalf("output = %q, want %q", out, targetOutput)
	}
}

func fieldAfter(s, key string) string {
	i := strings.Index(s, key)
	if i < 0 {
		return ""
	}
	rest := s[i+len(key):]
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		return rest[:j]
	}
	return rest
}
