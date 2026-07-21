package proxy_test

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/sshca"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// startCertUpstream launches an in-process SSH server that authenticates ONLY
// with a certificate signed by caPub (no password auth is offered at all), so a
// successful session proves the client presented a CA-signed cert — there is no
// standing secret it could have used. It stands in for a target whose sshd sets
// TrustedUserCAKeys to the pamv1 CA.
func startCertUpstream(t *testing.T, caPub ssh.PublicKey, wantUser, output string) (host string, port int) {
	t.Helper()
	checker := &ssh.CertChecker{
		IsUserAuthority: func(a ssh.PublicKey) bool {
			return bytes.Equal(a.Marshal(), caPub.Marshal())
		},
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() != wantUser {
				return nil, errUpstreamUser
			}
			return checker.Authenticate(c, key)
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

var errUpstreamUser = &upstreamErr{"upstream: wrong user"}

type upstreamErr struct{ s string }

func (e *upstreamErr) Error() string { return e.s }

// seedZSPTarget creates an ssh target plus a Zero Standing Privilege credential
// (secret_type ssh_ca, no stored secret) for upstreamUser.
func seedZSPTarget(t *testing.T, st store.Store, name, host string, port int) *store.Target {
	t.Helper()
	ctx := context.Background()
	target := &store.Target{Name: name, Host: host, Port: port, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	// No SecretEnc: a ZSP credential stores nothing — the proxy mints a cert JIT.
	cred := &store.Credential{TargetID: target.ID, Username: upstreamUser, SecretType: "ssh_ca"}
	if err := st.CreateCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	return target
}

// TestZeroStandingPrivilege is the flagship ZSP proof: the operator authenticates
// to the proxy with the PAM key, no secret is stored for the account, yet the
// command runs on an upstream that accepts ONLY a certificate signed by the pamv1
// CA. The certificate can only have been minted just-in-time by the proxy.
func TestZeroStandingPrivilege(t *testing.T) {
	ca := newTestCA(t)
	host, port := startCertUpstream(t, ca.PublicKey(), upstreamUser, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedZSPTarget(t, st, "web-zsp", host, port)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		CA: ca, CertTTL: time.Minute, Sessions: session.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, upstreamUser+"@web-zsp", proxyAPIKey)
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
	sess.Close()
	client.Close()

	// The certificate issuance and the session lifecycle must be audited.
	seen, _ := waitForAudit(t, st, "session.cert_issued", "session.start", "session.end")
	for _, want := range []string{"session.cert_issued", "session.start", "session.end"} {
		if !seen[want] {
			t.Fatalf("missing audit action %q; got %v", want, seen)
		}
	}
}

// TestZSPWithoutCADenied proves that an ssh_ca credential cannot be served when
// no CA is configured on the proxy — it fails closed rather than falling back to
// a (non-existent) stored secret.
func TestZSPWithoutCADenied(t *testing.T) {
	ca := newTestCA(t)
	host, port := startCertUpstream(t, ca.PublicKey(), upstreamUser, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedZSPTarget(t, st, "web-zsp", host, port)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	// No CA configured.
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, upstreamUser+"@web-zsp", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth should pass: %v", err)
	}
	defer client.Close()
	if sess, err := client.NewSession(); err == nil {
		sess.Close()
		t.Fatal("a ZSP session must be denied when no SSH CA is configured")
	}
	if seen, _ := waitForAudit(t, st, "session.error"); !seen["session.error"] {
		t.Fatal("a ZSP-without-CA denial must be audited as session.error")
	}
}

// newTestCA builds a CertAuthority backed by a fresh signer for the proxy tests.
func newTestCA(t *testing.T) *sshca.CertAuthority {
	t.Helper()
	return sshca.New(mustSigner(t))
}
