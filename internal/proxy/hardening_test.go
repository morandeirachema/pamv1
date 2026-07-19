package proxy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestCredentialDecryptedOnlyAfterAuthz proves the JIT secret is decrypted only
// after every authorization gate passes: a session denied by policy must not
// materialize plaintext. The credential is deliberately undecryptable, so any
// decryption attempt is observable as a failure in the audit trail.
func TestCredentialDecryptedOnlyAfterAuthz(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	v := mustVault(t)
	target := &store.Target{Name: "web-01", Host: "127.0.0.1", Port: 65000, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateCredential(ctx, &store.Credential{
		TargetID: target.ID, Username: upstreamUser, SecretType: "password",
		SecretEnc: "v1:not-a-real-token",
	}); err != nil {
		t.Fatal(err)
	}

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	// The protocol allowlist forbids ssh, so the connect is denied by the protocol
	// gate — which runs before decryption.
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey:          mustSigner(t),
		RecordingDir:     t.TempDir(),
		AllowedProtocols: []string{"winrm"},
	})
	if err != nil {
		t.Fatal(err)
	}
	addr := serveProxy(t, px)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if sess, e := client.NewSession(); e == nil {
		sess.Close()
		t.Fatal("session opened for a policy-forbidden protocol")
	}
	client.Close()

	events, err := st.ListAudit(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	var gateDenied, decryptAttempted bool
	for _, e := range events {
		if strings.Contains(e.Detail, "protocol-not-allowed") {
			gateDenied = true
		}
		if e.Action == "credential.decrypt_failed" || strings.Contains(e.Detail, "decryption failed") {
			decryptAttempted = true
		}
	}
	if !gateDenied {
		t.Error("expected the protocol gate to deny the session")
	}
	if decryptAttempted {
		t.Error("credential was decrypted for a policy-denied session — decryption must run only after authz")
	}
}
