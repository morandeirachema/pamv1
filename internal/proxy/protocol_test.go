package proxy_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestProxyProtocolAllowlist proves the proxy refuses a session to an ssh target
// when ssh is not in the configured protocol allowlist.
func TestProxyProtocolAllowlist(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)

	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		AllowedProtocols: []string{"winrm"}, // ssh deliberately excluded
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

	client, err := dialProxy(t, ln.Addr().String(), "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth should pass: %v", err)
	}
	defer client.Close()
	if sess, err := client.NewSession(); err == nil {
		sess.Close()
		t.Fatal("session must be denied when ssh is not allowed by policy")
	}
}
