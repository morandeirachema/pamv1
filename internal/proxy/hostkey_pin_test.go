package proxy_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// startUpstreamKeyed is startUpstream with a caller-supplied host key, so the
// test knows the exact public key to pin.
func startUpstreamKeyed(t *testing.T, wantUser, wantPass, output string, hostKey ssh.Signer) (string, int) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == wantUser && string(pass) == wantPass {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("upstream: auth denied")
		},
	}
	cfg.AddHostKey(hostKey)
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

func startProxyPinned(t *testing.T, st store.Store, v *vault.Vault, cb ssh.HostKeyCallback) string {
	t.Helper()
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		UpstreamHostKey: cb,
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

func writeKnownHosts(t *testing.T, host string, port int, key ssh.PublicKey) ssh.HostKeyCallback {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	addr := fmt.Sprintf("%s:%d", host, port)
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		t.Fatal(err)
	}
	return cb
}

func TestUpstreamHostKeyPinnedAccepts(t *testing.T) {
	hostKey := mustSigner(t)
	host, port := startUpstreamKeyed(t, upstreamUser, upstreamSecret, targetOutput, hostKey)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)

	cb := writeKnownHosts(t, host, port, hostKey.PublicKey())
	addr := startProxyPinned(t, st, v, cb)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session should be allowed (host key matches): %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("run")
	if err != nil || string(out) != targetOutput {
		t.Fatalf("exec: out=%q err=%v", out, err)
	}
}

func TestUpstreamHostKeyPinnedRejectsMismatch(t *testing.T) {
	hostKey := mustSigner(t)
	host, port := startUpstreamKeyed(t, upstreamUser, upstreamSecret, targetOutput, hostKey)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)

	// Pin a DIFFERENT key than the upstream actually presents.
	wrongKey := mustSigner(t)
	cb := writeKnownHosts(t, host, port, wrongKey.PublicKey())
	addr := startProxyPinned(t, st, v, cb)

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth should still pass (proxy handshake): %v", err)
	}
	defer client.Close()
	if sess, err := client.NewSession(); err == nil {
		sess.Close()
		t.Fatal("session must be denied when the upstream host key does not match the pin")
	}
}
