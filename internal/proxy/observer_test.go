package proxy_test

import (
	"testing"

	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// TestObserverSessionRefusesExec proves a read-only "+observe" session may
// authenticate and open a channel, but cannot run a command (exec is refused) —
// so an observer sees output without injecting keystrokes.
func TestObserverSessionRefusesExec(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	addr := startProxy(t, st, v, t.TempDir())

	client, err := dialProxy(t, addr, "web-01+observe", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth should pass: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	defer sess.Close()
	if out, err := sess.Output("run"); err == nil {
		t.Fatalf("observer must not be able to exec, got output %q", out)
	}
}

// TestInteractiveSessionStillRuns is the contrast: without the +observe suffix,
// the same target executes normally.
func TestInteractiveSessionStillRuns(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	seedTarget(t, st, v, host, port)
	addr := startProxy(t, st, v, t.TempDir())

	client, err := dialProxy(t, addr, "web-01", proxyAPIKey)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("run")
	if err != nil || string(out) != targetOutput {
		t.Fatalf("interactive exec: out=%q err=%v", out, err)
	}
}
