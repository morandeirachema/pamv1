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

// TestPostSessionRotationCallback proves the proxy invokes OnSessionEnd with the
// credential ID once a proxied session ends — the hook that forces post-session
// rotation.
func TestPostSessionRotationCallback(t *testing.T) {
	host, port := startUpstream(t, upstreamUser, upstreamSecret, targetOutput)
	st := memstore.New()
	v := mustVault(t)
	target := seedTarget(t, st, v, host, port)
	creds, _ := st.ListCredentials(context.Background(), target.ID)
	credID := creds[0].ID

	fired := make(chan int64, 1)
	resolver, err := auth.NewResolver(st, proxyAPIKey, "")
	if err != nil {
		t.Fatal(err)
	}
	px, err := proxy.New(st, v, resolver, proxy.Config{
		HostKey: mustSigner(t), RecordingDir: t.TempDir(), DialTimeout: 5 * time.Second,
		OnSessionEnd: func(id int64) { fired <- id },
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
		t.Fatalf("dial: %v", err)
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if _, err := sess.Output("run"); err != nil {
		t.Fatalf("exec: %v", err)
	}
	sess.Close()
	client.Close()

	select {
	case id := <-fired:
		if id != credID {
			t.Fatalf("OnSessionEnd cred id = %d, want %d", id, credID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("OnSessionEnd was not called after the session ended")
	}
}
