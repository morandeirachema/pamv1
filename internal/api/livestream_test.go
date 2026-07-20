package api_test

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/session"
)

// TestSessionStreamSSE proves an authorized supervisor can watch a live session
// over the SSE endpoint and receives the published output frames.
func TestSessionStreamSSE(t *testing.T) {
	hub := session.NewHub()
	srv, _ := newTestServerOpts(t, nil, api.Options{Live: hub})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/sessions/sess-1/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", testAPIKey) // admin holds CapReadAudit
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}

	// The handler subscribed before flushing headers, so publishing now is safe;
	// repeat to cover any scheduling delay before the reader is ready.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				hub.Publish("sess-1", []byte("live-output-42"))
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	defer close(stop)

	br := bufio.NewReader(resp.Body)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading SSE stream: %v", err)
		}
		if strings.Contains(line, "live-output-42") {
			return // received the live frame
		}
	}
	t.Fatal("did not receive the live frame over SSE")
}

// TestSessionStreamRequiresAudit proves a role without CapReadAudit cannot watch
// a session (the endpoint is authz-gated like the session list).
func TestSessionStreamRequiresAudit(t *testing.T) {
	hub := session.NewHub()
	srv, _ := newTestServerOpts(t, nil, api.Options{Live: hub})
	userTok := seedUser(t, srv, "bob", "user") // user lacks CapReadAudit

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/sessions/sess-1/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", userTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}
