package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestWebhookNotify verifies the webhook delivers the event as JSON to its URL.
func TestWebhookNotify(t *testing.T) {
	got := make(chan Event, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var e Event
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &e)
		got <- e
	}))
	defer srv.Close()

	NewWebhook(srv.URL).Notify(context.Background(), Event{
		Type: "breakglass.access", Actor: "break-glass", Detail: "GET /api/targets", Time: time.Unix(1, 0),
	})

	select {
	case e := <-got:
		if e.Type != "breakglass.access" || e.Actor != "break-glass" {
			t.Fatalf("unexpected alert: %+v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook was not called")
	}
}

// TestNoop verifies the Noop notifier neither panics nor blocks.
func TestNoop(t *testing.T) {
	// Must not panic or block.
	Noop{}.Notify(context.Background(), Event{Type: "x"})
}
