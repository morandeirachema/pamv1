// Package alert delivers real-time security alerts (e.g. break-glass use) to an
// external endpoint. Delivery is best-effort and non-blocking so it never holds
// up the request that triggered it.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/logging"
)

// Event is a security-relevant occurrence worth alerting on.
type Event struct {
	Type   string    `json:"type"` // e.g. breakglass.access, breakglass.unseal
	Actor  string    `json:"actor"`
	Detail string    `json:"detail"`
	Remote string    `json:"remote,omitempty"`
	Time   time.Time `json:"time"`
}

// Notifier delivers an alert. Implementations must not block the caller.
type Notifier interface {
	Notify(ctx context.Context, e Event)
}

// Noop drops alerts (used when no webhook is configured).
type Noop struct{}

func (Noop) Notify(context.Context, Event) {}

// Webhook POSTs alerts as JSON to a URL (best-effort, fire-and-forget).
type Webhook struct {
	url string
	hc  *http.Client
}

func NewWebhook(url string) *Webhook {
	return &Webhook{url: url, hc: &http.Client{Timeout: 10 * time.Second}}
}

func (w *Webhook) Notify(_ context.Context, e Event) {
	if e.Time.IsZero() {
		// caller should stamp Time; leave as-is otherwise (avoids time.Now here).
	}
	body, err := json.Marshal(e)
	if err != nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := w.hc.Do(req)
		if err != nil {
			logging.Component("alert").Warn("alert delivery failed", "type", e.Type, "err", err)
			return
		}
		resp.Body.Close()
	}()
}
