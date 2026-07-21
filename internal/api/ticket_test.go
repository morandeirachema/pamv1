package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/ticket"
)

// auditHas fails unless some audit event has the given action and a detail
// containing want.
func auditHas(t *testing.T, st store.Store, action, want string) {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 200)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Action == action && strings.Contains(e.Detail, want) {
			return
		}
	}
	t.Fatalf("no audit event action=%q containing %q", action, want)
}

// TestTicketGate proves the ITSM ticket gate: a required ticket must be present,
// must match the configured format, and must be accepted by the ITSM webhook
// before an access request is created; the ticket is recorded on the request.
func TestTicketGate(t *testing.T) {
	// Fake ITSM: only ticket "CHG1234" is a valid, approved change.
	itsm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["ticket"] == "CHG1234" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(itsm.Close)

	tv, err := ticket.New(`^CHG[0-9]{3,}$`, itsm.URL)
	if err != nil {
		t.Fatal(err)
	}
	srv, st := newTestServerOpts(t, nil, api.Options{TicketValidator: tv, RequireTicket: true})

	tc, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "prod-x", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if tc != http.StatusCreated {
		t.Fatalf("create target: %d %s", tc, td)
	}
	targetID := int64(jsonMap(t, td)["id"].(float64))
	reqURL := "/api/access-requests"

	// No ticket → refused (required).
	if code, _ := do(t, srv, http.MethodPost, reqURL, testAPIKey, map[string]any{"target_id": targetID, "reason": "maint"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("missing ticket: want 422, got %d", code)
	}
	// Bad format → refused by the regex before any webhook call.
	if code, _ := do(t, srv, http.MethodPost, reqURL, testAPIKey, map[string]any{"target_id": targetID, "reason": "maint", "ticket": "INC1"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad-format ticket: want 422, got %d", code)
	}
	// Right format but the ITSM webhook rejects it → refused.
	if code, _ := do(t, srv, http.MethodPost, reqURL, testAPIKey, map[string]any{"target_id": targetID, "reason": "maint", "ticket": "CHG555"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("webhook-rejected ticket: want 422, got %d", code)
	}
	// A valid, ITSM-approved ticket → the request is created and carries it.
	code, data := do(t, srv, http.MethodPost, reqURL, testAPIKey, map[string]any{"target_id": targetID, "reason": "maint", "ticket": "CHG1234"})
	if code != http.StatusCreated {
		t.Fatalf("valid ticket: want 201, got %d %s", code, data)
	}
	if jsonMap(t, data)["ticket"] != "CHG1234" {
		t.Fatalf("created request did not record the ticket: %s", data)
	}

	// The rejection and the accepted request are both audited (ticket recorded).
	auditHas(t, st, "access.ticket_rejected", "CHG555")
	auditHas(t, st, "access.request", "CHG1234")
}

// TestTicketGateDisabled proves that with no validator and no requirement, access
// requests work exactly as before (no ticket needed).
func TestTicketGateDisabled(t *testing.T) {
	srv := newTestServer(t) // no TicketValidator, RequireTicket=false
	tc, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "t-noticket", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if tc != http.StatusCreated {
		t.Fatalf("create target: %d %s", tc, td)
	}
	targetID := int64(jsonMap(t, td)["id"].(float64))
	if code, _ := do(t, srv, http.MethodPost, "/api/access-requests", testAPIKey, map[string]any{"target_id": targetID, "reason": "maint"}); code != http.StatusCreated {
		t.Fatalf("no-ticket request with gate disabled: want 201, got %d", code)
	}
}
