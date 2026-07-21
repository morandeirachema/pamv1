package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestMultiApproverChain proves an N-of-M approval chain: the request is granted
// only once the required number of DISTINCT approvers approve; an approver
// cannot approve twice.
func TestMultiApproverChain(t *testing.T) {
	srv := newTestServer(t)
	tc, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "prod-chain", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if tc != http.StatusCreated {
		t.Fatalf("create target: %d %s", tc, td)
	}
	targetID := int64(jsonMap(t, td)["id"].(float64))

	reqTok := seedUser(t, srv, "req", "user")
	app1 := seedUser(t, srv, "app1", "approver")
	app2 := seedUser(t, srv, "app2", "approver")

	// File a request that needs TWO distinct approvals.
	code, data := do(t, srv, http.MethodPost, "/api/access-requests", reqTok, map[string]any{
		"target_id": targetID, "reason": "maintenance", "approvals": 2,
	})
	if code != http.StatusCreated {
		t.Fatalf("file request: %d %s", code, data)
	}
	reqID := int64(jsonMap(t, data)["id"].(float64))
	approve := fmt.Sprintf("/api/access-requests/%d/approve", reqID)

	// First approval → still pending (1 of 2).
	_, d1 := do(t, srv, http.MethodPost, approve, app1, nil)
	if jsonMap(t, d1)["status"] != "pending" {
		t.Fatalf("after 1/2 approvals: want pending, got %s", d1)
	}
	// The same approver cannot approve again.
	if c, _ := do(t, srv, http.MethodPost, approve, app1, nil); c != http.StatusConflict {
		t.Fatalf("double approval by the same approver: want 409, got %d", c)
	}
	// A second, distinct approver → approved.
	_, d2 := do(t, srv, http.MethodPost, approve, app2, nil)
	m := jsonMap(t, d2)
	if m["status"] != "approved" {
		t.Fatalf("after 2/2 approvals: want approved, got %s", d2)
	}
	if ab, _ := m["approved_by"].(string); !strings.Contains(ab, "app1") || !strings.Contains(ab, "app2") {
		t.Fatalf("approved_by should list both approvers, got %q", m["approved_by"])
	}
}

// TestMandatoryReason proves PAM_REQUIRE_REASON rejects an empty-reason request.
func TestMandatoryReason(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{RequireReason: true})
	tc, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "prod-reason", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if tc != http.StatusCreated {
		t.Fatalf("create target: %d %s", tc, td)
	}
	targetID := int64(jsonMap(t, td)["id"].(float64))

	if c, _ := do(t, srv, http.MethodPost, "/api/access-requests", testAPIKey, map[string]any{"target_id": targetID}); c != http.StatusUnprocessableEntity {
		t.Fatalf("empty reason with RequireReason: want 422, got %d", c)
	}
	if c, _ := do(t, srv, http.MethodPost, "/api/access-requests", testAPIKey, map[string]any{"target_id": targetID, "reason": "patching CVE-1234"}); c != http.StatusCreated {
		t.Fatalf("with a reason: want 201, got %d", c)
	}
}

// TestScheduledWindow proves an access request accepts and records a scheduled
// maintenance window (not_before / not_after).
func TestScheduledWindow(t *testing.T) {
	srv := newTestServer(t)
	tc, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "prod-window", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if tc != http.StatusCreated {
		t.Fatalf("create target: %d %s", tc, td)
	}
	targetID := int64(jsonMap(t, td)["id"].(float64))

	code, data := do(t, srv, http.MethodPost, "/api/access-requests", testAPIKey, map[string]any{
		"target_id": targetID, "reason": "scheduled maintenance",
		"not_before": "2030-01-01T22:00:00Z", "not_after": "2030-01-01T23:00:00Z",
	})
	if code != http.StatusCreated {
		t.Fatalf("scheduled request: %d %s", code, data)
	}
	if m := jsonMap(t, data); m["not_before"] == nil {
		t.Fatalf("scheduled window not recorded: %s", data)
	}
}
