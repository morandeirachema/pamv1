package api_test

import (
	"net/http"
	"testing"
)

// TestAuditVerifyEndpoint covers GET /api/audit/verify: 501 when chaining is off,
// and ok=true once enabled and events have been appended through real actions.
func TestAuditVerifyEndpoint(t *testing.T) {
	srv, st := newTestServerStore(t)

	// Not enabled yet → 501 Not Implemented.
	status, _ := do(t, srv, http.MethodGet, "/api/audit/verify", testAPIKey, nil)
	if status != http.StatusNotImplemented {
		t.Fatalf("verify (chain off): want 501, got %d", status)
	}

	// Enable chaining, then perform an audited action.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	st.EnableAuditChain(key)
	if s, _ := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	}); s != http.StatusCreated {
		t.Fatalf("create target: %d", s)
	}

	status, data := do(t, srv, http.MethodGet, "/api/audit/verify", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("verify (chain on): want 200, got %d (%s)", status, data)
	}
	m := jsonMap(t, data)
	if ok, _ := m["ok"].(bool); !ok {
		t.Fatalf("verify: want ok=true, got %s", data)
	}
}
