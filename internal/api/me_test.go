package api_test

import (
	"net/http"
	"testing"
)

// TestMeReportsRoleAndCapabilities proves /api/me returns the caller's role and
// the stable capability names its role holds — the contract the portal's
// role-aware menu depends on.
func TestMeReportsRoleAndCapabilities(t *testing.T) {
	srv := newTestServer(t)

	// The bootstrap admin holds every capability.
	_, data := do(t, srv, http.MethodGet, "/api/me", testAPIKey, nil)
	m := jsonMap(t, data)
	if m["role"] != "admin" {
		t.Fatalf("admin role = %v", m["role"])
	}
	if caps, _ := m["capabilities"].([]any); len(caps) != 8 {
		t.Fatalf("admin should hold all 8 capabilities, got %v", m["capabilities"])
	}

	// A minted auditor token sees only the auditor capability set.
	_, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "al", "role": "auditor"})
	tok, _ := jsonMap(t, ud)["token"].(string)
	if tok == "" {
		t.Fatal("user create did not return a token")
	}
	_, ad := do(t, srv, http.MethodGet, "/api/me", tok, nil)
	am := jsonMap(t, ad)
	if am["role"] != "auditor" {
		t.Fatalf("auditor role = %v", am["role"])
	}
	got := map[string]bool{}
	for _, c := range am["capabilities"].([]any) {
		got[c.(string)] = true
	}
	if !got["read_inventory"] || !got["read_audit"] {
		t.Fatalf("auditor missing expected capabilities: %v", am["capabilities"])
	}
	if got["manage_users"] || got["reveal_secret"] || got["manage_targets"] {
		t.Fatalf("auditor must not hold admin capabilities: %v", am["capabilities"])
	}
}
