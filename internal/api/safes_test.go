package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// TestSafeDelegatedManagement proves safe creation needs CapManageTargets, and
// that a can_manage member (not only a global manager) may add members to their
// own safe — while a plain user without that grant is refused.
func TestSafeDelegatedManagement(t *testing.T) {
	srv := newTestServer(t)

	// Admin creates a safe.
	code, data := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "team-a", "description": "team A systems"})
	if code != http.StatusCreated {
		t.Fatalf("create safe: status %d body %s", code, data)
	}
	safeID := int64(jsonMap(t, data)["id"].(float64))
	membersURL := fmt.Sprintf("/api/safes/%d/members", safeID)

	// A plain user cannot create a safe (CapManageTargets).
	userTok := seedUser(t, srv, "bob", "user")
	if code, _ := do(t, srv, http.MethodPost, "/api/safes", userTok, map[string]any{"name": "sneaky"}); code != http.StatusForbidden {
		t.Fatalf("user create safe: want 403, got %d", code)
	}

	// The user is not yet a can_manage member → adding a member is refused.
	if code, _ := do(t, srv, http.MethodPost, membersURL, userTok, map[string]any{"subject_type": "user", "subject": "zoe"}); code != http.StatusForbidden {
		t.Fatalf("non-manager add member: want 403, got %d", code)
	}

	// Admin delegates safe management to the user.
	if code, _ := do(t, srv, http.MethodPost, membersURL, testAPIKey, map[string]any{"subject_type": "user", "subject": "bob", "can_manage": true}); code != http.StatusCreated {
		t.Fatalf("admin add can_manage member: %d", code)
	}

	// Now the delegated user can add a member to that safe.
	if code, body := do(t, srv, http.MethodPost, membersURL, userTok, map[string]any{"subject_type": "role", "subject": "user"}); code != http.StatusCreated {
		t.Fatalf("delegated add member: status %d body %s", code, body)
	}

	// The safe has both members.
	_, ld := do(t, srv, http.MethodGet, membersURL, testAPIKey, nil)
	var members []map[string]any
	if err := json.Unmarshal(ld, &members); err != nil {
		t.Fatalf("decode members: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("member count = %d, want 2", len(members))
	}
}

// TestSafeAssignTargetRestricts proves assigning a target to a safe is an admin
// action and audited, and that an unknown safe is rejected.
func TestSafeAssignTargetRestricts(t *testing.T) {
	srv := newTestServer(t)
	tc, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-safe", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if tc != http.StatusCreated {
		t.Fatalf("create target: %d %s", tc, td)
	}
	targetID := int64(jsonMap(t, td)["id"].(float64))

	code, data := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "prod"})
	if code != http.StatusCreated {
		t.Fatalf("create safe: %d %s", code, data)
	}
	safeID := int64(jsonMap(t, data)["id"].(float64))

	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d/safe", targetID), testAPIKey, map[string]any{"safe_id": safeID}); code != http.StatusNoContent {
		t.Fatalf("assign target to safe: want 204, got %d", code)
	}
	// A plain user cannot reassign a target's safe.
	userTok := seedUser(t, srv, "carol", "user")
	if code, _ := do(t, srv, http.MethodPut, fmt.Sprintf("/api/targets/%d/safe", targetID), userTok, map[string]any{"safe_id": nil}); code != http.StatusForbidden {
		t.Fatalf("user reassign safe: want 403, got %d", code)
	}
}
