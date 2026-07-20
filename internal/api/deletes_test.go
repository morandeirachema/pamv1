package api_test

import (
	"fmt"
	"net/http"
	"testing"
)

// TestDeleteHandlers covers the DELETE credential and DELETE user handlers
// (204 on success, 404 on a repeat) that lacked direct coverage.
func TestDeleteHandlers(t *testing.T) {
	srv := newTestServer(t)

	credID := seedTargetCred(t, srv, "ssh", "", "pw")
	if st, _ := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/credentials/%d", credID), testAPIKey, nil); st != http.StatusNoContent {
		t.Fatalf("delete credential: want 204, got %d", st)
	}
	if st, _ := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/credentials/%d", credID), testAPIKey, nil); st != http.StatusNotFound {
		t.Fatalf("re-delete credential: want 404, got %d", st)
	}

	_, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "del-me", "role": "user"})
	uid := int64(jsonMap(t, ud)["id"].(float64))
	if st, _ := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/users/%d", uid), testAPIKey, nil); st != http.StatusNoContent {
		t.Fatalf("delete user: want 204, got %d", st)
	}
	if st, _ := do(t, srv, http.MethodDelete, fmt.Sprintf("/api/users/%d", uid), testAPIKey, nil); st != http.StatusNotFound {
		t.Fatalf("re-delete user: want 404, got %d", st)
	}
}
