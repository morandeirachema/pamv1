package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// fakeDirectory reports per-username (exists, enabled) status.
type fakeDirectory struct {
	status map[string]struct{ exists, enabled bool }
}

func (f fakeDirectory) UserStatus(_ context.Context, username string) (bool, bool, error) {
	s, ok := f.status[username]
	if !ok {
		return false, false, nil
	}
	return s.exists, s.enabled, nil
}

func TestIdentityReconcile(t *testing.T) {
	dir := fakeDirectory{status: map[string]struct{ exists, enabled bool }{
		"enabled-user":  {true, true},
		"disabled-user": {true, false},
		// "local-only" absent from the directory entirely.
	}}
	srv, _ := newTestServerOpts(t, nil, api.Options{Directory: dir})

	seedUser(t, srv, "enabled-user", "user")
	seedUser(t, srv, "disabled-user", "user")
	seedUser(t, srv, "local-only", "user")

	// Dry run: reports the disabled user but changes nothing.
	status, data := do(t, srv, http.MethodPost, "/api/identity/reconcile?dry_run=true", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("dry run: %d %s", status, data)
	}
	m := jsonMap(t, data)
	if m["disabled"].(float64) != 1 || m["dry_run"] != true {
		t.Fatalf("dry run result: %s", data)
	}
	// The disabled user still exists after a dry run.
	_, data = do(t, srv, http.MethodGet, "/api/users", testAPIKey, nil)
	var users []map[string]any
	json.Unmarshal(data, &users)
	if len(users) != 3 {
		t.Fatalf("dry run must not delete: %d users", len(users))
	}

	// Real run: revokes the disabled directory user, keeps the others.
	status, data = do(t, srv, http.MethodPost, "/api/identity/reconcile", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("reconcile: %d %s", status, data)
	}
	if jsonMap(t, data)["disabled"].(float64) != 1 {
		t.Fatalf("expected 1 disabled: %s", data)
	}
	_, data = do(t, srv, http.MethodGet, "/api/users", testAPIKey, nil)
	json.Unmarshal(data, &users)
	names := map[string]bool{}
	for _, u := range users {
		names[u["username"].(string)] = true
	}
	if names["disabled-user"] {
		t.Fatal("disabled directory user was not revoked")
	}
	if !names["enabled-user"] || !names["local-only"] {
		t.Fatal("an active or local-only user was wrongly revoked")
	}
}

func TestIdentityReconcileNoDirectory(t *testing.T) {
	srv := newTestServer(t) // no Directory configured
	if status, _ := do(t, srv, http.MethodPost, "/api/identity/reconcile", testAPIKey, nil); status != http.StatusServiceUnavailable {
		t.Fatalf("no directory: want 503, got %d", status)
	}
}
