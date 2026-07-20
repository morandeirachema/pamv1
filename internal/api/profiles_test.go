package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestCustomProfileEndToEnd proves a custom profile grants exactly its
// capabilities to an assigned user: the user can perform capabilities in the
// profile and is 403'd on those outside it, and the four built-in roles are
// unaffected.
func TestCustomProfileEndToEnd(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})

	// A read-only profile: inventory + audit, nothing else.
	if code, d := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{
		"name": "readonly", "capabilities": []string{"read_inventory", "read_audit"},
	}); code != http.StatusCreated {
		t.Fatalf("create profile: %d %s", code, d)
	}
	// A profile name that shadows a built-in role is rejected.
	if code, _ := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{"name": "admin", "capabilities": []string{"read_inventory"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("shadowing profile: want 422, got %d", code)
	}
	// An unknown capability is rejected.
	if code, _ := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{"name": "bogus", "capabilities": []string{"fly"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown capability: want 422, got %d", code)
	}

	// Assign the profile to a user.
	_, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "ro", "role": "readonly"})
	tok, _ := jsonMap(t, ud)["token"].(string)
	if tok == "" {
		t.Fatalf("no token for profiled user: %s", ud)
	}

	// /api/me reflects the profile's capabilities.
	_, me := do(t, srv, http.MethodGet, "/api/me", tok, nil)
	if m := string(me); !strings.Contains(m, "read_inventory") || !strings.Contains(m, "read_audit") || strings.Contains(m, "manage_targets") {
		t.Fatalf("me capabilities wrong: %s", me)
	}

	// The profiled user may read inventory (CapReadInventory)...
	if code, _ := do(t, srv, http.MethodGet, "/api/targets", tok, nil); code != http.StatusOK {
		t.Fatalf("read inventory: want 200, got %d", code)
	}
	// ...but not manage targets (CapManageTargets) — 403.
	if code, _ := do(t, srv, http.MethodPost, "/api/targets", tok, map[string]any{"name": "x", "host": "h", "os_type": "linux", "protocol": "ssh"}); code != http.StatusForbidden {
		t.Fatalf("manage targets: want 403, got %d", code)
	}
}

// TestProfileNoEscalation proves a delegated user-admin (a profile carrying only
// manage_users) cannot escalate: it may manage users/profiles but cannot mint a
// full admin or forge a profile with capabilities it does not itself hold.
func TestProfileNoEscalation(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})

	// A delegated user-admin: can manage users + read inventory, nothing sensitive.
	if code, d := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{
		"name": "useradmin", "capabilities": []string{"manage_users", "read_inventory"},
	}); code != http.StatusCreated {
		t.Fatalf("create useradmin profile: %d %s", code, d)
	}
	_, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "ua", "role": "useradmin"})
	uaTok, _ := jsonMap(t, ud)["token"].(string)
	if uaTok == "" {
		t.Fatalf("no useradmin token: %s", ud)
	}

	// It reaches the admin surface (has manage_users) but cannot mint a full admin.
	if code, _ := do(t, srv, http.MethodPost, "/api/users", uaTok, map[string]any{"username": "hax", "role": "admin"}); code != http.StatusForbidden {
		t.Fatalf("delegated user-admin minting admin: want 403, got %d", code)
	}
	// Nor assign a built-in role carrying a capability it lacks (auditor→read_audit).
	if code, _ := do(t, srv, http.MethodPost, "/api/users", uaTok, map[string]any{"username": "hax2", "role": "auditor"}); code != http.StatusForbidden {
		t.Fatalf("delegated user-admin minting auditor: want 403, got %d", code)
	}
	// Nor forge a profile with a capability it lacks.
	if code, _ := do(t, srv, http.MethodPost, "/api/profiles", uaTok, map[string]any{"name": "sneaky", "capabilities": []string{"reveal_secret"}}); code != http.StatusForbidden {
		t.Fatalf("delegated user-admin forging reveal profile: want 403, got %d", code)
	}
	// It CAN act within its own capabilities.
	if code, d := do(t, srv, http.MethodPost, "/api/profiles", uaTok, map[string]any{"name": "ro2", "capabilities": []string{"read_inventory"}}); code != http.StatusCreated {
		t.Fatalf("delegated user-admin creating in-scope profile: %d %s", code, d)
	}
	// The bootstrap admin remains unconstrained.
	if code, _ := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "realadmin", "role": "admin"}); code != http.StatusCreated {
		t.Fatalf("bootstrap admin minting admin: want 201, got %d", code)
	}
}
