package api_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestConfigRequiresAdmin proves PUT/DELETE /api/config are restricted to a
// built-in admin — a delegated manage_users profile can reach the route (it holds
// CapManageUsers) but cannot change configuration, closing the escalation vector.
func TestConfigRequiresAdmin(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	if code, _ := do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{"name": "helpdesk", "capabilities": []string{"manage_users"}}); code != http.StatusCreated {
		t.Fatalf("create profile: %d", code)
	}
	_, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "hd", "role": "helpdesk"})
	tok, _ := jsonMap(t, ud)["token"].(string)

	// The delegated user-admin cannot weaken config (would remap admin / disable MFA).
	if code, _ := do(t, srv, http.MethodPut, "/api/config", tok, map[string]any{"key": "PAM_MFA_REQUIRED", "value": "false"}); code != http.StatusForbidden {
		t.Fatalf("helpdesk PUT config: want 403, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodDelete, "/api/config/PAM_MFA_REQUIRED", tok, nil); code != http.StatusForbidden {
		t.Fatalf("helpdesk DELETE config: want 403, got %d", code)
	}
	// The bootstrap admin still can.
	if code, _ := do(t, srv, http.MethodPut, "/api/config", testAPIKey, map[string]any{"key": "PAM_MFA_REQUIRED", "value": "true"}); code != http.StatusOK {
		t.Fatalf("admin PUT config: want 200, got %d", code)
	}
}

// TestRevealAndCheckoutObeyApproval proves reveal and checkout now honor the
// four-eyes approval gate, exactly like the connect paths.
func TestRevealAndCheckoutObeyApproval(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{RequireApproval: true})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{"name": "lnx", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh"})
	tid := int64(jsonMap(t, td)["id"].(float64))
	_, cd := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{"target_id": tid, "username": "root", "secret": "pw"})
	cid := int64(jsonMap(t, cd)["id"].(float64))

	// With global approval required and no approved request, both are 403.
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", cid), testAPIKey, nil); code != http.StatusForbidden {
		t.Fatalf("reveal under approval policy: want 403, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", cid), testAPIKey, nil); code != http.StatusForbidden {
		t.Fatalf("checkout under approval policy: want 403, got %d", code)
	}
}

// TestCheckinHolderOnly proves only the lease holder (or an admin) may check a
// credential back in.
func TestCheckinHolderOnly(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{"name": "lnx", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh"})
	tid := int64(jsonMap(t, td)["id"].(float64))
	_, cd := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{"target_id": tid, "username": "root", "secret": "pw"})
	cid := int64(jsonMap(t, cd)["id"].(float64))

	// Admin checks it out (holder = bootstrap-admin).
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkout", cid), testAPIKey, nil); code != http.StatusCreated {
		t.Fatalf("admin checkout: %d", code)
	}
	// A different reveal-capable user cannot check in someone else's lease.
	do(t, srv, http.MethodPost, "/api/profiles", testAPIKey, map[string]any{"name": "revealer", "capabilities": []string{"reveal_secret"}})
	_, ud := do(t, srv, http.MethodPost, "/api/users", testAPIKey, map[string]any{"username": "bob", "role": "revealer"})
	bob, _ := jsonMap(t, ud)["token"].(string)
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkin", cid), bob, nil); code != http.StatusForbidden {
		t.Fatalf("non-holder checkin: want 403, got %d", code)
	}
	// The admin (override) can.
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/checkin", cid), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("admin checkin: want 200, got %d", code)
	}
}
