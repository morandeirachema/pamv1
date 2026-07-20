package api_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestConfigHotSwap proves PUT/DELETE /api/config take effect without a restart
// (Phase 12): a reconfigure closure rebuilds the runtime snapshot from stored
// settings, the change is live on the next request, and a rejected reconfigure
// rolls the offending override back.
func TestConfigHotSwap(t *testing.T) {
	var backing store.Store
	// A production-shaped reconfigure closure: rebuild the hot-swappable config
	// from the current stored settings. It reflects PAM_ALLOWED_PROTOCOLS and
	// fails loudly on a sentinel bad value (standing in for e.g. an unreachable
	// LDAP URL) so the rollback path is exercised.
	reconfigure := func(ctx context.Context) (*api.RuntimeConfig, error) {
		rc := &api.RuntimeConfig{}
		if s, err := backing.GetSetting(ctx, "PAM_ALLOWED_PROTOCOLS"); err == nil {
			rc.AllowedProtocols = strings.Split(s.Value, ",")
		}
		if s, err := backing.GetSetting(ctx, "PAM_LDAP_URL"); err == nil && s.Value == "reject" {
			return nil, errors.New("cannot reach directory")
		}
		return rc, nil
	}
	srv, st := newTestServerOpts(t, nil, api.Options{Reconfigure: reconfigure})
	backing = st

	createWinRM := func(name string) int {
		code, _ := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
			"name": name, "host": "10.0.0.9", "port": 5986, "os_type": "windows", "protocol": "winrm",
		})
		return code
	}

	// Before any override, all protocols are allowed: a winrm target creates.
	if code := createWinRM("win-a"); code != http.StatusCreated {
		t.Fatalf("create winrm before policy: want 201, got %d", code)
	}

	// Restrict to ssh only via config — no restart.
	if code, d := do(t, srv, http.MethodPut, "/api/config", testAPIKey, map[string]any{"key": "PAM_ALLOWED_PROTOCOLS", "value": "ssh"}); code != http.StatusOK {
		t.Fatalf("put allowed protocols: %d %s", code, d)
	}
	// The new policy is live: a winrm target is now rejected...
	if code := createWinRM("win-b"); code != http.StatusUnprocessableEntity {
		t.Fatalf("create winrm after ssh-only policy: want 422, got %d", code)
	}
	// ...while an ssh target still creates.
	if code, _ := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "lnx-a", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	}); code != http.StatusCreated {
		t.Fatalf("create ssh after policy: want 201, got %d", code)
	}

	// Clearing the override reverts live to all-allowed.
	if code, _ := do(t, srv, http.MethodDelete, "/api/config/PAM_ALLOWED_PROTOCOLS", testAPIKey, nil); code != http.StatusNoContent {
		t.Fatalf("delete allowed protocols: %d", code)
	}
	if code := createWinRM("win-c"); code != http.StatusCreated {
		t.Fatalf("create winrm after revert: want 201, got %d", code)
	}

	// A reconfigure that fails rolls the override back rather than persisting a
	// value that would also break the next restart.
	if code, d := do(t, srv, http.MethodPut, "/api/config", testAPIKey, map[string]any{"key": "PAM_LDAP_URL", "value": "reject"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("rejected reconfigure: want 422, got %d %s", code, d)
	}
	if _, err := st.GetSetting(context.Background(), "PAM_LDAP_URL"); err == nil {
		t.Fatal("rejected override should have been rolled back")
	}
}
