package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// TestConfigOverrides covers the /api/config admin surface: set/list/delete
// overrides, reject non-overridable keys, and vault-encrypt secret values at
// rest (never returning or storing them in plaintext).
func TestConfigOverrides(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{})

	if code, _ := do(t, srv, http.MethodPut, "/api/config", testAPIKey, map[string]any{"key": "PAM_MFA_REQUIRED", "value": "true"}); code != http.StatusOK {
		t.Fatalf("put config: %d", code)
	}
	if code, _ := do(t, srv, http.MethodPut, "/api/config", testAPIKey, map[string]any{"key": "PAM_LDAP_BIND_PASSWORD", "value": "s3cr3t-bind"}); code != http.StatusOK {
		t.Fatalf("put secret config: %d", code)
	}
	// A non-overridable (bootstrap/transport) key is rejected.
	if code, _ := do(t, srv, http.MethodPut, "/api/config", testAPIKey, map[string]any{"key": "PAM_DATABASE_URL", "value": "postgres://evil"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("non-overridable key: want 422, got %d", code)
	}

	// Listing masks secrets and shows overrides; no secret plaintext leaks.
	_, data := do(t, srv, http.MethodGet, "/api/config", testAPIKey, nil)
	if !strings.Contains(string(data), `"PAM_MFA_REQUIRED"`) || !strings.Contains(string(data), "********") {
		t.Fatalf("config list missing expected content: %s", data)
	}
	if strings.Contains(string(data), "s3cr3t-bind") {
		t.Fatal("secret value leaked in the config listing")
	}

	// The secret is vault-encrypted at rest, not stored in plaintext.
	sett, err := st.GetSetting(context.Background(), "PAM_LDAP_BIND_PASSWORD")
	if err != nil || sett.Value == "s3cr3t-bind" || !strings.HasPrefix(sett.Value, "v2:") {
		t.Fatalf("secret setting not vault-encrypted: %+v err %v", sett, err)
	}

	// Delete reverts an override.
	if code, _ := do(t, srv, http.MethodDelete, "/api/config/PAM_MFA_REQUIRED", testAPIKey, nil); code != http.StatusNoContent {
		t.Fatalf("delete config: %d", code)
	}
	if _, err := st.GetSetting(context.Background(), "PAM_MFA_REQUIRED"); err == nil {
		t.Fatal("override should be gone after delete")
	}
}
