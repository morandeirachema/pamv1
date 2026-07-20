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

// TestConfigEffectiveAndIaC covers the read-only effective-config/health view and
// the IaC export: overrides render as env/Helm/Terraform, and secret values are
// never emitted in plaintext.
func TestConfigEffectiveAndIaC(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{})

	// Seed a plain and a secret override.
	for k, v := range map[string]string{"PAM_LDAP_URL": "ldaps://dc.example.com", "PAM_LDAP_BIND_PASSWORD": "sup3r-secret"} {
		if code, _ := do(t, srv, http.MethodPut, "/api/config", testAPIKey, map[string]any{"key": k, "value": v}); code != http.StatusOK {
			t.Fatalf("seed %s: %d", k, code)
		}
	}

	// Effective view reports backend status and (no reconfigure wired) hot_swap off.
	_, eff := do(t, srv, http.MethodGet, "/api/config/effective", testAPIKey, nil)
	if m := jsonMap(t, eff); m["backends"] == nil || m["hot_swap"] != false {
		t.Fatalf("effective config unexpected: %s", eff)
	}

	// env export: plain value present, secret value never in plaintext.
	_, env := do(t, srv, http.MethodGet, "/api/config/iac?format=env", testAPIKey, nil)
	envStr := string(env)
	if !strings.Contains(envStr, "PAM_LDAP_URL=ldaps://dc.example.com") {
		t.Fatalf("env export missing plain value: %s", envStr)
	}
	if strings.Contains(envStr, "sup3r-secret") {
		t.Fatal("secret plaintext leaked in env export")
	}

	// helm export references a secretKeyRef for the secret; terraform emits locals.
	_, helm := do(t, srv, http.MethodGet, "/api/config/iac?format=helm", testAPIKey, nil)
	if !strings.Contains(string(helm), "secretKeyRef") || strings.Contains(string(helm), "sup3r-secret") {
		t.Fatalf("helm export wrong: %s", helm)
	}
	_, tf := do(t, srv, http.MethodGet, "/api/config/iac?format=terraform", testAPIKey, nil)
	if !strings.Contains(string(tf), "locals {") || strings.Contains(string(tf), "sup3r-secret") {
		t.Fatalf("terraform export wrong: %s", tf)
	}

	// Unknown format is rejected.
	if code, _ := do(t, srv, http.MethodGet, "/api/config/iac?format=bogus", testAPIKey, nil); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad format: want 422, got %d", code)
	}
}
