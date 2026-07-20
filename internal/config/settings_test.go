package config

import (
	"testing"
	"time"
)

// TestApplyOverrides proves DB overrides apply to identity/policy fields, that
// bootstrap/transport and unknown keys are ignored, and that a malformed value
// for a known key is a hard error.
func TestApplyOverrides(t *testing.T) {
	cfg := &Config{}
	err := ApplyOverrides(cfg, map[string]string{
		"PAM_LDAP_URL":         "ldaps://dir",
		"PAM_MFA_REQUIRED":     "true",
		"PAM_CHECKOUT_TTL_MIN": "45",
		"PAM_DATABASE_URL":     "postgres://evil", // not overridable → ignored
		"PAM_UNKNOWN":          "x",               // unknown → ignored
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LDAPURL != "ldaps://dir" {
		t.Errorf("LDAPURL = %q", cfg.LDAPURL)
	}
	if !cfg.MFARequired {
		t.Error("MFARequired not applied")
	}
	if cfg.CheckoutTTL != 45*time.Minute {
		t.Errorf("CheckoutTTL = %v", cfg.CheckoutTTL)
	}
	if cfg.DatabaseURL != "" {
		t.Error("bootstrap key PAM_DATABASE_URL must never be overridable")
	}

	if err := ApplyOverrides(&Config{}, map[string]string{"PAM_MFA_REQUIRED": "notabool"}); err == nil {
		t.Error("a malformed boolean for a known key must error")
	}

	if !IsOverridable("PAM_LDAP_URL") || IsOverridable("PAM_DATABASE_URL") {
		t.Error("IsOverridable wrong")
	}
	if !IsSecretKey("PAM_LDAP_BIND_PASSWORD") || IsSecretKey("PAM_LDAP_URL") {
		t.Error("IsSecretKey wrong")
	}
	if len(OverridableKeys()) == 0 {
		t.Error("OverridableKeys empty")
	}
}
