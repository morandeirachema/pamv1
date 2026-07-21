package config

import (
	"strings"
	"testing"
)

// setRequired sets the three always-required vars (for the default local KEK) so
// a test can focus on the field under test.
func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("PAM_MASTER_KEY", "test-master-key")
	t.Setenv("PAM_API_KEY", "test-api-key")
	t.Setenv("PAM_DATABASE_URL", "memory")
}

// TestLoadValidation covers the fail-loud guards for negative rate limits and a
// partial email-alert config (which would otherwise silently disable controls).
func TestLoadValidation(t *testing.T) {
	t.Run("negative auth rate limit", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_AUTH_RATE_LIMIT", "-1")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_AUTH_RATE_LIMIT") {
			t.Fatalf("Load() = %v, want PAM_AUTH_RATE_LIMIT error", err)
		}
	})
	t.Run("partial email alert", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_ALERT_EMAIL_SMTP", "smtp:25")
		t.Setenv("PAM_ALERT_EMAIL_FROM", "pam@x")
		// PAM_ALERT_EMAIL_TO deliberately omitted.
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_ALERT_EMAIL") {
			t.Fatalf("Load() = %v, want PAM_ALERT_EMAIL error", err)
		}
	})
	t.Run("ldap insecure not overridable", func(t *testing.T) {
		if IsOverridable("PAM_LDAP_INSECURE_SKIP_VERIFY") {
			t.Fatal("PAM_LDAP_INSECURE_SKIP_VERIFY must not be a runtime-overridable setting")
		}
	})
	t.Run("zsp cert ttl too long", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_SSH_CA_KEY", "/data/ca")
		t.Setenv("PAM_SSH_CERT_TTL_MIN", "2000") // > 24h
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_SSH_CERT_TTL_MIN") {
			t.Fatalf("Load() = %v, want PAM_SSH_CERT_TTL_MIN too-long error", err)
		}
	})
	t.Run("invalid analytics timezone", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_ANALYTICS_TIMEZONE", "Nowhere/Fake")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_ANALYTICS_TIMEZONE") {
			t.Fatalf("Load() = %v, want PAM_ANALYTICS_TIMEZONE error", err)
		}
	})
}

// TestLoadRequiredVars checks each required variable is reported when missing and
// that the master key is required only for the local KEK provider.
func TestLoadRequiredVars(t *testing.T) {
	t.Run("all present", func(t *testing.T) {
		setRequired(t)
		if _, err := Load(); err != nil {
			t.Fatalf("Load() = %v, want nil", err)
		}
	})
	t.Run("missing api key", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_API_KEY", "")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_API_KEY") {
			t.Fatalf("Load() = %v, want PAM_API_KEY error", err)
		}
	})
	t.Run("missing database url", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_DATABASE_URL", "")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_DATABASE_URL") {
			t.Fatalf("Load() = %v, want PAM_DATABASE_URL error", err)
		}
	})
	t.Run("master key not required for non-local KEK", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_MASTER_KEY", "")
		t.Setenv("PAM_KEK_PROVIDER", "vault-transit")
		if _, err := Load(); err != nil {
			t.Fatalf("Load() = %v, want nil (KMS provider holds the key)", err)
		}
	})
	t.Run("master key required for local KEK", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_MASTER_KEY", "")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_MASTER_KEY") {
			t.Fatalf("Load() = %v, want PAM_MASTER_KEY error", err)
		}
	})
}

// TestLoadBooleanStrict proves security toggles accept any Go bool spelling and
// reject garbage loudly rather than silently failing open.
func TestLoadBooleanStrict(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{{"true", true}, {"TRUE", true}, {"1", true}, {"t", true}, {"false", false}, {"0", false}} {
		t.Run("MFA="+tc.val, func(t *testing.T) {
			setRequired(t)
			t.Setenv("PAM_MFA_REQUIRED", tc.val)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v", err)
			}
			if cfg.MFARequired != tc.want {
				t.Errorf("MFARequired = %v, want %v", cfg.MFARequired, tc.want)
			}
		})
	}
	t.Run("garbage errors, not silently off", func(t *testing.T) {
		setRequired(t)
		t.Setenv("PAM_MFA_REQUIRED", "yes")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_MFA_REQUIRED") {
			t.Fatalf("Load() = %v, want PAM_MFA_REQUIRED invalid-boolean error", err)
		}
	})
	t.Run("WinRM HTTPS defaults true and honors false", func(t *testing.T) {
		setRequired(t)
		cfg, _ := Load()
		if !cfg.WinRMHTTPS {
			t.Error("WinRMHTTPS default = false, want true")
		}
		t.Setenv("PAM_WINRM_HTTPS", "false")
		cfg, _ = Load()
		if cfg.WinRMHTTPS {
			t.Error("WinRMHTTPS with false = true")
		}
	})
}

// TestLoadIntegerStrict proves a non-integer errors rather than silently
// disabling the worker/limit it configures.
func TestLoadIntegerStrict(t *testing.T) {
	setRequired(t)
	t.Setenv("PAM_ROTATE_INTERVAL_MIN", "1h")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_ROTATE_INTERVAL_MIN") {
		t.Fatalf("Load() = %v, want PAM_ROTATE_INTERVAL_MIN invalid-integer error", err)
	}
}

// TestLoadTLSBothOrNeither proves a half-configured TLS pair is rejected instead
// of silently serving plaintext.
func TestLoadTLSBothOrNeither(t *testing.T) {
	setRequired(t)
	t.Setenv("PAM_TLS_CERT", "/tmp/cert.pem")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_TLS") {
		t.Fatalf("Load() = %v, want TLS pairing error", err)
	}
	t.Setenv("PAM_TLS_KEY", "/tmp/key.pem")
	if _, err := Load(); err != nil {
		t.Fatalf("Load() with both TLS vars = %v, want nil", err)
	}
}

// TestLoadBreakGlassThreshold proves an unusable quorum threshold is rejected.
func TestLoadBreakGlassThreshold(t *testing.T) {
	setRequired(t)
	t.Setenv("PAM_BREAK_GLASS_THRESHOLD", "1")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "PAM_BREAK_GLASS_THRESHOLD") {
		t.Fatalf("Load() = %v, want threshold error for 1", err)
	}
	t.Setenv("PAM_BREAK_GLASS_THRESHOLD", "3")
	t.Setenv("PAM_BREAK_GLASS_SHARES", "5")
	if _, err := Load(); err != nil {
		t.Fatalf("Load() with 3-of-5 = %v, want nil", err)
	}
}

// TestLoadOffCaseInsensitive proves the proxy disable sentinel is case-insensitive.
func TestLoadOffCaseInsensitive(t *testing.T) {
	setRequired(t)
	t.Setenv("PAM_SSH_ADDR", "OFF")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSHAddr != "off" {
		t.Errorf("SSHAddr = %q, want normalized \"off\"", cfg.SSHAddr)
	}
}
