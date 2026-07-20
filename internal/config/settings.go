package config

import (
	"fmt"
	"sort"
	"strconv"
	"time"
)

// setting maps a persisted configuration key to the Config field it overrides.
// Only identity backends, SSO, and operational policy are overridable — bootstrap
// and transport settings (database URL, master key, listen/TLS addresses, KEK
// provider) stay environment/IaC-only, so a stored setting can never repoint the
// database, unseal the vault, or change how the server binds.
type setting struct {
	Key    string
	Secret bool // value is stored vault-encrypted at rest
	apply  func(cfg *Config, val string) error
}

func applyStr(set func(*Config, string)) func(*Config, string) error {
	return func(c *Config, v string) error { set(c, v); return nil }
}
func applyBool(set func(*Config, bool)) func(*Config, string) error {
	return func(c *Config, v string) error {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("invalid boolean %q", v)
		}
		set(c, b)
		return nil
	}
}
func applyMinutes(set func(*Config, time.Duration)) func(*Config, string) error {
	return func(c *Config, v string) error {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid integer %q", v)
		}
		set(c, time.Duration(n)*time.Minute)
		return nil
	}
}

var settingSpecs = []setting{
	{Key: "PAM_LDAP_URL", apply: applyStr(func(c *Config, v string) { c.LDAPURL = v })},
	{Key: "PAM_LDAP_BIND_DN", apply: applyStr(func(c *Config, v string) { c.LDAPBindDN = v })},
	{Key: "PAM_LDAP_BIND_PASSWORD", Secret: true, apply: applyStr(func(c *Config, v string) { c.LDAPBindPassword = v })},
	{Key: "PAM_LDAP_BASE_DN", apply: applyStr(func(c *Config, v string) { c.LDAPBaseDN = v })},
	{Key: "PAM_LDAP_USER_FILTER", apply: applyStr(func(c *Config, v string) { c.LDAPUserFilter = v })},
	{Key: "PAM_LDAP_INSECURE_SKIP_VERIFY", apply: applyBool(func(c *Config, b bool) { c.LDAPInsecureSkipVerify = b })},
	{Key: "PAM_LDAP_GROUP_ADMIN", apply: applyStr(func(c *Config, v string) { c.LDAPGroupAdmin = v })},
	{Key: "PAM_LDAP_GROUP_USER", apply: applyStr(func(c *Config, v string) { c.LDAPGroupUser = v })},
	{Key: "PAM_LDAP_GROUP_AUDITOR", apply: applyStr(func(c *Config, v string) { c.LDAPGroupAuditor = v })},
	{Key: "PAM_LDAP_GROUP_APPROVER", apply: applyStr(func(c *Config, v string) { c.LDAPGroupApprover = v })},
	{Key: "PAM_ENTRA_TENANT_ID", apply: applyStr(func(c *Config, v string) { c.EntraTenantID = v })},
	{Key: "PAM_ENTRA_CLIENT_ID", apply: applyStr(func(c *Config, v string) { c.EntraClientID = v })},
	{Key: "PAM_ENTRA_CLIENT_SECRET", Secret: true, apply: applyStr(func(c *Config, v string) { c.EntraClientSecret = v })},
	{Key: "PAM_ENTRA_SCOPE", apply: applyStr(func(c *Config, v string) { c.EntraScope = v })},
	{Key: "PAM_ENTRA_AUTHORITY_HOST", apply: applyStr(func(c *Config, v string) { c.EntraAuthorityHost = v })},
	{Key: "PAM_ENTRA_ROLE_ADMIN", apply: applyStr(func(c *Config, v string) { c.EntraRoleAdmin = v })},
	{Key: "PAM_ENTRA_ROLE_USER", apply: applyStr(func(c *Config, v string) { c.EntraRoleUser = v })},
	{Key: "PAM_ENTRA_ROLE_AUDITOR", apply: applyStr(func(c *Config, v string) { c.EntraRoleAuditor = v })},
	{Key: "PAM_ENTRA_ROLE_APPROVER", apply: applyStr(func(c *Config, v string) { c.EntraRoleApprover = v })},
	{Key: "PAM_OIDC_ISSUER", apply: applyStr(func(c *Config, v string) { c.OIDCIssuer = v })},
	{Key: "PAM_OIDC_CLIENT_ID", apply: applyStr(func(c *Config, v string) { c.OIDCClientID = v })},
	{Key: "PAM_OIDC_CLIENT_SECRET", Secret: true, apply: applyStr(func(c *Config, v string) { c.OIDCClientSecret = v })},
	{Key: "PAM_OIDC_REDIRECT_URL", apply: applyStr(func(c *Config, v string) { c.OIDCRedirectURL = v })},
	{Key: "PAM_OIDC_SCOPES", apply: applyStr(func(c *Config, v string) { c.OIDCScopes = v })},
	{Key: "PAM_OIDC_AUTH_URL", apply: applyStr(func(c *Config, v string) { c.OIDCAuthURL = v })},
	{Key: "PAM_OIDC_TOKEN_URL", apply: applyStr(func(c *Config, v string) { c.OIDCTokenURL = v })},
	{Key: "PAM_OIDC_JWKS_URL", apply: applyStr(func(c *Config, v string) { c.OIDCJWKSURL = v })},
	{Key: "PAM_OIDC_ROLE_ADMIN", apply: applyStr(func(c *Config, v string) { c.OIDCRoleAdmin = v })},
	{Key: "PAM_OIDC_ROLE_USER", apply: applyStr(func(c *Config, v string) { c.OIDCRoleUser = v })},
	{Key: "PAM_OIDC_ROLE_AUDITOR", apply: applyStr(func(c *Config, v string) { c.OIDCRoleAuditor = v })},
	{Key: "PAM_OIDC_ROLE_APPROVER", apply: applyStr(func(c *Config, v string) { c.OIDCRoleApprover = v })},
	{Key: "PAM_REQUIRE_APPROVAL", apply: applyBool(func(c *Config, b bool) { c.RequireApproval = b })},
	{Key: "PAM_APPROVAL_WINDOW_MIN", apply: applyMinutes(func(c *Config, d time.Duration) { c.ApprovalWindow = d })},
	{Key: "PAM_MFA_REQUIRED", apply: applyBool(func(c *Config, b bool) { c.MFARequired = b })},
	{Key: "PAM_REVEAL_DISABLED", apply: applyBool(func(c *Config, b bool) { c.RevealDisabled = b })},
	{Key: "PAM_ROTATE_AFTER_SESSION", apply: applyBool(func(c *Config, b bool) { c.RotateAfterSession = b })},
	{Key: "PAM_CHECKOUT_TTL_MIN", apply: applyMinutes(func(c *Config, d time.Duration) { c.CheckoutTTL = d })},
	{Key: "PAM_ALLOWED_PROTOCOLS", apply: applyStr(func(c *Config, v string) { c.AllowedProtocols = v })},
}

var settingByKey = func() map[string]setting {
	m := make(map[string]setting, len(settingSpecs))
	for _, s := range settingSpecs {
		m[s.Key] = s
	}
	return m
}()

// ApplyOverrides overlays DB-stored configuration values (kv, already decrypted)
// onto cfg. Unknown keys are ignored — the API is the whitelist, and this is
// defense in depth — but a malformed value for a known key is a hard error so a
// bad stored setting fails loud at startup rather than silently misconfiguring.
func ApplyOverrides(cfg *Config, kv map[string]string) error {
	for k, v := range kv {
		s, ok := settingByKey[k]
		if !ok || v == "" {
			continue
		}
		if err := s.apply(cfg, v); err != nil {
			return fmt.Errorf("config override %s: %w", k, err)
		}
	}
	return nil
}

// OverridableKeys returns the sorted set of PAM_* keys that may be DB-overridden.
func OverridableKeys() []string {
	keys := make([]string, 0, len(settingSpecs))
	for _, s := range settingSpecs {
		keys = append(keys, s.Key)
	}
	sort.Strings(keys)
	return keys
}

// IsOverridable reports whether key may be stored as a configuration override.
func IsOverridable(key string) bool { _, ok := settingByKey[key]; return ok }

// IsSecretKey reports whether key's value is secret (stored vault-encrypted).
func IsSecretKey(key string) bool { s, ok := settingByKey[key]; return ok && s.Secret }
