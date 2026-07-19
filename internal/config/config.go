// Package config loads server configuration from PAM_* environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr  string
	DatabaseURL string
	MasterKey   string
	APIKey      string
	// BreakGlassKeyHash is the hex SHA-256 of the sealed emergency key
	// (optional; empty disables the break-glass path). Only the hash lives
	// in config so the plaintext key can be kept sealed offline.
	BreakGlassKeyHash string

	// SSHAddr is the session-proxy listen address; "off" disables it.
	SSHAddr string
	// SSHHostKeyPath persists the proxy host key; empty = ephemeral key.
	SSHHostKeyPath string
	// SSHKnownHosts pins upstream target host keys (an OpenSSH known_hosts file).
	// Empty = trust any upstream key (insecure; logged loudly).
	SSHKnownHosts string
	// RecordingDir is where session recordings are written.
	RecordingDir string

	// LogLevel is debug|info|warn|error (default info).
	LogLevel string
	// LogFormat is json|text (default json).
	LogFormat string

	// TLSCert/TLSKey enable native HTTPS on the listen address when both are set.
	TLSCert string
	TLSKey  string
	// AuthRatePerMin limits auth attempts per client IP per minute (0 disables).
	AuthRatePerMin int
	// RevealDisabled makes credential reveal break-glass-only.
	RevealDisabled bool

	// BreakGlassThreshold (M) enables M-of-N quorum unseal; BreakGlassShares (N)
	// is used by -split-key; BreakGlassTTL is the unsealed session lifetime.
	BreakGlassThreshold int
	BreakGlassShares    int
	BreakGlassTTL       time.Duration
	// AlertWebhook receives real-time break-glass alerts (JSON POST). AlertSyslog
	// ("udp://host:port" or "tcp://…") and the AlertEmail* fields add syslog and
	// SMTP alert channels; any combination fans out.
	AlertWebhook   string
	AlertSyslog    string
	AlertEmailSMTP string
	AlertEmailFrom string
	AlertEmailTo   string // comma-separated
	AlertEmailUser string
	AlertEmailPass string

	// MFARequired makes password login require a confirmed TOTP second factor.
	MFARequired bool

	// RotateInterval enables the background credential-lifecycle worker (reconcile
	// + max-age rotation); 0 disables it. RotateMaxAge rotates password
	// credentials older than this (0 = reconcile/report only).
	RotateInterval time.Duration
	RotateMaxAge   time.Duration
	// RotateAfterSession forces credential rotation when a proxied SSH session
	// ends, so a secret used in one session cannot be reused in the next.
	RotateAfterSession bool

	// OT hardening (Phase 8). RequireApproval gates every target's connect paths
	// behind an approved access request (4-eyes / maintenance window).
	// ApprovalWindow is how long an approval stays valid. AirGap disables all
	// outbound network calls (alert webhooks) for isolated deployments.
	RequireApproval bool
	ApprovalWindow  time.Duration
	AirGap          bool
	// CheckoutTTL is the lifetime of a credential checkout lease.
	CheckoutTTL time.Duration

	// WinRMHTTPS uses HTTPS (5986) for WinRM; WinRMInsecure skips TLS verify (dev).
	WinRMHTTPS    bool
	WinRMInsecure bool
	// WinRMNTLM selects NTLMv2 auth (required by most AD-joined hosts).
	WinRMNTLM bool
	// GuacdAddr enables RDP brokering via an Apache Guacamole guacd daemon.
	GuacdAddr string
	// GuacdRecordingPath makes guacd record RDP sessions server-side.
	GuacdRecordingPath string
	// GuacdRDPSecurity sets the RDP security mode ("nla", "tls", "rdp", …); empty
	// lets guacd negotiate. GuacdIgnoreCert disables RDP server-cert verification
	// (dev only — default false verifies the certificate).
	GuacdRDPSecurity string
	GuacdIgnoreCert  bool

	// KEKProvider selects the vault Key Encryption Key backend:
	// "local" (default, dev/test — uses MasterKey) or "vault-transit".
	KEKProvider string
	// Transit* configure the HashiCorp Vault Transit KEK (production).
	TransitAddr  string
	TransitToken string
	TransitKey   string
	// AWS* configure the AWS KMS KEK (production).
	AWSKMSKeyID string
	AWSRegion   string
	// PKCS11* configure the on-prem HSM KEK (only in builds tagged "pkcs11").
	PKCS11Module     string
	PKCS11Pin        string
	PKCS11KeyLabel   string
	PKCS11TokenLabel string

	// LDAP* configure Active Directory / LDAP login. Empty LDAPURL disables it.
	LDAPURL                string
	LDAPBindDN             string
	LDAPBindPassword       string
	LDAPBaseDN             string
	LDAPUserFilter         string
	LDAPInsecureSkipVerify bool
	LDAPGroupAdmin         string
	LDAPGroupUser          string
	LDAPGroupAuditor       string
	LDAPGroupApprover      string

	// Entra* configure Microsoft Entra ID (Azure AD) login. Empty tenant disables it.
	EntraTenantID      string
	EntraClientID      string
	EntraClientSecret  string
	EntraScope         string
	EntraAuthorityHost string
	EntraRoleAdmin     string
	EntraRoleUser      string
	EntraRoleAuditor   string
	EntraRoleApprover  string

	// OIDC* configure the browser Authorization Code login flow. Empty issuer disables it.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	OIDCScopes       string // space-separated; default "openid profile"
	OIDCAuthURL      string // optional; discovered from issuer if empty
	OIDCTokenURL     string
	OIDCJWKSURL      string
	OIDCRoleAdmin    string
	OIDCRoleUser     string
	OIDCRoleAuditor  string
	OIDCRoleApprover string
	PortalURL        string
}

// Load reads configuration from the PAM_* environment variables, applying
// defaults, and returns an error if a required variable (API key, database URL,
// or the master key when the local KEK provider is used) is missing.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:          getenv("PAM_LISTEN_ADDR", ":8080"),
		DatabaseURL:         os.Getenv("PAM_DATABASE_URL"),
		MasterKey:           os.Getenv("PAM_MASTER_KEY"),
		APIKey:              os.Getenv("PAM_API_KEY"),
		BreakGlassKeyHash:   os.Getenv("PAM_BREAK_GLASS_KEY_HASH"),
		SSHAddr:             getenv("PAM_SSH_ADDR", ":2222"),
		SSHHostKeyPath:      os.Getenv("PAM_SSH_HOST_KEY"),
		SSHKnownHosts:       os.Getenv("PAM_SSH_KNOWN_HOSTS"),
		RecordingDir:        getenv("PAM_RECORDING_DIR", "recordings"),
		LogLevel:            getenv("PAM_LOG_LEVEL", "info"),
		LogFormat:           getenv("PAM_LOG_FORMAT", "json"),
		TLSCert:             os.Getenv("PAM_TLS_CERT"),
		TLSKey:              os.Getenv("PAM_TLS_KEY"),
		AuthRatePerMin:      getenvInt("PAM_AUTH_RATE_LIMIT", 20),
		RevealDisabled:      os.Getenv("PAM_REVEAL_DISABLED") == "true",
		BreakGlassThreshold: getenvInt("PAM_BREAK_GLASS_THRESHOLD", 0),
		BreakGlassShares:    getenvInt("PAM_BREAK_GLASS_SHARES", 5),
		BreakGlassTTL:       time.Duration(getenvInt("PAM_BREAK_GLASS_TTL_MIN", 15)) * time.Minute,
		AlertWebhook:        os.Getenv("PAM_ALERT_WEBHOOK"),
		AlertSyslog:         os.Getenv("PAM_ALERT_SYSLOG"),
		AlertEmailSMTP:      os.Getenv("PAM_ALERT_EMAIL_SMTP"),
		AlertEmailFrom:      os.Getenv("PAM_ALERT_EMAIL_FROM"),
		AlertEmailTo:        os.Getenv("PAM_ALERT_EMAIL_TO"),
		AlertEmailUser:      os.Getenv("PAM_ALERT_EMAIL_USER"),
		AlertEmailPass:      os.Getenv("PAM_ALERT_EMAIL_PASS"),
		MFARequired:         os.Getenv("PAM_MFA_REQUIRED") == "true",
		RotateInterval:      time.Duration(getenvInt("PAM_ROTATE_INTERVAL_MIN", 0)) * time.Minute,
		RotateMaxAge:        time.Duration(getenvInt("PAM_ROTATE_MAX_AGE_HOURS", 0)) * time.Hour,
		RotateAfterSession:  os.Getenv("PAM_ROTATE_AFTER_SESSION") == "true",
		RequireApproval:     os.Getenv("PAM_REQUIRE_APPROVAL") == "true",
		ApprovalWindow:      time.Duration(getenvInt("PAM_APPROVAL_WINDOW_MIN", 60)) * time.Minute,
		AirGap:              os.Getenv("PAM_OT_AIRGAP") == "true",
		CheckoutTTL:         time.Duration(getenvInt("PAM_CHECKOUT_TTL_MIN", 30)) * time.Minute,
		WinRMHTTPS:          os.Getenv("PAM_WINRM_HTTPS") != "false", // default HTTPS
		WinRMInsecure:       os.Getenv("PAM_WINRM_INSECURE_SKIP_VERIFY") == "true",
		WinRMNTLM:           os.Getenv("PAM_WINRM_AUTH") == "ntlm",
		GuacdAddr:           os.Getenv("PAM_GUACD_ADDR"),
		GuacdRecordingPath:  os.Getenv("PAM_GUACD_RECORDING_PATH"),
		GuacdRDPSecurity:    os.Getenv("PAM_GUACD_RDP_SECURITY"),
		GuacdIgnoreCert:     os.Getenv("PAM_GUACD_IGNORE_CERT") == "true",
		KEKProvider:         getenv("PAM_KEK_PROVIDER", "local"),
		TransitAddr:         os.Getenv("PAM_KEK_TRANSIT_ADDR"),
		TransitToken:        os.Getenv("PAM_KEK_TRANSIT_TOKEN"),
		TransitKey:          os.Getenv("PAM_KEK_TRANSIT_KEY"),
		AWSKMSKeyID:         os.Getenv("PAM_KEK_AWS_KEY_ID"),
		AWSRegion:           os.Getenv("PAM_KEK_AWS_REGION"),
		PKCS11Module:        os.Getenv("PAM_KEK_PKCS11_MODULE"),
		PKCS11Pin:           os.Getenv("PAM_KEK_PKCS11_PIN"),
		PKCS11KeyLabel:      os.Getenv("PAM_KEK_PKCS11_KEY_LABEL"),
		PKCS11TokenLabel:    os.Getenv("PAM_KEK_PKCS11_TOKEN_LABEL"),

		LDAPURL:                os.Getenv("PAM_LDAP_URL"),
		LDAPBindDN:             os.Getenv("PAM_LDAP_BIND_DN"),
		LDAPBindPassword:       os.Getenv("PAM_LDAP_BIND_PASSWORD"),
		LDAPBaseDN:             os.Getenv("PAM_LDAP_BASE_DN"),
		LDAPUserFilter:         os.Getenv("PAM_LDAP_USER_FILTER"),
		LDAPInsecureSkipVerify: os.Getenv("PAM_LDAP_INSECURE_SKIP_VERIFY") == "true",
		LDAPGroupAdmin:         os.Getenv("PAM_LDAP_GROUP_ADMIN"),
		LDAPGroupUser:          os.Getenv("PAM_LDAP_GROUP_USER"),
		LDAPGroupAuditor:       os.Getenv("PAM_LDAP_GROUP_AUDITOR"),
		LDAPGroupApprover:      os.Getenv("PAM_LDAP_GROUP_APPROVER"),

		EntraTenantID:      os.Getenv("PAM_ENTRA_TENANT_ID"),
		EntraClientID:      os.Getenv("PAM_ENTRA_CLIENT_ID"),
		EntraClientSecret:  os.Getenv("PAM_ENTRA_CLIENT_SECRET"),
		EntraScope:         os.Getenv("PAM_ENTRA_SCOPE"),
		EntraAuthorityHost: os.Getenv("PAM_ENTRA_AUTHORITY_HOST"),
		EntraRoleAdmin:     os.Getenv("PAM_ENTRA_ROLE_ADMIN"),
		EntraRoleUser:      os.Getenv("PAM_ENTRA_ROLE_USER"),
		EntraRoleAuditor:   os.Getenv("PAM_ENTRA_ROLE_AUDITOR"),
		EntraRoleApprover:  os.Getenv("PAM_ENTRA_ROLE_APPROVER"),

		OIDCIssuer:       os.Getenv("PAM_OIDC_ISSUER"),
		OIDCClientID:     os.Getenv("PAM_OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("PAM_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  os.Getenv("PAM_OIDC_REDIRECT_URL"),
		OIDCScopes:       os.Getenv("PAM_OIDC_SCOPES"),
		OIDCAuthURL:      os.Getenv("PAM_OIDC_AUTH_URL"),
		OIDCTokenURL:     os.Getenv("PAM_OIDC_TOKEN_URL"),
		OIDCJWKSURL:      os.Getenv("PAM_OIDC_JWKS_URL"),
		OIDCRoleAdmin:    os.Getenv("PAM_OIDC_ROLE_ADMIN"),
		OIDCRoleUser:     os.Getenv("PAM_OIDC_ROLE_USER"),
		OIDCRoleAuditor:  os.Getenv("PAM_OIDC_ROLE_AUDITOR"),
		OIDCRoleApprover: os.Getenv("PAM_OIDC_ROLE_APPROVER"),
		PortalURL:        os.Getenv("PAM_PORTAL_URL"),
	}
	// MasterKey is required only for the local KEK provider; a KMS-backed
	// provider (e.g. vault-transit) holds the key material instead. The KEK
	// factory validates provider-specific settings at startup.
	if cfg.KEKProvider == "local" && cfg.MasterKey == "" {
		return nil, fmt.Errorf("PAM_MASTER_KEY is required for the local KEK (generate one with: pam-server -genkey), or set PAM_KEK_PROVIDER")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("PAM_API_KEY is required")
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf(`PAM_DATABASE_URL is required (postgres://... or "memory" for an ephemeral demo)`)
	}
	return cfg, nil
}

// getenv returns the environment variable key, or def when it is unset or empty.
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// getenvInt returns the environment variable key parsed as an int, or def when
// it is unset, empty, or not a valid integer.
func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
