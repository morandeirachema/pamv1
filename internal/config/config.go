// Package config loads server configuration from PAM_* environment variables.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
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
	// DBAddr is the PostgreSQL session-proxy listen address; "off" disables it
	// (Phase 15). Operators reach postgres targets with psql through this port.
	DBAddr string
	// SSHHostKeyPath persists the proxy host key; empty = ephemeral key.
	SSHHostKeyPath string
	// SSHCAKeyPath persists the Zero Standing Privilege SSH certificate-authority
	// key (Phase 22). When set, "ssh_ca" credentials are served by minting a
	// short-lived user certificate just-in-time instead of injecting a stored
	// secret. Empty = ZSP disabled. SSHCertTTL is the minted certificate's
	// validity (a small window, since it is minted fresh per session).
	SSHCAKeyPath string
	SSHCertTTL   time.Duration
	// SSHKnownHosts pins upstream target host keys (an OpenSSH known_hosts file).
	// Empty = trust any upstream key (insecure; logged loudly).
	SSHKnownHosts string
	// SSHJump* route SSH targets through an SSH bastion (for legacy equipment only
	// reachable via a jump host). Empty SSHJumpHost disables it.
	SSHJumpHost string
	SSHJumpUser string
	SSHJumpKey  string // path to the bastion private key (PEM)
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
	// TrustedProxyHops is the number of trusted reverse-proxy hops in front of the
	// API. 0 (default) keys the rate limiter on RemoteAddr; >0 takes the client IP
	// from the last N X-Forwarded-For entries (the hops YOU control), so per-IP
	// throttling still works behind a TLS-terminating proxy without trusting a
	// spoofable header end-to-end.
	TrustedProxyHops int
	// ProxyAuthRatePerMin limits failed authentication attempts per client IP per
	// minute on the SSH (:2222) and PostgreSQL (:5433) proxies, throttling online
	// guessing of the operator-chosen PAM_API_KEY (0 disables).
	ProxyAuthRatePerMin int
	// RequireHTTPS refuses to start the API/portal over plaintext HTTP when native
	// TLS (TLSCert/TLSKey) is not configured — fail-closed transport. Leave false
	// only when TLS is terminated by a trusted reverse proxy or for local demos.
	RequireHTTPS bool
	// RequireDBClientTLS refuses to start the PostgreSQL session proxy without TLS
	// on the operator-facing leg (TLSCert/TLSKey), so the operator's PAM key is
	// never sent to the DB proxy in cleartext.
	RequireDBClientTLS bool
	// DBUpstreamCA is a PEM CA bundle used to VERIFY the upstream PostgreSQL
	// server's TLS certificate on the database proxy's target leg. DBUpstreamTLSVerify
	// verifies against the system roots instead. Either enables fail-closed upstream
	// TLS so the JIT-injected DB credential can't be harvested by a MITM; unset
	// keeps the legacy trust-any-with-warning behavior.
	DBUpstreamCA        string
	DBUpstreamTLSVerify bool
	// AuditHMACKey, when set (base64 of 32 bytes), turns on tamper-evident
	// chaining of the PRIMARY audit trail: each event is HMAC-linked to the
	// previous one, so editing/reordering/deleting any event is detectable via
	// GET /api/audit/verify. Unset leaves the plain (unchained) audit table.
	AuditHMACKey string
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

	// RequireRecording refuses a proxied session when its recording cannot be
	// created, rather than proceeding unrecorded (fail-closed session auditing).
	RequireRecording bool

	// OT hardening (Phase 8). RequireApproval gates every target's connect paths
	// behind an approved access request (4-eyes / maintenance window).
	// ApprovalWindow is how long an approval stays valid. AirGap disables all
	// outbound network calls (alert webhooks) for isolated deployments.
	RequireApproval bool
	ApprovalWindow  time.Duration
	AirGap          bool
	// ITSM / ticketing gate (Phase 20). RequireTicket makes an access request
	// carry a change/incident ticket; TicketPattern is a regex it must match and
	// TicketValidateURL is a webhook the ITSM system answers 2xx for a valid ticket.
	RequireTicket     bool
	TicketPattern     string
	TicketValidateURL string
	// Approval workflow (Phase 21). ApprovalsRequired is the default number of
	// distinct approvers an access request needs (multi-tier chains); a request
	// may ask for more. RequireReason rejects an access request with no reason.
	ApprovalsRequired int
	RequireReason     bool
	// CheckoutTTL is the lifetime of a credential checkout lease.
	CheckoutTTL time.Duration
	// AllowedProtocols restricts which target protocols may be created and
	// connected to (comma-separated, e.g. "ssh,winrm"); empty = all allowed. Used
	// in OT zones to forbid protocols like RDP.
	AllowedProtocols string
	// CommandDenyFile is a file of regular expressions (one per line, '#'
	// comments) that block matching commands on the exec/WinRM/SQL paths
	// (Phase 16 command control). Empty disables command control.
	CommandDenyFile string

	// Privileged threat analytics (Phase 23). AnalyticsInterval enables the
	// background risk-scoring worker (0 disables it; the read-only risk endpoint
	// stays available). AnalyticsWindow is how far back each scoring pass looks.
	// AnalyticsAutoKill terminates a critical-risk actor's live sessions.
	// AnalyticsBusinessStart/End bound business hours for the off-hours signal,
	// interpreted in AnalyticsTimezone (an IANA name; empty = UTC, matching the
	// UTC audit timestamps).
	AnalyticsInterval      time.Duration
	AnalyticsWindow        time.Duration
	AnalyticsAutoKill      bool
	AnalyticsBusinessStart int
	AnalyticsBusinessEnd   int
	AnalyticsTimezone      string

	// AppSecretsEnabled turns on the application-secrets API (Phase 24, Tier-4):
	// a Conjur-style path where a non-agent application retrieves the specific
	// secrets it has been granted with a bearer key. Opt-in (default off) because
	// it delivers plaintext secrets to machines — front it with TLS.
	AppSecretsEnabled bool

	// Broker (Phase 13, AI-agent access broker). Setting BrokerPolicyFile enables
	// the broker; the audit key + seed are then required (fail-loud).
	BrokerPolicyFile    string        // PAM_BROKER_POLICY_FILE — YAML policy rules; enables the broker
	BrokerAuditKey      string        // PAM_BROKER_AUDIT_KEY — base64 32-byte HMAC chain key
	BrokerAuditSignSeed string        // PAM_BROKER_AUDIT_SIGN_SEED — base64 32-byte ed25519 seed
	BrokerTokenTTL      time.Duration // PAM_BROKER_TOKEN_TTL_MIN — approval resume-token lifetime (default 15m)
	BrokerMaxArgBytes   int           // PAM_BROKER_MAX_ARG_BYTES — cap on a tool call's serialized args (0 = off)
	BrokerRatePerMin    int           // PAM_BROKER_RATE_PER_MIN — per-agent tool-call rate limit (0 = off)
	// SPIFFE JWT-SVID agent identity (Phase 13d). Setting the JWKS path enables it.
	BrokerTrustDomainJWKS string // PAM_BROKER_TRUST_DOMAIN_JWKS — file with the trust-domain JWKS
	BrokerTrustDomain     string // PAM_BROKER_TRUST_DOMAIN — SPIFFE trust domain host (e.g. example.org)
	BrokerAudience        string // PAM_BROKER_AUDIENCE — required SVID audience
	BrokerMaxDelegation   int    // PAM_BROKER_MAX_DELEGATION_DEPTH — RFC 8693 act-chain cap (default 1)

	// WinRMHTTPS uses HTTPS (5986) for WinRM; WinRMInsecure skips TLS verify (dev).
	WinRMHTTPS    bool
	WinRMInsecure bool
	// WinRMNTLM selects NTLMv2 auth (required by most AD-joined hosts).
	WinRMNTLM bool
	// ProxyWinRM enables an interactive WinRM command loop through the SSH proxy
	// (ssh <cred>@<winrm-target>@pam). Opt-in — off by default.
	ProxyWinRM bool
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
	var errs []string
	// boolean parses a strict bool (true/false/1/0/t/f/…) and records an error for
	// any other value rather than silently falling back — a garbage value on a
	// security toggle (MFA, recording, air-gap) must fail loud, not fail open.
	boolean := func(key string, def bool) bool {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: invalid boolean %q (use true or false)", key, v))
			return def
		}
		return b
	}
	// integer parses an int and records an error for a non-integer value instead
	// of silently disabling the feature it configures.
	integer := func(key string, def int) int {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: invalid integer %q", key, v))
			return def
		}
		return n
	}
	cfg := &Config{
		ListenAddr:          getenv("PAM_LISTEN_ADDR", ":8080"),
		DatabaseURL:         os.Getenv("PAM_DATABASE_URL"),
		MasterKey:           os.Getenv("PAM_MASTER_KEY"),
		APIKey:              os.Getenv("PAM_API_KEY"),
		BreakGlassKeyHash:   os.Getenv("PAM_BREAK_GLASS_KEY_HASH"),
		SSHAddr:             getenv("PAM_SSH_ADDR", ":2222"),
		DBAddr:              getenv("PAM_DB_ADDR", "off"),
		SSHHostKeyPath:      os.Getenv("PAM_SSH_HOST_KEY"),
		SSHCAKeyPath:        os.Getenv("PAM_SSH_CA_KEY"),
		SSHCertTTL:          time.Duration(integer("PAM_SSH_CERT_TTL_MIN", 2)) * time.Minute,
		SSHKnownHosts:       os.Getenv("PAM_SSH_KNOWN_HOSTS"),
		SSHJumpHost:         os.Getenv("PAM_SSH_JUMP_HOST"),
		SSHJumpUser:         os.Getenv("PAM_SSH_JUMP_USER"),
		SSHJumpKey:          os.Getenv("PAM_SSH_JUMP_KEY"),
		RecordingDir:        getenv("PAM_RECORDING_DIR", "recordings"),
		LogLevel:            getenv("PAM_LOG_LEVEL", "info"),
		LogFormat:           getenv("PAM_LOG_FORMAT", "json"),
		TLSCert:             os.Getenv("PAM_TLS_CERT"),
		TLSKey:              os.Getenv("PAM_TLS_KEY"),
		AuthRatePerMin:      integer("PAM_AUTH_RATE_LIMIT", 20),
		TrustedProxyHops:    integer("PAM_TRUSTED_PROXY_HOPS", 0),
		ProxyAuthRatePerMin: integer("PAM_PROXY_AUTH_RATE_LIMIT", 10),
		RequireHTTPS:        boolean("PAM_REQUIRE_HTTPS", false),
		RequireDBClientTLS:  boolean("PAM_REQUIRE_DB_CLIENT_TLS", false),
		DBUpstreamCA:        os.Getenv("PAM_DB_UPSTREAM_CA"),
		DBUpstreamTLSVerify: boolean("PAM_DB_UPSTREAM_TLS_VERIFY", false),
		AuditHMACKey:        os.Getenv("PAM_AUDIT_HMAC_KEY"),
		RevealDisabled:      boolean("PAM_REVEAL_DISABLED", false),
		BreakGlassThreshold: integer("PAM_BREAK_GLASS_THRESHOLD", 0),
		BreakGlassShares:    integer("PAM_BREAK_GLASS_SHARES", 5),
		BreakGlassTTL:       time.Duration(integer("PAM_BREAK_GLASS_TTL_MIN", 15)) * time.Minute,
		AlertWebhook:        os.Getenv("PAM_ALERT_WEBHOOK"),
		AlertSyslog:         os.Getenv("PAM_ALERT_SYSLOG"),
		AlertEmailSMTP:      os.Getenv("PAM_ALERT_EMAIL_SMTP"),
		AlertEmailFrom:      os.Getenv("PAM_ALERT_EMAIL_FROM"),
		AlertEmailTo:        os.Getenv("PAM_ALERT_EMAIL_TO"),
		AlertEmailUser:      os.Getenv("PAM_ALERT_EMAIL_USER"),
		AlertEmailPass:      os.Getenv("PAM_ALERT_EMAIL_PASS"),
		MFARequired:         boolean("PAM_MFA_REQUIRED", false),
		RotateInterval:      time.Duration(integer("PAM_ROTATE_INTERVAL_MIN", 0)) * time.Minute,
		RotateMaxAge:        time.Duration(integer("PAM_ROTATE_MAX_AGE_HOURS", 0)) * time.Hour,
		RotateAfterSession:  boolean("PAM_ROTATE_AFTER_SESSION", false),
		RequireRecording:    boolean("PAM_REQUIRE_RECORDING", false),
		RequireApproval:     boolean("PAM_REQUIRE_APPROVAL", false),
		ApprovalWindow:      time.Duration(integer("PAM_APPROVAL_WINDOW_MIN", 60)) * time.Minute,
		RequireTicket:       boolean("PAM_REQUIRE_TICKET", false),
		TicketPattern:       os.Getenv("PAM_TICKET_PATTERN"),
		TicketValidateURL:   os.Getenv("PAM_TICKET_VALIDATE_URL"),
		ApprovalsRequired:   integer("PAM_APPROVALS_REQUIRED", 1),
		RequireReason:       boolean("PAM_REQUIRE_REASON", false),
		AirGap:              boolean("PAM_OT_AIRGAP", false),
		CheckoutTTL:         time.Duration(integer("PAM_CHECKOUT_TTL_MIN", 30)) * time.Minute,
		AllowedProtocols:    os.Getenv("PAM_ALLOWED_PROTOCOLS"),
		CommandDenyFile:     os.Getenv("PAM_COMMAND_DENY_FILE"),

		AnalyticsInterval:      time.Duration(integer("PAM_ANALYTICS_INTERVAL_MIN", 0)) * time.Minute,
		AnalyticsWindow:        time.Duration(integer("PAM_ANALYTICS_WINDOW_MIN", 60)) * time.Minute,
		AnalyticsAutoKill:      boolean("PAM_ANALYTICS_AUTO_KILL", false),
		AnalyticsBusinessStart: integer("PAM_ANALYTICS_BUSINESS_START", 7),
		AnalyticsBusinessEnd:   integer("PAM_ANALYTICS_BUSINESS_END", 20),
		AnalyticsTimezone:      os.Getenv("PAM_ANALYTICS_TIMEZONE"),
		AppSecretsEnabled:      boolean("PAM_APP_SECRETS_ENABLED", false),
		BrokerPolicyFile:       os.Getenv("PAM_BROKER_POLICY_FILE"),
		BrokerAuditKey:         os.Getenv("PAM_BROKER_AUDIT_KEY"),
		BrokerAuditSignSeed:    os.Getenv("PAM_BROKER_AUDIT_SIGN_SEED"),
		BrokerTokenTTL:         time.Duration(integer("PAM_BROKER_TOKEN_TTL_MIN", 15)) * time.Minute,
		BrokerMaxArgBytes:      integer("PAM_BROKER_MAX_ARG_BYTES", 16384),
		BrokerRatePerMin:       integer("PAM_BROKER_RATE_PER_MIN", 0),

		BrokerTrustDomainJWKS: os.Getenv("PAM_BROKER_TRUST_DOMAIN_JWKS"),
		BrokerTrustDomain:     os.Getenv("PAM_BROKER_TRUST_DOMAIN"),
		BrokerAudience:        os.Getenv("PAM_BROKER_AUDIENCE"),
		BrokerMaxDelegation:   integer("PAM_BROKER_MAX_DELEGATION_DEPTH", 1),
		WinRMHTTPS:            boolean("PAM_WINRM_HTTPS", true), // default HTTPS
		WinRMInsecure:         boolean("PAM_WINRM_INSECURE_SKIP_VERIFY", false),
		WinRMNTLM:             os.Getenv("PAM_WINRM_AUTH") == "ntlm",
		ProxyWinRM:            boolean("PAM_PROXY_WINRM", false),
		GuacdAddr:             os.Getenv("PAM_GUACD_ADDR"),
		GuacdRecordingPath:    os.Getenv("PAM_GUACD_RECORDING_PATH"),
		GuacdRDPSecurity:      os.Getenv("PAM_GUACD_RDP_SECURITY"),
		GuacdIgnoreCert:       boolean("PAM_GUACD_IGNORE_CERT", false),
		KEKProvider:           getenv("PAM_KEK_PROVIDER", "local"),
		TransitAddr:           os.Getenv("PAM_KEK_TRANSIT_ADDR"),
		TransitToken:          os.Getenv("PAM_KEK_TRANSIT_TOKEN"),
		TransitKey:            os.Getenv("PAM_KEK_TRANSIT_KEY"),
		AWSKMSKeyID:           os.Getenv("PAM_KEK_AWS_KEY_ID"),
		AWSRegion:             os.Getenv("PAM_KEK_AWS_REGION"),
		PKCS11Module:          os.Getenv("PAM_KEK_PKCS11_MODULE"),
		PKCS11Pin:             os.Getenv("PAM_KEK_PKCS11_PIN"),
		PKCS11KeyLabel:        os.Getenv("PAM_KEK_PKCS11_KEY_LABEL"),
		PKCS11TokenLabel:      os.Getenv("PAM_KEK_PKCS11_TOKEN_LABEL"),

		LDAPURL:                os.Getenv("PAM_LDAP_URL"),
		LDAPBindDN:             os.Getenv("PAM_LDAP_BIND_DN"),
		LDAPBindPassword:       os.Getenv("PAM_LDAP_BIND_PASSWORD"),
		LDAPBaseDN:             os.Getenv("PAM_LDAP_BASE_DN"),
		LDAPUserFilter:         os.Getenv("PAM_LDAP_USER_FILTER"),
		LDAPInsecureSkipVerify: boolean("PAM_LDAP_INSECURE_SKIP_VERIFY", false),
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
	// Normalize the disable sentinel so "off"/"OFF"/"Off" all disable the proxy.
	if strings.EqualFold(cfg.SSHAddr, "off") {
		cfg.SSHAddr = "off"
	}
	if strings.EqualFold(cfg.DBAddr, "off") {
		cfg.DBAddr = "off"
	}

	// MasterKey is required only for the local KEK provider; a KMS-backed
	// provider (e.g. vault-transit) holds the key material instead. The KEK
	// factory validates provider-specific settings at startup.
	if cfg.KEKProvider == "local" && cfg.MasterKey == "" {
		errs = append(errs, "PAM_MASTER_KEY is required for the local KEK (generate one with: pam-server -genkey), or set PAM_KEK_PROVIDER")
	}
	if cfg.APIKey == "" {
		errs = append(errs, "PAM_API_KEY is required")
	} else if len(cfg.APIKey) < 16 && cfg.DatabaseURL != "memory" && !boolean("PAM_ALLOW_WEAK_API_KEY", false) {
		// The bootstrap key is presented as the SSH/DB proxy password and grants
		// admin; the proxies now throttle guessing, but a real (non-demo) deployment
		// must not run on a short, human-chosen key. The in-memory demo store and an
		// explicit PAM_ALLOW_WEAK_API_KEY escape hatch are exempt so the quickstart
		// keeps working.
		errs = append(errs, "PAM_API_KEY must be at least 16 characters (set PAM_ALLOW_WEAK_API_KEY=true to override, e.g. for demos)")
	}
	if cfg.DatabaseURL == "" {
		errs = append(errs, `PAM_DATABASE_URL is required (postgres://... or "memory" for an ephemeral demo)`)
	}
	// TLS must be all-or-nothing: one of cert/key set without the other would
	// silently downgrade the control plane to plaintext HTTP.
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		errs = append(errs, "PAM_TLS_CERT and PAM_TLS_KEY must both be set (HTTPS) or both empty (HTTP)")
	}
	// Break-glass quorum needs a threshold of at least 2; 1 or a negative value
	// would pass startup yet leave the M-of-N unseal path permanently disabled.
	if cfg.BreakGlassThreshold != 0 && (cfg.BreakGlassThreshold < 2 || cfg.BreakGlassThreshold > 255) {
		errs = append(errs, "PAM_BREAK_GLASS_THRESHOLD must be 0 (disabled) or between 2 and 255")
	}
	if cfg.BreakGlassThreshold >= 2 && cfg.BreakGlassShares < cfg.BreakGlassThreshold {
		errs = append(errs, "PAM_BREAK_GLASS_SHARES must be >= PAM_BREAK_GLASS_THRESHOLD")
	}
	// When the agent broker is enabled its audit-chain keys are mandatory: a
	// verifiable log with no key would silently be unverifiable.
	if cfg.BrokerPolicyFile != "" && (cfg.BrokerAuditKey == "" || cfg.BrokerAuditSignSeed == "") {
		errs = append(errs, "PAM_BROKER_AUDIT_KEY and PAM_BROKER_AUDIT_SIGN_SEED (base64 32-byte values) are required when PAM_BROKER_POLICY_FILE is set")
	}
	// SPIFFE SVID identity needs its trust domain and audience to verify a subject
	// and reject cross-audience token replay; a JWKS file with neither would accept
	// any well-formed token in any trust domain.
	if cfg.BrokerTrustDomainJWKS != "" && (cfg.BrokerTrustDomain == "" || cfg.BrokerAudience == "") {
		errs = append(errs, "PAM_BROKER_TRUST_DOMAIN and PAM_BROKER_AUDIENCE are required when PAM_BROKER_TRUST_DOMAIN_JWKS is set")
	}
	// Business-hours bounds must be a valid, non-empty window (the off-hours risk
	// signal is otherwise meaningless or inverted).
	if cfg.AnalyticsBusinessStart < 0 || cfg.AnalyticsBusinessEnd > 24 ||
		cfg.AnalyticsBusinessStart >= cfg.AnalyticsBusinessEnd {
		errs = append(errs, "PAM_ANALYTICS_BUSINESS_START/_END must satisfy 0 <= START < END <= 24")
	}
	// A bad timezone name must fail loud, not silently fall back to UTC and score
	// the off-hours signal in the wrong zone.
	if cfg.AnalyticsTimezone != "" {
		if _, err := time.LoadLocation(cfg.AnalyticsTimezone); err != nil {
			errs = append(errs, fmt.Sprintf("PAM_ANALYTICS_TIMEZONE %q is not a valid IANA timezone", cfg.AnalyticsTimezone))
		}
	}
	// A Zero Standing Privilege certificate must have a positive, short lifetime; a
	// zero/negative TTL would mint an already-expired certificate, and an overly
	// long one silently becomes a standing credential (defeating the point of ZSP).
	if cfg.SSHCAKeyPath != "" && cfg.SSHCertTTL <= 0 {
		errs = append(errs, "PAM_SSH_CERT_TTL_MIN must be >= 1 when PAM_SSH_CA_KEY is set")
	}
	if cfg.SSHCAKeyPath != "" && cfg.SSHCertTTL > 24*time.Hour {
		errs = append(errs, "PAM_SSH_CERT_TTL_MIN must be <= 1440 (24h) to keep ZSP certificates short-lived")
	}
	// Rate limits are "0 = off"; a negative value must fail loud rather than
	// silently disable throttling (a fat-fingered minus turning off brute-force
	// protection).
	if cfg.AuthRatePerMin < 0 {
		errs = append(errs, "PAM_AUTH_RATE_LIMIT must be >= 0 (0 disables)")
	}
	if cfg.BrokerRatePerMin < 0 || cfg.BrokerMaxArgBytes < 0 {
		errs = append(errs, "PAM_BROKER_RATE_PER_MIN and PAM_BROKER_MAX_ARG_BYTES must be >= 0")
	}
	// Email alerting is all-or-nothing: a partial config silently drops the
	// detective break-glass alert channel while the operator believes it is armed.
	emailSet := 0
	for _, v := range []string{cfg.AlertEmailSMTP, cfg.AlertEmailFrom, cfg.AlertEmailTo} {
		if v != "" {
			emailSet++
		}
	}
	if emailSet != 0 && emailSet != 3 {
		errs = append(errs, "PAM_ALERT_EMAIL_SMTP, PAM_ALERT_EMAIL_FROM and PAM_ALERT_EMAIL_TO must all be set together (or all empty)")
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("config: %s", strings.Join(errs, "; "))
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
