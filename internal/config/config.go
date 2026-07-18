// Package config loads server configuration from PAM_* environment variables.
package config

import (
	"fmt"
	"os"
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
	// RecordingDir is where session recordings are written.
	RecordingDir string

	// LogLevel is debug|info|warn|error (default info).
	LogLevel string
	// LogFormat is json|text (default json).
	LogFormat string

	// KEKProvider selects the vault Key Encryption Key backend:
	// "local" (default, dev/test — uses MasterKey) or "vault-transit".
	KEKProvider string
	// Transit* configure the HashiCorp Vault Transit KEK (production).
	TransitAddr  string
	TransitToken string
	TransitKey   string

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
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:        getenv("PAM_LISTEN_ADDR", ":8080"),
		DatabaseURL:       os.Getenv("PAM_DATABASE_URL"),
		MasterKey:         os.Getenv("PAM_MASTER_KEY"),
		APIKey:            os.Getenv("PAM_API_KEY"),
		BreakGlassKeyHash: os.Getenv("PAM_BREAK_GLASS_KEY_HASH"),
		SSHAddr:           getenv("PAM_SSH_ADDR", ":2222"),
		SSHHostKeyPath:    os.Getenv("PAM_SSH_HOST_KEY"),
		RecordingDir:      getenv("PAM_RECORDING_DIR", "recordings"),
		LogLevel:          getenv("PAM_LOG_LEVEL", "info"),
		LogFormat:         getenv("PAM_LOG_FORMAT", "json"),
		KEKProvider:       getenv("PAM_KEK_PROVIDER", "local"),
		TransitAddr:       os.Getenv("PAM_KEK_TRANSIT_ADDR"),
		TransitToken:      os.Getenv("PAM_KEK_TRANSIT_TOKEN"),
		TransitKey:        os.Getenv("PAM_KEK_TRANSIT_KEY"),

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

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
