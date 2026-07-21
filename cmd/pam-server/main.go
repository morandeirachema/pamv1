// pam-server runs the pamv1 API and portal.
//
// Utility flags:
//
//	-genkey       print a fresh vault master key (PAM_MASTER_KEY) and exit
//	-hashkey      read an emergency break-glass key from stdin and print its
//	              SHA-256 hex (PAM_BREAK_GLASS_KEY_HASH); the plaintext key is
//	              then sealed offline (envelope / safe) and never stored.
//	-healthcheck  probe the local /healthz endpoint and exit 0 if healthy
//	              (used by the container HEALTHCHECK on the shell-less image).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/config"
	"github.com/morandeirachema/pamv1/internal/conjur"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/maint"
	"github.com/morandeirachema/pamv1/internal/oidc"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/shamir"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/store/pgstore"
	"github.com/morandeirachema/pamv1/internal/vault"
	"github.com/morandeirachema/pamv1/internal/winrm"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// main parses the utility flags and dispatches: -genkey prints a fresh vault
// master key, -hashkey prints the SHA-256 of a break-glass key read from stdin,
// -rotate-kek re-encrypts secrets under a new master key, -split-key emits
// Shamir shares of a break-glass key, and the default path runs the server.
func main() {
	genkey := flag.Bool("genkey", false, "print a new vault master key and exit")
	hashkey := flag.Bool("hashkey", false, "read a break-glass key from stdin, print its SHA-256 hex and exit")
	rotateKEK := flag.Bool("rotate-kek", false, "re-encrypt all vaulted secrets from PAM_MASTER_KEY to PAM_NEW_MASTER_KEY and exit")
	splitKey := flag.Bool("split-key", false, "read a break-glass key from stdin and print N Shamir shares (PAM_BREAK_GLASS_SHARES / _THRESHOLD)")
	healthcheck := flag.Bool("healthcheck", false, "probe the local /healthz endpoint and exit 0 if healthy (for container HEALTHCHECK)")
	flag.Parse()

	switch {
	case *genkey:
		key, err := vault.GenerateMasterKey()
		if err != nil {
			fatal(err)
		}
		fmt.Println(key)
	case *hashkey:
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fatal(err)
		}
		key := strings.TrimSpace(string(data))
		if key == "" {
			fatal(fmt.Errorf("no key on stdin (would hash the empty string, yielding an unusable break-glass hash)"))
		}
		sum := sha256.Sum256([]byte(key))
		fmt.Println(hex.EncodeToString(sum[:]))
	case *rotateKEK:
		if err := runRotateKEK(); err != nil {
			fatal(err)
		}
	case *splitKey:
		if err := runSplitKey(); err != nil {
			fatal(err)
		}
	case *healthcheck:
		if err := runHealthcheck(); err != nil {
			fatal(err)
		}
	default:
		if err := run(); err != nil {
			fatal(err)
		}
	}
}

// runHealthcheck probes the local liveness endpoint and exits non-zero unless it
// returns 200. It exists so a container HEALTHCHECK works on the distroless image
// (which has no shell or curl): `pam-server -healthcheck` targets the configured
// PAM_LISTEN_ADDR on the loopback.
func runHealthcheck() error {
	addr := os.Getenv("PAM_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("PAM_LISTEN_ADDR %q: %w", addr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1" // the server binds all interfaces; probe loopback
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}

// applyStoredConfig overlays DB-persisted configuration overrides (Phase 12) onto
// cfg, decrypting secret settings with the vault. Overrides cover identity
// backends, SSO, and operational policy; bootstrap/transport settings are not
// overridable. Applied at startup, so changes take effect on the next restart.
func applyStoredConfig(ctx context.Context, st store.Store, v *vault.Vault, cfg *config.Config, log *slog.Logger) error {
	settings, err := st.ListSettings(ctx)
	if err != nil {
		return fmt.Errorf("load config overrides: %w", err)
	}
	if len(settings) == 0 {
		return nil
	}
	kv := make(map[string]string, len(settings))
	for _, s := range settings {
		val := s.Value
		if s.Secret {
			pt, derr := v.Decrypt(ctx, s.Value, store.ConfigAAD(s.Key))
			if derr != nil {
				return fmt.Errorf("decrypt config setting %s: %w", s.Key, derr)
			}
			val = pt
		}
		kv[s.Key] = val
	}
	if err := config.ApplyOverrides(cfg, kv); err != nil {
		return err
	}
	log.Info("applied stored configuration overrides", "count", len(kv))
	return nil
}

// buildBroker loads the AI-agent access-broker policy and decodes its
// audit-chain keys when PAM_BROKER_POLICY_FILE is set. It returns all-nil when
// the broker is disabled; config.Load already guarantees the keys are present
// when the policy file is set, so any decode failure here is a fatal misconfig.
func buildBroker(cfg *config.Config) (*policy.Engine, []byte, ed25519.PrivateKey, error) {
	if cfg.BrokerPolicyFile == "" {
		return nil, nil, nil, nil
	}
	engine, err := policy.LoadFile(cfg.BrokerPolicyFile)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := base64.StdEncoding.DecodeString(cfg.BrokerAuditKey)
	if err != nil || len(key) != auditchain.KeySize {
		return nil, nil, nil, fmt.Errorf("PAM_BROKER_AUDIT_KEY must be base64 of %d bytes", auditchain.KeySize)
	}
	seed, err := base64.StdEncoding.DecodeString(cfg.BrokerAuditSignSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, nil, nil, fmt.Errorf("PAM_BROKER_AUDIT_SIGN_SEED must be base64 of %d bytes", ed25519.SeedSize)
	}
	return engine, key, ed25519.NewKeyFromSeed(seed), nil
}

// runRotateKEK re-encrypts every vaulted secret from the current local master
// key (PAM_MASTER_KEY) to a new one (PAM_NEW_MASTER_KEY). Run it offline, then
// set PAM_MASTER_KEY to the new key and restart.
func runRotateKEK() error {
	oldV, err := vault.New(os.Getenv("PAM_MASTER_KEY"))
	if err != nil {
		return fmt.Errorf("current key (PAM_MASTER_KEY): %w", err)
	}
	newKey := os.Getenv("PAM_NEW_MASTER_KEY")
	if newKey == "" {
		return fmt.Errorf("PAM_NEW_MASTER_KEY is required (generate one with -genkey)")
	}
	newV, err := vault.New(newKey)
	if err != nil {
		return fmt.Errorf("new key (PAM_NEW_MASTER_KEY): %w", err)
	}
	dbURL := os.Getenv("PAM_DATABASE_URL")
	if dbURL == "" || dbURL == "memory" {
		return fmt.Errorf("PAM_DATABASE_URL must point at a PostgreSQL database")
	}
	ctx := context.Background()
	st, err := pgstore.Open(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer st.Close()

	n, err := maint.RotateVaultKEK(ctx, st, oldV, newV)
	if err != nil {
		return fmt.Errorf("rotation failed after %d secrets: %w", n, err)
	}
	fmt.Printf("rotated %d secrets; now set PAM_MASTER_KEY to the new key and restart\n", n)
	return nil
}

// fatal prints err to stderr prefixed with "pam-server:" and exits with status 1.
func fatal(err error) {
	fmt.Fprintln(os.Stderr, "pam-server:", err)
	os.Exit(1)
}

// runSplitKey reads the break-glass key from stdin and prints N Shamir shares
// (hex, one per line), of which PAM_BREAK_GLASS_THRESHOLD reconstruct the key.
// Distribute one share to each custodian; the server holds none.
func runSplitKey() error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	key := []byte(strings.TrimSpace(string(data)))
	if len(key) == 0 {
		return fmt.Errorf("no key on stdin")
	}
	n := getenvInt("PAM_BREAK_GLASS_SHARES", 5)
	m := getenvInt("PAM_BREAK_GLASS_THRESHOLD", 3)
	shares, err := shamir.Split(key, n, m)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "# %d shares; any %d reconstruct the key. Distribute one per custodian.\n", n, m)
	for _, s := range shares {
		fmt.Println(hex.EncodeToString(s))
	}
	return nil
}

// getenvInt returns the integer value of the named environment variable, or def
// when the variable is unset or does not parse as an integer.
func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// buildAuthenticator wires the enabled password identity sources (on-prem AD via
// LDAP and/or Microsoft Entra ID) into a single Authenticator (nil if none), and
// returns the LDAP directory source (for identity reconciliation) when LDAP is
// configured.
func buildAuthenticator(cfg *config.Config, log *slog.Logger) (auth.Authenticator, auth.DirectorySource, error) {
	var sources []auth.Authenticator
	var directory auth.DirectorySource

	if cfg.LDAPURL != "" {
		ldapAuth, err := auth.NewLDAPAuthenticator(auth.LDAPConfig{
			URL:                cfg.LDAPURL,
			BindDN:             cfg.LDAPBindDN,
			BindPassword:       cfg.LDAPBindPassword,
			BaseDN:             cfg.LDAPBaseDN,
			UserFilter:         cfg.LDAPUserFilter,
			InsecureSkipVerify: cfg.LDAPInsecureSkipVerify,
			GroupRoleMap:       roleMap(cfg.LDAPGroupAdmin, cfg.LDAPGroupUser, cfg.LDAPGroupAuditor, cfg.LDAPGroupApprover),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("ldap: %w", err)
		}
		sources = append(sources, ldapAuth)
		directory = ldapAuth
		log.Info("active directory login enabled", "url", cfg.LDAPURL, "insecure_skip_verify", cfg.LDAPInsecureSkipVerify)
	}

	if cfg.EntraTenantID != "" {
		entraAuth, err := auth.NewEntraAuthenticator(auth.EntraConfig{
			TenantID:      cfg.EntraTenantID,
			ClientID:      cfg.EntraClientID,
			ClientSecret:  cfg.EntraClientSecret,
			Scope:         cfg.EntraScope,
			AuthorityHost: cfg.EntraAuthorityHost,
			RoleMap:       roleMap(cfg.EntraRoleAdmin, cfg.EntraRoleUser, cfg.EntraRoleAuditor, cfg.EntraRoleApprover),
		})
		if err != nil {
			return nil, nil, fmt.Errorf("entra: %w", err)
		}
		sources = append(sources, entraAuth)
		log.Info("entra id login enabled", "tenant", cfg.EntraTenantID)
	}

	return auth.NewChain(sources...), directory, nil
}

// buildOIDC constructs the OIDC provider when PAM_OIDC_ISSUER is set, filling in
// the authorize/token/JWKS endpoints from discovery when not given explicitly.
func buildOIDC(ctx context.Context, cfg *config.Config, log *slog.Logger) (*oidc.Provider, error) {
	if cfg.OIDCIssuer == "" {
		return nil, nil
	}
	authURL, tokenURL, jwksURL := cfg.OIDCAuthURL, cfg.OIDCTokenURL, cfg.OIDCJWKSURL
	if authURL == "" || tokenURL == "" || jwksURL == "" {
		a, t, j, err := oidc.Discover(ctx, nil, cfg.OIDCIssuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery: %w", err)
		}
		authURL, tokenURL, jwksURL = a, t, j
	}
	var scopes []string
	if cfg.OIDCScopes != "" {
		scopes = strings.Fields(cfg.OIDCScopes)
	}
	p, err := oidc.NewProvider(oidc.Config{
		Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCClientSecret,
		RedirectURL: cfg.OIDCRedirectURL, AuthURL: authURL, TokenURL: tokenURL, JWKSURL: jwksURL,
		Scopes: scopes,
	})
	if err != nil {
		return nil, err
	}
	log.Info("oidc login enabled", "issuer", cfg.OIDCIssuer)
	return p, nil
}

// roleMap builds a lower-cased key → role map for the four role slots, skipping
// empty entries. Keys are group DNs (LDAP) or app-role/group ids (Entra).
func roleMap(admin, user, auditor, approver string) map[string]auth.Role {
	m := map[string]auth.Role{}
	add := func(key string, role auth.Role) {
		if key != "" {
			m[strings.ToLower(key)] = role
		}
	}
	add(admin, auth.RoleAdmin)
	add(user, auth.RoleUser)
	add(auditor, auth.RoleAuditor)
	add(approver, auth.RoleApprover)
	return m
}

// run loads configuration and starts the server: it builds the vault KEK,
// opens the store (Postgres or the in-memory demo store), wires the identity
// resolver, password authenticators and optional OIDC provider, configures
// alerting and upstream SSH host-key verification, constructs the API/portal
// handler, optionally launches the credential-lifecycle worker and the SSH
// proxy, then serves HTTP(S) until interrupted and shuts down gracefully.
func run() error {
	// Optionally source pamv1's own bootstrap secrets from CyberArk Conjur
	// (Phase 18) before reading the environment. A no-op unless PAM_CONJUR_URL is
	// set; SOPS/env remains the default. Fail-loud so a configured-but-unreachable
	// Conjur never starts the server with empty secrets.
	if err := conjur.SourceEnv(context.Background()); err != nil {
		return fmt.Errorf("conjur secret source: %w", err)
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logging.Setup(cfg.LogLevel, cfg.LogFormat)
	log := logging.Component("server")

	kek, err := vault.NewKEK(vault.KEKOptions{
		Provider:     cfg.KEKProvider,
		MasterKey:    cfg.MasterKey,
		TransitAddr:  cfg.TransitAddr,
		TransitToken: cfg.TransitToken,
		TransitKey:   cfg.TransitKey,
		AWSRegion:    cfg.AWSRegion,
		AWSKMSKeyID:  cfg.AWSKMSKeyID,

		PKCS11Module:     cfg.PKCS11Module,
		PKCS11Pin:        cfg.PKCS11Pin,
		PKCS11KeyLabel:   cfg.PKCS11KeyLabel,
		PKCS11TokenLabel: cfg.PKCS11TokenLabel,
	})
	if err != nil {
		return err
	}
	v := vault.NewWithKEK(kek)
	log.Info("vault ready", "kek", kek.ID())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var st store.Store
	if cfg.DatabaseURL == "memory" {
		log.Warn("using ephemeral in-memory store; data is lost on restart (demo mode)")
		st = memstore.New()
	} else {
		st, err = pgstore.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			return fmt.Errorf("connect to postgres: %w", err)
		}
	}
	defer st.Close()

	// Phase 12: overlay DB-persisted configuration onto the env-derived config
	// before building the identity backends and policy-driven components, so
	// stored settings take effect (identity/SSO/policy only; bootstrap/transport
	// stay environment-only). base keeps the pristine env baseline so the hot-swap
	// reconfigure closure can rebuild from env + the current overrides.
	base := *cfg
	if err := applyStoredConfig(ctx, st, v, cfg, log); err != nil {
		return err
	}

	resolver, err := auth.NewResolver(st, cfg.APIKey, cfg.BreakGlassKeyHash)
	if err != nil {
		return err
	}
	resolver.WithProfiles(st) // Phase 12: resolve custom permission profiles

	authn, directory, err := buildAuthenticator(cfg, log)
	if err != nil {
		return err
	}

	oidcProvider, err := buildOIDC(ctx, cfg, log)
	if err != nil {
		return err
	}

	sessions := session.NewRegistry()
	liveHub := session.NewHub()

	// Command control (Phase 16): compile the deny file, if configured, into a
	// guard shared by the SSH and database proxies. Fail-loud on a bad pattern.
	var cmdGuard *proxy.CommandGuard
	if cfg.CommandDenyFile != "" {
		denyBytes, derr := os.ReadFile(cfg.CommandDenyFile)
		if derr != nil {
			return fmt.Errorf("command deny file %q: %w", cfg.CommandDenyFile, derr)
		}
		cmdGuard, derr = proxy.NewCommandGuard(proxy.ParseCommandDeny(string(denyBytes)))
		if derr != nil {
			return fmt.Errorf("command deny file %q: %w", cfg.CommandDenyFile, derr)
		}
		log.Info("command control enabled", "patterns", cmdGuard.Size())
	}

	winrmClient := winrm.Client{HTTPS: cfg.WinRMHTTPS, Insecure: cfg.WinRMInsecure, NTLM: cfg.WinRMNTLM, Timeout: 30 * time.Second}

	alerter := buildAlerter(cfg, log)

	// Upstream SSH host-key verification (shared by the proxy and the rotation
	// connector). Empty PAM_SSH_KNOWN_HOSTS = trust any key (insecure, logged).
	var upstreamHostKey ssh.HostKeyCallback
	if cfg.SSHKnownHosts != "" {
		cb, herr := knownhosts.New(cfg.SSHKnownHosts)
		if herr != nil {
			return fmt.Errorf("ssh known_hosts %q: %w", cfg.SSHKnownHosts, herr)
		}
		upstreamHostKey = cb
		log.Info("upstream SSH host keys pinned", "known_hosts", cfg.SSHKnownHosts)
	}

	brokerPolicy, brokerAuditKey, brokerSignKey, err := buildBroker(cfg)
	if err != nil {
		return err
	}

	// SPIFFE JWT-SVID agent identity (Phase 13d): accepted alongside static agent
	// keys when a trust-domain JWKS is configured. Load-time failure is fatal.
	var svidVerifier agentid.Verifier
	if cfg.BrokerTrustDomainJWKS != "" {
		sv, err := agentid.NewSVIDVerifier(cfg.BrokerTrustDomainJWKS, cfg.BrokerTrustDomain, cfg.BrokerAudience, cfg.BrokerMaxDelegation)
		if err != nil {
			return fmt.Errorf("broker SVID verifier: %w", err)
		}
		svidVerifier = sv
		log.Info("agent broker accepts SPIFFE SVIDs", "trust_domain", cfg.BrokerTrustDomain, "max_delegation", cfg.BrokerMaxDelegation)
	}

	// reconfigure reproduces the hot-swappable RuntimeConfig from the pristine env
	// baseline plus the current DB overrides, so PUT/DELETE /api/config can rebuild
	// the identity backends and operational policy without a restart (Phase 12).
	reconfigure := func(ctx context.Context) (*api.RuntimeConfig, error) {
		c := base
		if err := applyStoredConfig(ctx, st, v, &c, log); err != nil {
			return nil, err
		}
		an, dir, err := buildAuthenticator(&c, log)
		if err != nil {
			return nil, err
		}
		op, err := buildOIDC(ctx, &c, log)
		if err != nil {
			return nil, err
		}
		return &api.RuntimeConfig{
			Authn:            an,
			Directory:        dir,
			OIDC:             op,
			OIDCRoleMap:      roleMap(c.OIDCRoleAdmin, c.OIDCRoleUser, c.OIDCRoleAuditor, c.OIDCRoleApprover),
			MFARequired:      c.MFARequired,
			RevealDisabled:   c.RevealDisabled,
			ApprovalRequired: c.RequireApproval,
			ApprovalWindow:   c.ApprovalWindow,
			CheckoutTTL:      c.CheckoutTTL,
			AllowedProtocols: splitAndTrim(c.AllowedProtocols),
		}, nil
	}

	handler, err := api.New(st, v, resolver, authn, api.Options{
		Sessions:            sessions,
		Live:                liveHub,
		SSHHostKeyCallback:  upstreamHostKey,
		MFARequired:         cfg.MFARequired,
		RecordingDir:        cfg.RecordingDir,
		WinRM:               winrmClient,
		OIDC:                oidcProvider,
		OIDCRoleMap:         roleMap(cfg.OIDCRoleAdmin, cfg.OIDCRoleUser, cfg.OIDCRoleAuditor, cfg.OIDCRoleApprover),
		PortalURL:           cfg.PortalURL,
		GuacdAddr:           cfg.GuacdAddr,
		GuacdRecordingPath:  cfg.GuacdRecordingPath,
		GuacdRDPSecurity:    cfg.GuacdRDPSecurity,
		GuacdIgnoreCert:     cfg.GuacdIgnoreCert,
		AuthRatePerMin:      cfg.AuthRatePerMin,
		RevealDisabled:      cfg.RevealDisabled,
		BreakGlassHashHex:   cfg.BreakGlassKeyHash,
		BreakGlassThreshold: cfg.BreakGlassThreshold,
		BreakGlassTTL:       cfg.BreakGlassTTL,
		Alerter:             alerter,
		RequireApproval:     cfg.RequireApproval,
		ApprovalWindow:      cfg.ApprovalWindow,
		AirGap:              cfg.AirGap,
		CheckoutTTL:         cfg.CheckoutTTL,
		AllowedProtocols:    splitAndTrim(cfg.AllowedProtocols),
		Directory:           directory,
		Reconfigure:         reconfigure,
		BrokerPolicy:        brokerPolicy,
		BrokerAuditKey:      brokerAuditKey,
		BrokerAuditSignKey:  brokerSignKey,
		BrokerTokenTTL:      cfg.BrokerTokenTTL,
		BrokerMaxArgBytes:   cfg.BrokerMaxArgBytes,
		BrokerRatePerMin:    cfg.BrokerRatePerMin,
		BrokerSVIDVerifier:  svidVerifier,
	})
	if err != nil {
		return err
	}
	if cfg.MFARequired {
		log.Info("MFA is required for password logins")
	}

	if cfg.RotateInterval > 0 {
		go handler.RunLifecycleWorker(ctx, api.RotationPolicy{
			Interval: cfg.RotateInterval,
			MaxAge:   cfg.RotateMaxAge,
		})
	}
	if cfg.BrokerPolicyFile != "" {
		go handler.RunBrokerTokenGC(ctx) // sweep spent/expired resume tokens
	}

	// errc receives the first fatal listener error (HTTP or SSH proxy); either
	// aborts startup loudly instead of running half a control plane.
	errc := make(chan error, 1)

	// proxyDone closes when the SSH proxy has fully drained; shutdown waits on it
	// so in-flight sessions' closing audit events and recordings are flushed
	// before the process (and the store) exits. Closed immediately when the proxy
	// is disabled so the shutdown wait is a no-op.
	proxyDone := make(chan struct{})
	if cfg.SSHAddr == "off" {
		close(proxyDone)
	}
	// dbProxyDone mirrors proxyDone for the PostgreSQL session proxy (Phase 15).
	dbProxyDone := make(chan struct{})
	if cfg.DBAddr == "off" {
		close(dbProxyDone)
	}
	if cfg.SSHAddr != "off" {
		hostKey, err := proxy.LoadOrCreateHostKey(cfg.SSHHostKeyPath)
		if err != nil {
			return fmt.Errorf("ssh host key: %w", err)
		}
		var onSessionEnd func(int64)
		if cfg.RotateAfterSession {
			onSessionEnd = func(credID int64) { handler.RotateCredentialByID(context.Background(), credID) }
			log.Info("post-session credential rotation enabled")
		}
		var proxyWinRM winrm.Runner
		if cfg.ProxyWinRM {
			proxyWinRM = winrmClient
			log.Info("interactive WinRM shell through the proxy enabled")
		}
		var jump *proxy.JumpConfig
		if cfg.SSHJumpHost != "" {
			keyPEM, jerr := os.ReadFile(cfg.SSHJumpKey)
			if jerr != nil {
				return fmt.Errorf("ssh jump key %q: %w", cfg.SSHJumpKey, jerr)
			}
			jump = &proxy.JumpConfig{Addr: cfg.SSHJumpHost, User: cfg.SSHJumpUser, KeyPEM: string(keyPEM), HostKey: upstreamHostKey}
		}
		px, err := proxy.New(st, v, resolver, proxy.Config{
			HostKey:          hostKey,
			RecordingDir:     cfg.RecordingDir,
			Sessions:         sessions,
			RequireApproval:  cfg.RequireApproval,
			UpstreamHostKey:  upstreamHostKey,
			OnSessionEnd:     onSessionEnd,
			AllowedProtocols: splitAndTrim(cfg.AllowedProtocols),
			WinRMRunner:      proxyWinRM,
			Jump:             jump,
			RequireRecording: cfg.RequireRecording,
			CommandGuard:     cmdGuard,
			Live:             liveHub,
		})
		if err != nil {
			return err
		}
		go func() {
			defer close(proxyDone)
			if err := px.ListenAndServe(ctx, cfg.SSHAddr); err != nil && ctx.Err() == nil {
				// A bind/listener failure (not graceful shutdown) is fatal: the PAM
				// must not run without its session broker.
				log.Error("ssh proxy stopped", "err", err)
				select {
				case errc <- fmt.Errorf("ssh proxy: %w", err):
				default:
				}
			}
		}()
	}

	// PostgreSQL session proxy (Phase 15): brokers postgres targets with JIT
	// credential injection and per-statement query audit, on its own listener.
	if cfg.DBAddr != "off" {
		var dbOnSessionEnd func(int64)
		if cfg.RotateAfterSession {
			dbOnSessionEnd = func(credID int64) { handler.RotateCredentialByID(context.Background(), credID) }
		}
		var dbClientTLS *tls.Config
		if cfg.TLSCert != "" && cfg.TLSKey != "" {
			cert, cerr := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
			if cerr != nil {
				return fmt.Errorf("db proxy tls: %w", cerr)
			}
			dbClientTLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
		}
		dbx, err := proxy.NewDB(st, v, resolver, proxy.DBConfig{
			RecordingDir:     cfg.RecordingDir,
			Sessions:         sessions,
			RequireApproval:  cfg.RequireApproval,
			AllowedProtocols: splitAndTrim(cfg.AllowedProtocols),
			RequireRecording: cfg.RequireRecording,
			ClientTLS:        dbClientTLS,
			OnSessionEnd:     dbOnSessionEnd,
			CommandGuard:     cmdGuard,
			Live:             liveHub,
		})
		if err != nil {
			return err
		}
		go func() {
			defer close(dbProxyDone)
			if err := dbx.ListenAndServe(ctx, cfg.DBAddr); err != nil && ctx.Err() == nil {
				log.Error("database proxy stopped", "err", err)
				select {
				case errc <- fmt.Errorf("database proxy: %w", err):
				default:
				}
			}
		}()
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	tlsEnabled := cfg.TLSCert != "" && cfg.TLSKey != ""
	if tlsEnabled {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	go func() {
		if tlsEnabled {
			errc <- srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	log.Info("pam-server listening", "addr", cfg.ListenAddr, "tls", tlsEnabled,
		"breakglass", cfg.BreakGlassKeyHash != "", "log_level", cfg.LogLevel)

	// drainProxy cancels the run context (so the proxy Serve returns) and waits,
	// bounded, for it to finish flushing session audit/recordings before the
	// deferred st.Close() runs — on either exit path.
	drainProxy := func() {
		stop() // cancel ctx so the proxies drain
		select {
		case <-proxyDone:
		case <-time.After(10 * time.Second):
			log.Warn("ssh proxy drain timed out")
		}
		select {
		case <-dbProxyDone:
		case <-time.After(10 * time.Second):
			log.Warn("database proxy drain timed out")
		}
	}

	select {
	case err := <-errc:
		// A listener failed. Shut the HTTP server and drain the proxy before
		// returning, so the store isn't closed under live sessions.
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		drainProxy()
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := srv.Shutdown(shutCtx)
		drainProxy()
		return err
	}
}

// buildAlerter assembles the configured real-time alert channels (webhook,
// syslog, email) into one Notifier, fanning out when several are set. Air-gap
// mode disables all outbound alerting.
func buildAlerter(cfg *config.Config, log *slog.Logger) alert.Notifier {
	if cfg.AirGap {
		log.Info("air-gap mode: outbound alerting disabled")
		return alert.Noop{}
	}
	var ns []alert.Notifier
	if cfg.AlertWebhook != "" {
		ns = append(ns, alert.NewWebhook(cfg.AlertWebhook))
		log.Info("alert channel enabled", "kind", "webhook")
	}
	if cfg.AlertSyslog != "" {
		network, addr := "udp", cfg.AlertSyslog
		for _, p := range []string{"udp", "tcp"} {
			if rest, ok := strings.CutPrefix(addr, p+"://"); ok {
				network, addr = p, rest
			}
		}
		ns = append(ns, alert.NewSyslog(network, addr, "pamv1"))
		log.Info("alert channel enabled", "kind", "syslog", "addr", addr)
	}
	if cfg.AlertEmailSMTP != "" && cfg.AlertEmailFrom != "" && cfg.AlertEmailTo != "" {
		to := splitAndTrim(cfg.AlertEmailTo)
		ns = append(ns, alert.NewEmail(cfg.AlertEmailSMTP, cfg.AlertEmailFrom, to, cfg.AlertEmailUser, cfg.AlertEmailPass))
		log.Info("alert channel enabled", "kind", "email", "recipients", len(to))
	}
	switch len(ns) {
	case 0:
		return alert.Noop{}
	case 1:
		return ns[0]
	default:
		return alert.Multi(ns)
	}
}

// splitAndTrim splits a comma-separated list, dropping empty/whitespace entries.
func splitAndTrim(csv string) []string {
	var out []string
	for _, p := range strings.Split(csv, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
