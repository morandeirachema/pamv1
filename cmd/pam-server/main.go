// pam-server runs the pamv1 API and portal.
//
// Utility flags:
//
//	-genkey   print a fresh vault master key (PAM_MASTER_KEY) and exit
//	-hashkey  read an emergency break-glass key from stdin and print its
//	          SHA-256 hex (PAM_BREAK_GLASS_KEY_HASH); the plaintext key is
//	          then sealed offline (envelope / safe) and never stored.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/config"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/proxy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/store/pgstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

func main() {
	genkey := flag.Bool("genkey", false, "print a new vault master key and exit")
	hashkey := flag.Bool("hashkey", false, "read a break-glass key from stdin, print its SHA-256 hex and exit")
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
		sum := sha256.Sum256([]byte(strings.TrimSpace(string(data))))
		fmt.Println(hex.EncodeToString(sum[:]))
	default:
		if err := run(); err != nil {
			fatal(err)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "pam-server:", err)
	os.Exit(1)
}

// buildAuthenticator wires the enabled password identity sources (on-prem AD via
// LDAP and/or Microsoft Entra ID) into a single Authenticator, or nil if none.
func buildAuthenticator(cfg *config.Config, log *slog.Logger) (auth.Authenticator, error) {
	var sources []auth.Authenticator

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
			return nil, fmt.Errorf("ldap: %w", err)
		}
		sources = append(sources, ldapAuth)
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
			return nil, fmt.Errorf("entra: %w", err)
		}
		sources = append(sources, entraAuth)
		log.Info("entra id login enabled", "tenant", cfg.EntraTenantID)
	}

	return auth.NewChain(sources...), nil
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

func run() error {
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

	resolver, err := auth.NewResolver(st, cfg.APIKey, cfg.BreakGlassKeyHash)
	if err != nil {
		return err
	}

	authn, err := buildAuthenticator(cfg, log)
	if err != nil {
		return err
	}

	handler, err := api.New(st, v, resolver, authn)
	if err != nil {
		return err
	}

	if cfg.SSHAddr != "off" {
		hostKey, err := proxy.LoadOrCreateHostKey(cfg.SSHHostKeyPath)
		if err != nil {
			return fmt.Errorf("ssh host key: %w", err)
		}
		px, err := proxy.New(st, v, resolver, proxy.Config{
			HostKey:      hostKey,
			RecordingDir: cfg.RecordingDir,
		})
		if err != nil {
			return err
		}
		go func() {
			if err := px.ListenAndServe(ctx, cfg.SSHAddr); err != nil {
				log.Error("ssh proxy stopped", "err", err)
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

	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("pam-server listening", "addr", cfg.ListenAddr,
		"breakglass", cfg.BreakGlassKeyHash != "", "log_level", cfg.LogLevel)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	}
}
