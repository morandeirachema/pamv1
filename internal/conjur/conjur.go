// Package conjur is an optional runtime source for pamv1's OWN bootstrap secrets
// (Phase 18). When PAM_CONJUR_URL is set, pamv1 authenticates to a CyberArk
// Conjur instance at startup and fills any empty bootstrap PAM_* secret
// (master key, API key, database URL, break-glass hash, broker keys) from it —
// so those secrets can live in Conjur (with machine-identity auth, central
// rotation and access audit) instead of a sealed manifest. It is an alternative
// to the SOPS GitOps sealing (Phase 14), not a replacement: SOPS stays the
// zero-dependency default, Conjur is opt-in.
//
// The client is hand-rolled over the two Conjur REST endpoints pamv1 needs
// (authenticate + read secret), so it adds no dependency — the same approach the
// repo takes for MCP JSON-RPC and SPIFFE JWT verification.
package conjur

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/logging"
)

// Config describes how to reach a Conjur instance and authenticate to it.
type Config struct {
	URL     string // appliance base URL, e.g. https://conjur.example
	Account string // Conjur account (organizational namespace)

	// authn-api-key: a host login (e.g. "host/pamv1/pam-server") + its API key.
	Login  string
	APIKey string

	// authn-jwt: a Conjur JWT authenticator service id + the JWT to present
	// (typically a Kubernetes projected service-account token) — no static
	// bootstrap secret needs to live in Git.
	JWTServiceID string
	JWT          string

	CACertPEM string // optional PEM CA bundle for TLS to Conjur (empty = system roots)
	Timeout   time.Duration
}

// Client talks to a Conjur instance.
type Client struct {
	cfg  Config
	http *http.Client
	log  *slog.Logger
}

// New validates cfg and builds a Client. Exactly one authentication method
// (authn-api-key or authn-jwt) must be configured.
func New(cfg Config) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("conjur: URL is required")
	}
	if cfg.Account == "" {
		return nil, errors.New("conjur: account is required")
	}
	apiKeyAuth := cfg.Login != "" && cfg.APIKey != ""
	jwtAuth := cfg.JWTServiceID != "" && cfg.JWT != ""
	if apiKeyAuth == jwtAuth {
		return nil, errors.New("conjur: configure exactly one of authn-api-key (login + api key) or authn-jwt (service id + jwt)")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACertPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
			return nil, errors.New("conjur: PAM_CONJUR_CACERT is not a valid PEM bundle")
		}
		tlsCfg.RootCAs = pool
	}
	return &Client{
		cfg:  cfg,
		log:  logging.Component("conjur"),
		http: &http.Client{Timeout: cfg.Timeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	}, nil
}

// Authenticate exchanges the configured credential for a short-lived Conjur
// access token, base64-encoded ready for the Authorization header.
func (c *Client) Authenticate(ctx context.Context) (string, error) {
	base := strings.TrimRight(c.cfg.URL, "/")
	var endpoint, contentType, body string
	if c.cfg.JWT != "" {
		endpoint = fmt.Sprintf("%s/authn-jwt/%s/%s/authenticate", base, url.PathEscape(c.cfg.JWTServiceID), url.PathEscape(c.cfg.Account))
		contentType = "application/x-www-form-urlencoded"
		body = "jwt=" + url.QueryEscape(c.cfg.JWT)
	} else {
		endpoint = fmt.Sprintf("%s/authn/%s/%s/authenticate", base, url.PathEscape(c.cfg.Account), url.PathEscape(c.cfg.Login))
		contentType = "text/plain"
		body = c.cfg.APIKey
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("conjur authenticate: %w", err)
	}
	defer resp.Body.Close()
	tok, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("conjur authenticate: status %d", resp.StatusCode)
	}
	return base64.StdEncoding.EncodeToString(tok), nil
}

// Get retrieves a variable's value. found is false (with a nil error) when the
// variable has no value or is not permitted (HTTP 404) — a variable that simply
// isn't managed in Conjur, which the caller skips.
func (c *Client) Get(ctx context.Context, token, variableID string) (value string, found bool, err error) {
	endpoint := fmt.Sprintf("%s/secrets/%s/variable/%s",
		strings.TrimRight(c.cfg.URL, "/"), url.PathEscape(c.cfg.Account), url.PathEscape(variableID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Authorization", `Token token="`+token+`"`)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("conjur get %q: %w", variableID, err)
	}
	defer resp.Body.Close()
	val, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", false, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return string(val), true, nil
	case http.StatusNotFound:
		return "", false, nil
	default:
		return "", false, fmt.Errorf("conjur get %q: status %d", variableID, resp.StatusCode)
	}
}

// bootstrapSecrets maps each PAM_* bootstrap secret to its Conjur variable
// suffix (under the policy prefix). Only secrets empty in the environment are
// sourced, so an explicit env value always wins.
var bootstrapSecrets = []struct{ env, suffix string }{
	{"PAM_MASTER_KEY", "master-key"},
	{"PAM_API_KEY", "api-key"},
	{"PAM_DATABASE_URL", "database-url"},
	{"PAM_BREAK_GLASS_KEY_HASH", "break-glass-key-hash"},
	{"PAM_BROKER_AUDIT_KEY", "broker-audit-key"},
	{"PAM_BROKER_AUDIT_SIGN_SEED", "broker-audit-sign-seed"},
}

// SourceEnv is the startup entry point. When Conjur is configured (PAM_CONJUR_URL
// set, or PAM_SECRETS_PROVIDER=conjur), it authenticates and fills any empty
// bootstrap PAM_* secret from Conjur before config.Load reads the environment.
// It fails loud on auth/transport errors — a configured-but-unreachable Conjur
// must not silently start pamv1 with empty secrets — but treats a variable
// missing in Conjur (404) as "not managed here" and leaves it to the normal
// fail-loud config validation. Disabled = no-op.
func SourceEnv(ctx context.Context) error {
	provider := strings.EqualFold(os.Getenv("PAM_SECRETS_PROVIDER"), "conjur")
	urlSet := os.Getenv("PAM_CONJUR_URL") != ""
	if !provider && !urlSet {
		return nil // Conjur disabled; SOPS/env is the source
	}
	if provider && !urlSet {
		return errors.New("PAM_SECRETS_PROVIDER=conjur requires PAM_CONJUR_URL")
	}

	jwt, err := readFileEnv("PAM_CONJUR_JWT_FILE")
	if err != nil {
		return err
	}
	cacert, err := readFileEnv("PAM_CONJUR_CACERT")
	if err != nil {
		return err
	}
	c, err := New(Config{
		URL:          os.Getenv("PAM_CONJUR_URL"),
		Account:      getenv("PAM_CONJUR_ACCOUNT", "default"),
		Login:        os.Getenv("PAM_CONJUR_AUTHN_LOGIN"),
		APIKey:       os.Getenv("PAM_CONJUR_API_KEY"),
		JWTServiceID: os.Getenv("PAM_CONJUR_AUTHN_JWT_SERVICE_ID"),
		JWT:          strings.TrimSpace(jwt),
		CACertPEM:    cacert,
	})
	if err != nil {
		return err
	}
	return c.populateEnv(ctx)
}

// populateEnv authenticates once and fills empty bootstrap secrets from Conjur.
func (c *Client) populateEnv(ctx context.Context) error {
	prefix := getenv("PAM_CONJUR_POLICY_PREFIX", "pamv1")
	token, err := c.Authenticate(ctx)
	if err != nil {
		return err
	}
	filled := make([]string, 0, len(bootstrapSecrets))
	for _, s := range bootstrapSecrets {
		if os.Getenv(s.env) != "" {
			continue // an explicit env value wins
		}
		val, ok, err := c.Get(ctx, token, prefix+"/"+s.suffix)
		if err != nil {
			return err
		}
		if !ok {
			continue // not managed in Conjur
		}
		if err := os.Setenv(s.env, val); err != nil {
			return err
		}
		filled = append(filled, s.env)
	}
	// The values themselves are never logged — only which keys Conjur supplied.
	c.log.Info("sourced bootstrap secrets from Conjur", "url", c.cfg.URL, "account", c.cfg.Account, "keys", strings.Join(filled, ","))
	return nil
}

// readFileEnv reads the file named by the env var key, returning "" when the var
// is unset. A set-but-unreadable path is a fail-loud error.
func readFileEnv(key string) (string, error) {
	path := os.Getenv(key)
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path) // #nosec G703 G304 -- path is the operator-set PAM_CONJUR_JWT_FILE, not request input
	if err != nil {
		return "", fmt.Errorf("%s %q: %w", key, path, err)
	}
	return string(b), nil
}

// getenv returns the env var value or a default.
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
