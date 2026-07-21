package conjur_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/conjur"
)

// fakeConjur is a minimal in-process Conjur that issues a token on authenticate
// and serves the seeded variables (404 for the rest), so tests exercise the real
// authenticate → retrieve flow without a live Conjur.
func fakeConjur(t *testing.T, vars map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/authenticate"):
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			_, _ = w.Write([]byte(`{"protected":"x","payload":"y","signature":"z"}`))
		case strings.Contains(r.URL.Path, "/secrets/"):
			// A secret read must carry the access token.
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Token token=") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			i := strings.Index(r.URL.Path, "/variable/")
			id := r.URL.Path[i+len("/variable/"):] // decoded, e.g. pamv1/master-key
			if v, ok := vars[id]; ok {
				_, _ = w.Write([]byte(v))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestAuthenticateAndGet proves the client authenticates and retrieves a
// variable, and reports a missing variable as not-found (not an error).
func TestAuthenticateAndGet(t *testing.T) {
	srv := fakeConjur(t, map[string]string{"pamv1/master-key": "the-master-key"})
	c, err := conjur.New(conjur.Config{URL: srv.URL, Account: "default", Login: "host/pamv1", APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.Authenticate(context.Background())
	if err != nil || tok == "" {
		t.Fatalf("Authenticate: tok=%q err=%v", tok, err)
	}
	if v, ok, err := c.Get(context.Background(), tok, "pamv1/master-key"); err != nil || !ok || v != "the-master-key" {
		t.Fatalf("Get: v=%q ok=%v err=%v", v, ok, err)
	}
	if _, ok, err := c.Get(context.Background(), tok, "pamv1/absent"); err != nil || ok {
		t.Fatalf("Get(absent): ok=%v err=%v, want not-found without error", ok, err)
	}
}

// TestAuthFailureIsLoud proves a rejected authentication is a hard error.
func TestAuthFailureIsLoud(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c, err := conjur.New(conjur.Config{URL: srv.URL, Account: "default", Login: "host/pamv1", APIKey: "bad"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Authenticate(context.Background()); err == nil {
		t.Fatal("expected an error for rejected authentication")
	}
}

// TestNewValidation proves exactly one auth method must be configured.
func TestNewValidation(t *testing.T) {
	if _, err := conjur.New(conjur.Config{URL: "https://c", Account: "default"}); err == nil {
		t.Fatal("no auth method: expected an error")
	}
	if _, err := conjur.New(conjur.Config{URL: "https://c", Account: "default", Login: "l", APIKey: "k", JWTServiceID: "s", JWT: "j"}); err == nil {
		t.Fatal("two auth methods: expected an error")
	}
	if _, err := conjur.New(conjur.Config{Account: "default", Login: "l", APIKey: "k"}); err == nil {
		t.Fatal("missing URL: expected an error")
	}
}

// TestSourceEnvFillsEmptyOnly proves SourceEnv sources empty bootstrap secrets
// from Conjur while an explicit environment value wins.
func TestSourceEnvFillsEmptyOnly(t *testing.T) {
	srv := fakeConjur(t, map[string]string{
		"pamv1/master-key":   "conjur-master",
		"pamv1/api-key":      "conjur-api",
		"pamv1/database-url": "postgres://from-conjur",
	})
	t.Setenv("PAM_CONJUR_URL", srv.URL)
	t.Setenv("PAM_CONJUR_ACCOUNT", "default")
	t.Setenv("PAM_CONJUR_AUTHN_LOGIN", "host/pamv1")
	t.Setenv("PAM_CONJUR_API_KEY", "k")
	t.Setenv("PAM_MASTER_KEY", "")               // empty → sourced from Conjur
	t.Setenv("PAM_DATABASE_URL", "")             // empty → sourced from Conjur
	t.Setenv("PAM_API_KEY", "explicit-from-env") // set → must win

	if err := conjur.SourceEnv(context.Background()); err != nil {
		t.Fatalf("SourceEnv: %v", err)
	}
	if got := os.Getenv("PAM_MASTER_KEY"); got != "conjur-master" {
		t.Fatalf("PAM_MASTER_KEY = %q, want conjur-master", got)
	}
	if got := os.Getenv("PAM_DATABASE_URL"); got != "postgres://from-conjur" {
		t.Fatalf("PAM_DATABASE_URL = %q, want the Conjur value", got)
	}
	if got := os.Getenv("PAM_API_KEY"); got != "explicit-from-env" {
		t.Fatalf("PAM_API_KEY = %q, an explicit env value must win", got)
	}
}

// TestSourceEnvDisabled proves SourceEnv is a no-op when Conjur is not configured.
func TestSourceEnvDisabled(t *testing.T) {
	t.Setenv("PAM_CONJUR_URL", "")
	t.Setenv("PAM_SECRETS_PROVIDER", "")
	t.Setenv("PAM_MASTER_KEY", "unchanged")
	if err := conjur.SourceEnv(context.Background()); err != nil {
		t.Fatalf("disabled SourceEnv should be a no-op, got %v", err)
	}
	if os.Getenv("PAM_MASTER_KEY") != "unchanged" {
		t.Fatal("disabled SourceEnv must not touch the environment")
	}
}

// TestSourceEnvProviderWithoutURL proves the fail-loud misconfiguration path.
func TestSourceEnvProviderWithoutURL(t *testing.T) {
	t.Setenv("PAM_CONJUR_URL", "")
	t.Setenv("PAM_SECRETS_PROVIDER", "conjur")
	if err := conjur.SourceEnv(context.Background()); err == nil {
		t.Fatal("PAM_SECRETS_PROVIDER=conjur without PAM_CONJUR_URL must fail loud")
	}
}
