package api_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/oidc"
)

const oidcIssuer = "https://issuer.test"

// tokenBox holds the id_token the mock IdP will return next (set by the test
// once it knows the nonce from the authorize redirect).
type tokenBox struct {
	mu sync.Mutex
	v  string
}

// set stores the id_token the mock IdP will return next.
func (b *tokenBox) set(s string) { b.mu.Lock(); b.v = s; b.mu.Unlock() }

// get returns the currently stored id_token.
func (b *tokenBox) get() string { b.mu.Lock(); defer b.mu.Unlock(); return b.v }

// signToken builds an RS256-signed JWT (kid "k1") carrying the given claims.
func signToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	in := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"}) + "." + enc(claims)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// oidcServer starts a mock IdP (token + JWKS endpoints) and a PAM server wired to
// it, returning the PAM server, its token box, and the IdP signing key.
func oidcServer(t *testing.T) (*httptest.Server, *tokenBox, *rsa.PrivateKey) {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	box := &tokenBox{}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"id_token": box.get()})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		e := big.NewInt(int64(key.PublicKey.E)).Bytes()
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": "k1", "kty": "RSA",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(e),
		}}})
	})
	idp := httptest.NewServer(mux)
	t.Cleanup(idp.Close)

	provider, err := oidc.NewProvider(oidc.Config{
		Issuer: oidcIssuer, ClientID: "pam", ClientSecret: "s",
		RedirectURL: "https://pam.example.com/api/auth/oidc/callback",
		AuthURL:     idp.URL + "/authorize", TokenURL: idp.URL + "/token", JWKSURL: idp.URL + "/keys",
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		OIDC:        provider,
		OIDCRoleMap: map[string]auth.Role{"pam.admin": auth.RoleAdmin},
		PortalURL:   "/",
	})
	return srv, box, key
}

// noRedirect returns a client that surfaces 3xx instead of following them.
func noRedirect(srv *httptest.Server) *http.Client {
	c := srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// TestOIDCLoginFlow walks the full Authorization Code + PKCE flow and confirms
// the issued session carries the mapped admin role.
func TestOIDCLoginFlow(t *testing.T) {
	srv, box, key := oidcServer(t)
	client := noRedirect(srv)

	// 1. Start → 302 to the IdP authorize URL; capture state + nonce.
	resp, err := client.Get(srv.URL + "/api/auth/oidc/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start status = %d, want 302", resp.StatusCode)
	}
	authURL, _ := url.Parse(resp.Header.Get("Location"))
	state := authURL.Query().Get("state")
	nonce := authURL.Query().Get("nonce")
	if state == "" || nonce == "" || authURL.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("bad authorize redirect: %s", authURL)
	}

	// 2. The IdP would now sign an id_token carrying that nonce.
	box.set(signToken(t, key, map[string]any{
		"iss": oidcIssuer, "aud": "pam", "exp": time.Now().Add(time.Hour).Unix(),
		"nonce": nonce, "sub": "u1", "preferred_username": "alice@contoso.com",
		"roles": []string{"pam.admin"},
	}))

	// 3. Callback → 302 back to the portal with a token in the fragment.
	resp, err = client.Get(srv.URL + "/api/auth/oidc/callback?code=abc&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	frag, _ := url.Parse(loc)
	vals, _ := url.ParseQuery(frag.Fragment)
	token := vals.Get("pam_token")
	if token == "" {
		t.Fatalf("callback did not return a token: %s", loc)
	}

	// 4. The issued session works and carries the admin role.
	if status, _ := do(t, srv, http.MethodGet, "/api/targets", token, nil); status != http.StatusOK {
		t.Fatalf("oidc session should access targets: %d", status)
	}
	if status, _ := do(t, srv, http.MethodPost, "/api/users", token,
		map[string]any{"username": "x", "role": "user"}); status != http.StatusCreated {
		t.Fatalf("oidc admin should manage users: %d", status)
	}
}

// TestOIDCCallbackBadState verifies an unknown state redirects back with
// pam_error=invalid_state.
func TestOIDCCallbackBadState(t *testing.T) {
	srv, _, _ := oidcServer(t)
	client := noRedirect(srv)
	resp, err := client.Get(srv.URL + "/api/auth/oidc/callback?code=abc&state=nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	frag, _ := url.Parse(resp.Header.Get("Location"))
	if v, _ := url.ParseQuery(frag.Fragment); v.Get("pam_error") != "invalid_state" {
		t.Fatalf("bad state should redirect with pam_error=invalid_state, got %s", resp.Header.Get("Location"))
	}
}

// TestOIDCNotConfigured verifies the OIDC start endpoint is 404 when OIDC is not
// configured.
func TestOIDCNotConfigured(t *testing.T) {
	srv := newTestServer(t)
	client := noRedirect(srv)
	resp, err := client.Get(srv.URL + "/api/auth/oidc/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("oidc start without config = %d, want 404", resp.StatusCode)
	}
}
