package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signIDToken builds an RS256-signed JWT for the given claims.
func signIDToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	payload := enc(claims)
	signingInput := header + "." + payload
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func b64uint(i int) string {
	b := big.NewInt(int64(i)).Bytes()
	return base64.RawURLEncoding.EncodeToString(b)
}

// mockIdP serves a token endpoint returning idToken and a JWKS with the public key.
func mockIdP(t *testing.T, key *rsa.PrivateKey, kid, idToken string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"id_token": idToken, "token_type": "Bearer"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kid": kid, "kty": "RSA",
			"n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e": b64uint(key.PublicKey.E),
		}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func provider(t *testing.T, srv *httptest.Server, issuer string) *Provider {
	t.Helper()
	p, err := NewProvider(Config{
		Issuer: issuer, ClientID: "pam-client", ClientSecret: "secret",
		RedirectURL: "https://pam.example.com/api/auth/oidc/callback",
		AuthURL:     srv.URL + "/authorize", TokenURL: srv.URL + "/token", JWKSURL: srv.URL + "/keys",
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExchangeValidToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	const issuer = "https://issuer.example.com"
	idToken := signIDToken(t, key, "k1", map[string]any{
		"iss": issuer, "aud": "pam-client", "exp": time.Now().Add(time.Hour).Unix(),
		"nonce": "nonce-123", "sub": "abc", "preferred_username": "alice@contoso.com",
		"roles": []string{"pam.admin"},
	})
	srv := mockIdP(t, key, "k1", idToken)
	p := provider(t, srv, issuer)

	claims, err := p.Exchange(context.Background(), "code", "verifier", "nonce-123")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if claims.PreferredUsername != "alice@contoso.com" || len(claims.Roles) != 1 || claims.Roles[0] != "pam.admin" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestExchangeRejects(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	const issuer = "https://issuer.example.com"
	base := func() map[string]any {
		return map[string]any{
			"iss": issuer, "aud": "pam-client", "exp": time.Now().Add(time.Hour).Unix(),
			"nonce": "nonce-123", "sub": "abc",
		}
	}
	cases := []struct {
		name       string
		signKey    *rsa.PrivateKey
		claims     map[string]any
		checkNonce string
	}{
		{"bad signature", other, base(), "nonce-123"},
		{"wrong issuer", key, merge(base(), "iss", "https://evil"), "nonce-123"},
		{"wrong audience", key, merge(base(), "aud", "someone-else"), "nonce-123"},
		{"nonce mismatch", key, base(), "different-nonce"},
		{"expired", key, merge(base(), "exp", time.Now().Add(-2*time.Hour).Unix()), "nonce-123"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idToken := signIDToken(t, c.signKey, "k1", c.claims)
			srv := mockIdP(t, key, "k1", idToken) // JWKS always the real key
			p := provider(t, srv, issuer)
			if _, err := p.Exchange(context.Background(), "code", "verifier", c.checkNonce); err == nil {
				t.Fatalf("%s: expected rejection", c.name)
			}
		})
	}
}

func TestAuthCodeURLAndPKCE(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := mockIdP(t, key, "k1", "")
	p := provider(t, srv, "https://issuer.example.com")

	verifier, challenge, err := GeneratePKCE()
	if err != nil || verifier == "" || challenge == verifier {
		t.Fatalf("pkce: v=%q c=%q err=%v", verifier, challenge, err)
	}
	u := p.AuthCodeURL("state-1", "nonce-1", challenge)
	for _, want := range []string{"response_type=code", "client_id=pam-client", "code_challenge_method=S256", "state=state-1", "nonce=nonce-1"} {
		if !strings.Contains(u, want) {
			t.Fatalf("auth url %q missing %q", u, want)
		}
	}
}

func merge(m map[string]any, k string, v any) map[string]any {
	m[k] = v
	return m
}
