package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// signRS256 builds an RS256-signed JWT with the given kid and claims.
func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signingInput := enc(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}) + "." + enc(claims)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// b64exp base64url-encodes a JWK's public exponent.
func b64exp(e int) string {
	var b []byte
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// entraTestServer serves the ROPC token endpoint (returning idToken for the right
// creds) and a JWKS advertising pub under kid.
func entraTestServer(t *testing.T, wantUser, wantPass, idToken, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/keys" {
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kid": kid, "kty": "RSA",
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": b64exp(pub.E),
			}}})
			return
		}
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "password" ||
			r.FormValue("username") != wantUser || r.FormValue("password") != wantPass {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant","error_description":"bad creds"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": idToken, "token_type": "Bearer"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newEntraKeys wires an EntraAuthenticator to a mock token+JWKS server. The
// id_token is signed by signKey; the JWKS advertises advertiseKey — pass the same
// key for a valid setup, or a different one to simulate a bad signature.
func newEntraKeys(t *testing.T, wantUser, wantPass string, claims map[string]any, signKey, advertiseKey *rsa.PrivateKey) *EntraAuthenticator {
	t.Helper()
	const kid = "test-kid"
	claims["aud"] = "client"
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	idToken := signRS256(t, signKey, kid, claims)
	srv := entraTestServer(t, wantUser, wantPass, idToken, kid, &advertiseKey.PublicKey)
	a, err := NewEntraAuthenticator(EntraConfig{
		TenantID: "tenant", ClientID: "client", ClientSecret: "secret",
		RoleMap: map[string]Role{
			"pam.admin":                            RoleAdmin,
			"pam.user":                             RoleUser,
			"11111111-1111-1111-1111-111111111111": RoleAuditor, // a group id
		},
		tokenEndpoint: srv.URL + "/token",
		jwksURL:       srv.URL + "/keys",
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// newEntra wires an EntraAuthenticator with a correctly signed id_token.
func newEntra(t *testing.T, wantUser, wantPass string, claims map[string]any) *EntraAuthenticator {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return newEntraKeys(t, wantUser, wantPass, claims, key, key)
}

// TestEntraAppRoleLogin proves a user with a mapped app role logs in with that role.
func TestEntraAppRoleLogin(t *testing.T) {
	a := newEntra(t, "alice@contoso.com", "pw", map[string]any{
		"roles":              []string{"pam.user"},
		"preferred_username": "alice@contoso.com",
	})
	p, err := a.Authenticate(context.Background(), "alice@contoso.com", "pw")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if p.Name != "alice@contoso.com" || p.Role != RoleUser {
		t.Fatalf("got %+v, want alice/user", p)
	}
}

// TestEntraGroupClaimAndHighestWins proves group claims are honored and the
// highest-privilege mapped claim wins.
func TestEntraGroupClaimAndHighestWins(t *testing.T) {
	// user (from roles) + auditor (from groups) → auditor outranks user.
	a := newEntra(t, "bob", "pw", map[string]any{
		"roles":  []string{"pam.user"},
		"groups": []string{"11111111-1111-1111-1111-111111111111"}, // auditor
	})
	p, err := a.Authenticate(context.Background(), "bob", "pw")
	if err != nil || p.Role != RoleAuditor {
		t.Fatalf("got %+v err %v, want auditor", p, err)
	}
}

// TestEntraBadPassword proves a rejected credential returns ErrUnauthorized.
func TestEntraBadPassword(t *testing.T) {
	a := newEntra(t, "alice", "pw", map[string]any{"roles": []string{"pam.user"}})
	if _, err := a.Authenticate(context.Background(), "alice", "wrong"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bad password: got %v, want ErrUnauthorized", err)
	}
}

// TestEntraNoMappedRole proves a user with no mapped claim returns ErrUnauthorized.
func TestEntraNoMappedRole(t *testing.T) {
	a := newEntra(t, "eve", "pw", map[string]any{"roles": []string{"SomethingElse"}})
	if _, err := a.Authenticate(context.Background(), "eve", "pw"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("no mapped role: got %v, want ErrUnauthorized", err)
	}
}

// TestEntraRejectsBadSignature proves an id_token whose signature does not match
// the JWKS is rejected (the signature is now validated, not just parsed).
func TestEntraRejectsBadSignature(t *testing.T) {
	signKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	// The token is signed by signKey, but the JWKS advertises otherKey.
	a := newEntraKeys(t, "mallory", "pw", map[string]any{"roles": []string{"pam.admin"}}, signKey, otherKey)
	if _, err := a.Authenticate(context.Background(), "mallory", "pw"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("forged token: got %v, want ErrUnauthorized", err)
	}
}

// TestEntraValidation proves an empty config is rejected by the constructor.
func TestEntraValidation(t *testing.T) {
	if _, err := NewEntraAuthenticator(EntraConfig{}); err == nil {
		t.Fatal("empty config should error")
	}
}

// fakeAuth is a trivial Authenticator for chain tests.
type fakeAuth struct {
	user, pass string
	role       Role
}

// Authenticate returns a Principal when u/p match the fixture, else ErrUnauthorized.
func (f fakeAuth) Authenticate(_ context.Context, u, p string) (*Principal, error) {
	if u == f.user && p == f.pass {
		return &Principal{Name: u, Role: f.role}, nil
	}
	return nil, ErrUnauthorized
}

// TestChainAuthenticator checks chain construction (all-nil, single, multi) and
// that authentication falls through to a later source or ends unauthorized.
func TestChainAuthenticator(t *testing.T) {
	if NewChain(nil, nil) != nil {
		t.Fatal("all-nil chain should be nil")
	}
	single := fakeAuth{user: "a", pass: "1", role: RoleUser}
	if got := NewChain(nil, single); got != Authenticator(single) {
		t.Fatal("single non-nil should return that authenticator")
	}

	chain := NewChain(
		fakeAuth{user: "ldapuser", pass: "x", role: RoleAdmin},
		fakeAuth{user: "entrauser", pass: "y", role: RoleAuditor},
	)
	// Resolves via the second source when the first rejects.
	p, err := chain.Authenticate(context.Background(), "entrauser", "y")
	if err != nil || p.Role != RoleAuditor {
		t.Fatalf("chain second source: got %+v err %v", p, err)
	}
	// Neither matches → unauthorized.
	if _, err := chain.Authenticate(context.Background(), "nobody", "z"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("chain no match: got %v", err)
	}
}
