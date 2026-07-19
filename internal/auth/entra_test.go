package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// makeJWT builds an unsigned JWT whose payload carries the given claims.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." + enc(claims) + ".sig"
}

// mockEntra serves an OAuth2 token endpoint: it authenticates one user and
// returns an access token carrying the provided claims.
func mockEntra(t *testing.T, wantUser, wantPass string, claims map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "password" ||
			r.FormValue("username") != wantUser || r.FormValue("password") != wantPass {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant","error_description":"bad creds"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": makeJWT(t, claims), "token_type": "Bearer"})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newEntra builds an EntraAuthenticator pointed at endpoint with a fixed role map.
func newEntra(t *testing.T, endpoint string) *EntraAuthenticator {
	t.Helper()
	a, err := NewEntraAuthenticator(EntraConfig{
		TenantID: "tenant", ClientID: "client", ClientSecret: "secret",
		RoleMap: map[string]Role{
			"pam.admin":                            RoleAdmin,
			"pam.user":                             RoleUser,
			"11111111-1111-1111-1111-111111111111": RoleAuditor, // a group id
		},
		tokenEndpoint: endpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestEntraAppRoleLogin proves a user with a mapped app role logs in with that role.
func TestEntraAppRoleLogin(t *testing.T) {
	srv := mockEntra(t, "alice@contoso.com", "pw", map[string]any{
		"roles":              []string{"pam.user"},
		"preferred_username": "alice@contoso.com",
	})
	a := newEntra(t, srv.URL)
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
	srv := mockEntra(t, "bob", "pw", map[string]any{
		"roles":  []string{"pam.user"},
		"groups": []string{"11111111-1111-1111-1111-111111111111"}, // auditor
	})
	// user (from roles) + auditor (from groups) → highest privilege = auditor
	// among {user, auditor}; auditor outranks user in the order.
	a := newEntra(t, srv.URL)
	p, err := a.Authenticate(context.Background(), "bob", "pw")
	if err != nil || p.Role != RoleAuditor {
		t.Fatalf("got %+v err %v, want auditor", p, err)
	}
}

// TestEntraBadPassword proves a rejected credential returns ErrUnauthorized.
func TestEntraBadPassword(t *testing.T) {
	srv := mockEntra(t, "alice", "pw", map[string]any{"roles": []string{"pam.user"}})
	a := newEntra(t, srv.URL)
	if _, err := a.Authenticate(context.Background(), "alice", "wrong"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bad password: got %v, want ErrUnauthorized", err)
	}
}

// TestEntraNoMappedRole proves a user with no mapped claim returns ErrUnauthorized.
func TestEntraNoMappedRole(t *testing.T) {
	srv := mockEntra(t, "eve", "pw", map[string]any{"roles": []string{"SomethingElse"}})
	a := newEntra(t, srv.URL)
	if _, err := a.Authenticate(context.Background(), "eve", "pw"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("no mapped role: got %v, want ErrUnauthorized", err)
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
