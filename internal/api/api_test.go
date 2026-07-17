package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

const (
	testAPIKey     = "test-api-key"
	breakGlassKey  = "sealed-emergency-key"
	secretPassword = "S3cret-P@ssw0rd!"
)

// newTestServerStore returns a running server and its backing store so tests
// can seed users with specific roles.
func newTestServerStore(t *testing.T) (*httptest.Server, store.Store) {
	t.Helper()
	return newTestServerAuthn(t, nil)
}

// newTestServerAuthn builds a server with an optional password authenticator.
func newTestServerAuthn(t *testing.T, authn auth.Authenticator) (*httptest.Server, store.Store) {
	t.Helper()
	masterKey, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	bgHash := sha256.Sum256([]byte(breakGlassKey))
	resolver, err := auth.NewResolver(st, testAPIKey, hex.EncodeToString(bgHash[:]))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := api.New(st, v, resolver, authn)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, st
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv, _ := newTestServerStore(t)
	return srv
}

// seedUser creates a user with the given role and returns its token.
func seedUser(t *testing.T, srv *httptest.Server, username, role string) string {
	t.Helper()
	status, data := do(t, srv, http.MethodPost, "/api/users", testAPIKey,
		map[string]any{"username": username, "role": role})
	if status != http.StatusCreated {
		t.Fatalf("seed user %s: status %d body %s", username, status, data)
	}
	tok, _ := jsonMap(t, data)["token"].(string)
	if tok == "" {
		t.Fatalf("seed user %s: no token returned: %s", username, data)
	}
	return tok
}

func do(t *testing.T, srv *httptest.Server, method, path, apiKey string, body any) (int, []byte) {
	t.Helper()
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, buf)
	if err != nil {
		t.Fatal(err)
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func jsonMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal %q: %v", data, err)
	}
	return m
}

func TestHealthzIsOpen(t *testing.T) {
	srv := newTestServer(t)
	status, _ := do(t, srv, http.MethodGet, "/healthz", "", nil)
	if status != http.StatusOK {
		t.Fatalf("healthz status = %d", status)
	}
}

func TestAuthRequired(t *testing.T) {
	srv := newTestServer(t)
	for _, key := range []string{"", "wrong-key"} {
		status, _ := do(t, srv, http.MethodGet, "/api/targets", key, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("key %q: status = %d, want 401", key, status)
		}
	}
}

func TestFullFlow(t *testing.T) {
	srv := newTestServer(t)

	status, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, data)
	}
	targetID := int64(jsonMap(t, data)["id"].(float64))

	status, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "root", "secret": secretPassword,
	})
	if status != http.StatusCreated {
		t.Fatalf("create credential: %d %s", status, data)
	}
	if strings.Contains(string(data), secretPassword) || strings.Contains(string(data), "secret_enc") {
		t.Fatalf("credential response leaks secret material: %s", data)
	}
	credID := int64(jsonMap(t, data)["id"].(float64))

	status, data = do(t, srv, http.MethodGet, "/api/credentials?target_id=1", testAPIKey, nil)
	if status != http.StatusOK || strings.Contains(string(data), secretPassword) {
		t.Fatalf("list credentials: %d %s", status, data)
	}

	status, data = do(t, srv, http.MethodPost,
		"/api/credentials/"+itoa(credID)+"/reveal", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("reveal: %d %s", status, data)
	}
	if jsonMap(t, data)["secret"] != secretPassword {
		t.Fatalf("revealed secret mismatch: %s", data)
	}

	status, data = do(t, srv, http.MethodGet, "/api/audit", testAPIKey, nil)
	if status != http.StatusOK || !strings.Contains(string(data), "credential.reveal") {
		t.Fatalf("audit must record the reveal: %d %s", status, data)
	}

	status, _ = do(t, srv, http.MethodDelete, "/api/targets/"+itoa(targetID), testAPIKey, nil)
	if status != http.StatusNoContent {
		t.Fatalf("delete target: %d", status)
	}
	status, data = do(t, srv, http.MethodGet, "/api/credentials", testAPIKey, nil)
	if status != http.StatusOK || strings.TrimSpace(string(data)) != "[]" {
		t.Fatalf("credentials must cascade on target delete: %s", data)
	}
}

func TestBreakGlass(t *testing.T) {
	srv := newTestServer(t)
	status, _ := do(t, srv, http.MethodGet, "/api/targets", breakGlassKey, nil)
	if status != http.StatusOK {
		t.Fatalf("break-glass key rejected: %d", status)
	}
	status, data := do(t, srv, http.MethodGet, "/api/audit", testAPIKey, nil)
	if status != http.StatusOK || !strings.Contains(string(data), "breakglass.access") ||
		!strings.Contains(string(data), "break-glass") {
		t.Fatalf("break-glass use must be audited: %d %s", status, data)
	}
}

func TestValidationAndConflicts(t *testing.T) {
	srv := newTestServer(t)
	status, _ := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "x", "host": "h", "os_type": "solaris", "protocol": "ssh",
	})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("bad os_type: %d, want 422", status)
	}
	payload := map[string]any{"name": "dup", "host": "h", "os_type": "linux", "protocol": "ssh"}
	if status, _ = do(t, srv, http.MethodPost, "/api/targets", testAPIKey, payload); status != http.StatusCreated {
		t.Fatalf("create: %d", status)
	}
	if status, _ = do(t, srv, http.MethodPost, "/api/targets", testAPIKey, payload); status != http.StatusConflict {
		t.Fatalf("duplicate name: %d, want 409", status)
	}
}

func TestRBAC(t *testing.T) {
	srv := newTestServer(t)

	userTok := seedUser(t, srv, "alice", "user")
	auditorTok := seedUser(t, srv, "theo", "auditor")
	approverTok := seedUser(t, srv, "peggy", "approver")

	// Seed a target + credential as admin so read/reveal paths have data.
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "db-01", "host": "10.0.0.9", "os_type": "linux", "protocol": "ssh",
	})
	targetID := int64(jsonMap(t, data)["id"].(float64))
	_, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "root", "secret": secretPassword,
	})
	credID := int64(jsonMap(t, data)["id"].(float64))

	type tc struct {
		name, method, path, key string
		body                    any
		want                    int
	}
	newTarget := map[string]any{"name": "x", "host": "h", "os_type": "linux", "protocol": "ssh"}
	cases := []tc{
		// user: can read inventory, cannot manage / reveal / audit / users
		{"user reads targets", http.MethodGet, "/api/targets", userTok, nil, 200},
		{"user cannot create target", http.MethodPost, "/api/targets", userTok, newTarget, 403},
		{"user cannot reveal", http.MethodPost, "/api/credentials/" + itoa(credID) + "/reveal", userTok, nil, 403},
		{"user cannot read audit", http.MethodGet, "/api/audit", userTok, nil, 403},
		{"user cannot list users", http.MethodGet, "/api/users", userTok, nil, 403},
		// auditor: reads audit + inventory, nothing else
		{"auditor reads audit", http.MethodGet, "/api/audit", auditorTok, nil, 200},
		{"auditor reads targets", http.MethodGet, "/api/targets", auditorTok, nil, 200},
		{"auditor cannot create target", http.MethodPost, "/api/targets", auditorTok, newTarget, 403},
		{"auditor cannot reveal", http.MethodPost, "/api/credentials/" + itoa(credID) + "/reveal", auditorTok, nil, 403},
		// approver: reads audit + inventory, cannot manage or reveal
		{"approver reads audit", http.MethodGet, "/api/audit", approverTok, nil, 200},
		{"approver cannot create target", http.MethodPost, "/api/targets", approverTok, newTarget, 403},
		{"approver cannot reveal", http.MethodPost, "/api/credentials/" + itoa(credID) + "/reveal", approverTok, nil, 403},
		// admin (bootstrap): everything
		{"admin reveals", http.MethodPost, "/api/credentials/" + itoa(credID) + "/reveal", testAPIKey, nil, 200},
		{"admin reads audit", http.MethodGet, "/api/audit", testAPIKey, nil, 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, body := do(t, srv, c.method, c.path, c.key, c.body)
			if status != c.want {
				t.Fatalf("%s: status %d, want %d (%s)", c.name, status, c.want, body)
			}
		})
	}
}

// fakeAuthenticator stands in for the AD/LDAP password authenticator.
type fakeAuthenticator struct {
	username, password string
	role               auth.Role
}

func (f fakeAuthenticator) Authenticate(_ context.Context, u, p string) (*auth.Principal, error) {
	if u == f.username && p == f.password {
		return &auth.Principal{Name: u, Role: f.role}, nil
	}
	return nil, auth.ErrUnauthorized
}

func TestLoginSession(t *testing.T) {
	srv, _ := newTestServerAuthn(t, fakeAuthenticator{username: "ad-alice", password: "pw", role: auth.RoleUser})

	// Wrong password is rejected.
	if status, _ := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{
		"username": "ad-alice", "password": "nope",
	}); status != http.StatusUnauthorized {
		t.Fatalf("bad login: status %d, want 401", status)
	}

	// Successful login returns a session token.
	status, data := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{
		"username": "ad-alice", "password": "pw",
	})
	if status != http.StatusCreated {
		t.Fatalf("login: status %d body %s", status, data)
	}
	m := jsonMap(t, data)
	token, _ := m["token"].(string)
	if token == "" || m["role"] != "user" {
		t.Fatalf("unexpected login response: %s", data)
	}

	// The session token authenticates like any identity and carries the role:
	// a user may read the inventory but not manage it.
	if status, _ := do(t, srv, http.MethodGet, "/api/targets", token, nil); status != http.StatusOK {
		t.Fatalf("session token should read targets: %d", status)
	}
	if status, _ := do(t, srv, http.MethodPost, "/api/targets", token, map[string]any{
		"name": "x", "host": "h", "os_type": "linux", "protocol": "ssh",
	}); status != http.StatusForbidden {
		t.Fatalf("user session should not manage targets: %d", status)
	}

	// Logout revokes it.
	if status, _ := do(t, srv, http.MethodPost, "/api/logout", token, nil); status != http.StatusNoContent {
		t.Fatalf("logout: %d", status)
	}
	if status, _ := do(t, srv, http.MethodGet, "/api/targets", token, nil); status != http.StatusUnauthorized {
		t.Fatalf("revoked session should be 401, got %d", status)
	}
}

func TestLoginNotConfigured(t *testing.T) {
	srv := newTestServer(t) // no authenticator
	if status, _ := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{
		"username": "x", "password": "y",
	}); status != http.StatusServiceUnavailable {
		t.Fatalf("login without authenticator: status %d, want 503", status)
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
