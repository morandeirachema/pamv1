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
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/mfa"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
	"github.com/morandeirachema/pamv1/internal/winrm"
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
	return newTestServerOpts(t, authn, api.Options{})
}

// newTestServerOpts builds a server with a password authenticator and options.
func newTestServerOpts(t *testing.T, authn auth.Authenticator, opts api.Options) (*httptest.Server, store.Store) {
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
	resolver.WithProfiles(st) // Phase 12: resolve custom profiles, as main.go does
	handler, err := api.New(st, v, resolver, authn, opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, st
}

// newTestServer returns a running server with the default (no-authenticator) options.
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

// do issues an HTTP request with an optional X-API-Key and JSON body, returning
// the response status and raw body.
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

// jsonMap unmarshals a JSON object body into a map, failing the test on error.
func jsonMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal %q: %v", data, err)
	}
	return m
}

// TestHealthzIsOpen verifies the liveness probe requires no authentication.
func TestHealthzIsOpen(t *testing.T) {
	srv := newTestServer(t)
	status, _ := do(t, srv, http.MethodGet, "/healthz", "", nil)
	if status != http.StatusOK {
		t.Fatalf("healthz status = %d", status)
	}
}

// TestAuthRequired verifies API endpoints reject a missing or wrong key with 401.
func TestAuthRequired(t *testing.T) {
	srv := newTestServer(t)
	for _, key := range []string{"", "wrong-key"} {
		status, _ := do(t, srv, http.MethodGet, "/api/targets", key, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("key %q: status = %d, want 401", key, status)
		}
	}
}

// TestFullFlow exercises the target -> credential -> reveal -> audit -> delete
// happy path, and confirms secrets never leak in create/list responses and that
// credentials cascade when their target is deleted.
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

// TestBreakGlass verifies the break-glass key authenticates and every use is audited.
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

// TestValidationAndConflicts covers input validation (bad os_type) and the
// duplicate-name conflict on target creation.
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

// TestRBAC checks each role's capability matrix across the management, reveal,
// audit and users endpoints.
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

// Authenticate returns the configured principal when the credentials match, else
// ErrUnauthorized.
func (f fakeAuthenticator) Authenticate(_ context.Context, u, p string) (*auth.Principal, error) {
	if u == f.username && p == f.password {
		return &auth.Principal{Name: u, Role: f.role}, nil
	}
	return nil, auth.ErrUnauthorized
}

// TestLoginSession verifies password login issues a role-scoped session token
// that authenticates like any identity and can be revoked by logout.
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

// TestMFAEnrollmentAndLogin walks enrollment, then proves login requires a valid
// OTP once MFA is confirmed (and rejects a wrong code).
func TestMFAEnrollmentAndLogin(t *testing.T) {
	srv, _ := newTestServerAuthn(t, fakeAuthenticator{username: "ad-alice", password: "pw", role: auth.RoleUser})

	// 1. First login (no MFA yet) → session token.
	_, data := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw"})
	sessTok, _ := jsonMap(t, data)["token"].(string)
	if sessTok == "" {
		t.Fatalf("no session token: %s", data)
	}

	// 2. Enroll MFA with that session; get the secret.
	status, data := do(t, srv, http.MethodPost, "/api/mfa/enroll", sessTok, nil)
	if status != http.StatusCreated {
		t.Fatalf("enroll: %d %s", status, data)
	}
	secret, _ := jsonMap(t, data)["secret"].(string)
	if secret == "" {
		t.Fatalf("no secret returned: %s", data)
	}

	// 3. Confirm enrollment with a valid code.
	code, err := mfa.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if status, data := do(t, srv, http.MethodPost, "/api/mfa/verify", sessTok, map[string]any{"otp": code}); status != http.StatusOK {
		t.Fatalf("verify: %d %s", status, data)
	}

	// 4. Now login WITHOUT an OTP must be refused with mfa_required.
	status, data = do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw"})
	if status != http.StatusUnauthorized || jsonMap(t, data)["mfa_required"] != true {
		t.Fatalf("login without OTP should require MFA: %d %s", status, data)
	}

	// 5. Login WITH a valid OTP succeeds.
	code, _ = mfa.Code(secret, time.Now())
	status, data = do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw", "otp": code})
	if status != http.StatusCreated {
		t.Fatalf("login with OTP should succeed: %d %s", status, data)
	}

	// 6. Wrong OTP is rejected.
	if status, _ := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw", "otp": "000000"}); status != http.StatusUnauthorized {
		t.Fatalf("login with wrong OTP should fail: %d", status)
	}
}

// enrollMFA enrolls and confirms MFA for the given session token, returning the
// TOTP secret.
func enrollMFA(t *testing.T, srv *httptest.Server, sessTok string) string {
	t.Helper()
	status, data := do(t, srv, http.MethodPost, "/api/mfa/enroll", sessTok, nil)
	if status != http.StatusCreated {
		t.Fatalf("enroll: %d %s", status, data)
	}
	secret, _ := jsonMap(t, data)["secret"].(string)
	code, _ := mfa.Code(secret, time.Now())
	if status, data := do(t, srv, http.MethodPost, "/api/mfa/verify", sessTok, map[string]any{"otp": code}); status != http.StatusOK {
		t.Fatalf("verify: %d %s", status, data)
	}
	return secret
}

// TestEnforceMFAPolicy verifies that with MFARequired an un-enrolled user gets an
// enrollment-only session (blocked from everything else) and gains full access
// only after enrolling and presenting an OTP.
func TestEnforceMFAPolicy(t *testing.T) {
	srv, _ := newTestServerOpts(t,
		fakeAuthenticator{username: "ad-alice", password: "pw", role: auth.RoleUser},
		api.Options{MFARequired: true})

	// 1. First login with no MFA → enrollment-only session (200, flagged).
	status, data := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw"})
	if status != http.StatusOK || jsonMap(t, data)["mfa_enrollment_required"] != true {
		t.Fatalf("expected enrollment-required session: %d %s", status, data)
	}
	enrollTok, _ := jsonMap(t, data)["token"].(string)

	// 2. The enrollment-only session cannot do anything else.
	if st, _ := do(t, srv, http.MethodGet, "/api/targets", enrollTok, nil); st != http.StatusForbidden {
		t.Fatalf("enroll-only session must be blocked from /api/targets: %d", st)
	}

	// 3. Enroll + confirm using the enrollment session.
	secret := enrollMFA(t, srv, enrollTok)

	// 4. Re-login now demands the OTP, and succeeds with it → full session.
	if st, _ := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw"}); st != http.StatusUnauthorized {
		t.Fatalf("login should now require OTP: %d", st)
	}
	code, _ := mfa.Code(secret, time.Now())
	status, data = do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw", "otp": code})
	if status != http.StatusCreated {
		t.Fatalf("login with OTP should succeed: %d %s", status, data)
	}
	fullTok, _ := jsonMap(t, data)["token"].(string)
	if st, _ := do(t, srv, http.MethodGet, "/api/targets", fullTok, nil); st != http.StatusOK {
		t.Fatalf("full session should access /api/targets: %d", st)
	}
}

// TestRecoveryCodes verifies a recovery code can stand in for the OTP once and is
// then single-use.
func TestRecoveryCodes(t *testing.T) {
	srv, _ := newTestServerAuthn(t, fakeAuthenticator{username: "ad-alice", password: "pw", role: auth.RoleUser})

	// Get a session, enroll+confirm MFA.
	_, data := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw"})
	sessTok, _ := jsonMap(t, data)["token"].(string)
	enrollMFA(t, srv, sessTok)

	// Generate recovery codes.
	status, data := do(t, srv, http.MethodPost, "/api/mfa/recovery-codes", sessTok, nil)
	if status != http.StatusCreated {
		t.Fatalf("recovery-codes: %d %s", status, data)
	}
	codesRaw, _ := jsonMap(t, data)["recovery_codes"].([]any)
	if len(codesRaw) != 10 {
		t.Fatalf("want 10 recovery codes, got %d", len(codesRaw))
	}
	recovery := codesRaw[0].(string)

	// Log in using a recovery code in place of the OTP.
	status, _ = do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw", "otp": recovery})
	if status != http.StatusCreated {
		t.Fatalf("login with recovery code should succeed: %d", status)
	}
	// The same recovery code is single-use — a second attempt fails.
	status, _ = do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw", "otp": recovery})
	if status != http.StatusUnauthorized {
		t.Fatalf("reused recovery code should fail: %d", status)
	}
}

// TestTargetGrantsEnforcement verifies per-target grants gate access: open with
// no grants, denied when granted only to others, allowed by a user or role grant,
// plus grant listing and role validation.
func TestTargetGrantsEnforcement(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\n"}}
	srv, _ := newTestServerOpts(t, nil, api.Options{WinRM: fake})

	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win", "host": "h", "port": 5986, "os_type": "windows", "protocol": "winrm",
	})
	tid := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "Administrator", "secret": "s",
	})
	aliceTok := seedUser(t, srv, "alice", "user")
	winrmPath := "/api/targets/" + itoa(tid) + "/winrm"
	runBody := map[string]any{"command": "whoami"}

	// No grants → open: alice can run.
	if status, _ := do(t, srv, http.MethodPost, winrmPath, aliceTok, runBody); status != http.StatusOK {
		t.Fatalf("no grants should be open: %d", status)
	}

	// Grant to someone else → alice is denied.
	status, data := do(t, srv, http.MethodPost, "/api/targets/"+itoa(tid)+"/grants", testAPIKey,
		map[string]any{"subject_type": "user", "subject": "bob"})
	if status != http.StatusCreated {
		t.Fatalf("create grant: %d %s", status, data)
	}
	if status, _ := do(t, srv, http.MethodPost, winrmPath, aliceTok, runBody); status != http.StatusForbidden {
		t.Fatalf("ungranted user should be 403: %d", status)
	}

	// Grant alice's role → allowed again.
	do(t, srv, http.MethodPost, "/api/targets/"+itoa(tid)+"/grants", testAPIKey,
		map[string]any{"subject_type": "role", "subject": "user"})
	if status, _ := do(t, srv, http.MethodPost, winrmPath, aliceTok, runBody); status != http.StatusOK {
		t.Fatalf("granted role should run: %d", status)
	}

	// List shows two grants; validation rejects a bad role.
	if status, data := do(t, srv, http.MethodGet, "/api/targets/"+itoa(tid)+"/grants", testAPIKey, nil); status != http.StatusOK || strings.Count(string(data), "subject") < 2 {
		t.Fatalf("list grants: %d %s", status, data)
	}
	if status, _ := do(t, srv, http.MethodPost, "/api/targets/"+itoa(tid)+"/grants", testAPIKey,
		map[string]any{"subject_type": "role", "subject": "wizard"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("invalid role grant should be 422: %d", status)
	}
}

// TestLiveSessionsAndKill verifies auditors can list live sessions, only admins
// can kill them (invoking the registered kill func), and an unknown id is a 404.
func TestLiveSessionsAndKill(t *testing.T) {
	reg := session.NewRegistry()
	srv, _ := newTestServerOpts(t, nil, api.Options{Sessions: reg})

	killed := false
	id := reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() { killed = true })

	// Auditor may list live sessions.
	auditorTok := seedUser(t, srv, "theo", "auditor")
	status, data := do(t, srv, http.MethodGet, "/api/sessions", auditorTok, nil)
	if status != http.StatusOK || !strings.Contains(string(data), "web-01") {
		t.Fatalf("list sessions: %d %s", status, data)
	}

	// A plain user cannot kill.
	userTok := seedUser(t, srv, "alice", "user")
	if status, _ := do(t, srv, http.MethodDelete, "/api/sessions/"+id, userTok, nil); status != http.StatusForbidden {
		t.Fatalf("user kill should be 403: %d", status)
	}

	// Admin kills the session.
	if status, _ := do(t, srv, http.MethodDelete, "/api/sessions/"+id, testAPIKey, nil); status != http.StatusNoContent {
		t.Fatalf("admin kill: %d", status)
	}
	if !killed {
		t.Fatal("kill func not invoked")
	}
	// Killing an unknown id is a 404.
	if status, _ := do(t, srv, http.MethodDelete, "/api/sessions/nope", testAPIKey, nil); status != http.StatusNotFound {
		t.Fatalf("kill unknown: %d, want 404", status)
	}
}

// TestRevealDisabledByPolicy verifies reveal is refused under policy for a normal
// admin but still permitted for break-glass.
func TestRevealDisabledByPolicy(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{RevealDisabled: true})
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "t", "host": "h", "os_type": "linux", "protocol": "ssh",
	})
	tid := int64(jsonMap(t, data)["id"].(float64))
	_, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "root", "secret": secretPassword,
	})
	cid := int64(jsonMap(t, data)["id"].(float64))

	// Admin reveal is refused under the policy...
	if status, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(cid)+"/reveal", testAPIKey, nil); status != http.StatusForbidden {
		t.Fatalf("admin reveal under policy: %d, want 403", status)
	}
	// ...but break-glass may still reveal in an emergency.
	if status, _ := do(t, srv, http.MethodPost, "/api/credentials/"+itoa(cid)+"/reveal", breakGlassKey, nil); status != http.StatusOK {
		t.Fatalf("break-glass reveal under policy: %d, want 200", status)
	}
}

// TestSecurityHeaders verifies the baseline hardening headers are set on responses.
func TestSecurityHeaders(t *testing.T) {
	srv := newTestServer(t)
	_, _ = do(t, srv, http.MethodGet, "/healthz", "", nil)
	// Fetch headers via a raw request.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/healthz", nil)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for k, v := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Error("missing HSTS header")
	}
}

// TestAuthRateLimit verifies the per-IP limiter blocks login attempts past the
// configured per-minute budget with 429.
func TestAuthRateLimit(t *testing.T) {
	srv, _ := newTestServerOpts(t,
		fakeAuthenticator{username: "u", password: "p", role: auth.RoleUser},
		api.Options{AuthRatePerMin: 3})

	// 3 attempts allowed (wrong creds → 401), the 4th is rate-limited (429).
	for i := 0; i < 3; i++ {
		if status, _ := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{
			"username": "u", "password": "wrong",
		}); status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i+1, status)
		}
	}
	if status, _ := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{
		"username": "u", "password": "wrong",
	}); status != http.StatusTooManyRequests {
		t.Fatalf("4th attempt: status %d, want 429", status)
	}
}

// TestLoginNotConfigured verifies login returns 503 when no password
// authenticator is wired.
func TestLoginNotConfigured(t *testing.T) {
	srv := newTestServer(t) // no authenticator
	if status, _ := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{
		"username": "x", "password": "y",
	}); status != http.StatusServiceUnavailable {
		t.Fatalf("login without authenticator: status %d, want 503", status)
	}
}

// fakeWinRM records what it was asked to run and returns a canned result.
type fakeWinRM struct {
	gotHost, gotUser, gotPass, gotCmd string
	gotPort                           int
	result                            winrm.Result
	err                               error
}

// Run records the dial parameters and command, then returns the canned result/error.
func (f *fakeWinRM) Run(_ context.Context, host string, port int, user, password, command string) (winrm.Result, error) {
	f.gotHost, f.gotPort, f.gotUser, f.gotPass, f.gotCmd = host, port, user, password, command
	return f.result, f.err
}

// TestWinRMRun proves JIT injection: the vaulted secret and username reach the
// runner (never the client), the run is audited, and a transcript is recorded.
func TestWinRMRun(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "contoso\\Administrator\r\n", ExitCode: 0}}
	recDir := t.TempDir()
	srv, _ := newTestServerOpts(t, nil, api.Options{WinRM: fake, RecordingDir: recDir})

	// Seed a Windows/WinRM target + credential (as admin).
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-01", "host": "10.0.0.5", "port": 5986, "os_type": "windows", "protocol": "winrm",
	})
	targetID := int64(jsonMap(t, data)["id"].(float64))
	if _, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": targetID, "username": "Administrator", "secret": "Win-S3cret!",
	}); d == nil {
		t.Fatal("seed credential failed")
	}

	// Run a command through the proxy path (admin has CapConnect).
	status, data := do(t, srv, http.MethodPost, "/api/targets/"+itoa(targetID)+"/winrm", testAPIKey,
		map[string]any{"command": "whoami"})
	if status != http.StatusOK {
		t.Fatalf("winrm run: %d %s", status, data)
	}
	m := jsonMap(t, data)
	if m["stdout"] != "contoso\\Administrator\r\n" || m["exit_code"].(float64) != 0 {
		t.Fatalf("unexpected result: %s", data)
	}

	// JIT injection proof: the vaulted secret + username reached the runner,
	// and the client never possessed them.
	if fake.gotPass != "Win-S3cret!" || fake.gotUser != "Administrator" {
		t.Fatalf("credential not injected: user=%q pass=%q", fake.gotUser, fake.gotPass)
	}
	if fake.gotHost != "10.0.0.5" || fake.gotPort != 5986 || fake.gotCmd != "whoami" {
		t.Fatalf("wrong dial params: %+v", fake)
	}

	// Audited, and a transcript was recorded.
	if status, data := do(t, srv, http.MethodGet, "/api/audit", testAPIKey, nil); status != http.StatusOK ||
		!strings.Contains(string(data), "winrm.run") {
		t.Fatalf("winrm run must be audited: %s", data)
	}
	entries, _ := os.ReadDir(recDir)
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".winrm.log") {
		t.Fatalf("expected one transcript, got %v", entries)
	}
}

// TestWinRMRejectsNonWindowsTarget verifies a WinRM run against a non-WinRM
// target is rejected with 422.
func TestWinRMRejectsNonWindowsTarget(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{WinRM: &fakeWinRM{}})
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "lnx", "host": "h", "os_type": "linux", "protocol": "ssh",
	})
	id := int64(jsonMap(t, data)["id"].(float64))
	if status, _ := do(t, srv, http.MethodPost, "/api/targets/"+itoa(id)+"/winrm", testAPIKey,
		map[string]any{"command": "whoami"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("winrm on ssh target should be 422, got %d", status)
	}
}

// TestWinRMRequiresConnectCapability verifies a role without CapConnect (auditor)
// cannot run WinRM commands.
func TestWinRMRequiresConnectCapability(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{WinRM: &fakeWinRM{}})
	auditorTok := seedUser(t, srv, "theo", "auditor")
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-02", "host": "h", "port": 5986, "os_type": "windows", "protocol": "winrm",
	})
	id := int64(jsonMap(t, data)["id"].(float64))
	if status, _ := do(t, srv, http.MethodPost, "/api/targets/"+itoa(id)+"/winrm", auditorTok,
		map[string]any{"command": "whoami"}); status != http.StatusForbidden {
		t.Fatalf("auditor should not run winrm, got %d", status)
	}
}

// itoa formats an int64 as a decimal string.
func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
