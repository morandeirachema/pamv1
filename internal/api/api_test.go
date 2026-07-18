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
	handler, err := api.New(st, v, resolver, authn, opts)
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

// enrollAndConfirmMFA logs in, enrolls MFA and confirms it, returning the
// TOTP secret and a full (post-enrollment) session token.
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

func (f *fakeWinRM) Run(_ context.Context, host string, port int, user, password, command string) (winrm.Result, error) {
	f.gotHost, f.gotPort, f.gotUser, f.gotPass, f.gotCmd = host, port, user, password, command
	return f.result, f.err
}

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

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
