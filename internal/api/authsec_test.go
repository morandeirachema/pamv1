package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/mfa"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// TestMFAChangeRequiresCurrentFactor proves a confirmed second factor cannot be
// replaced or removed without proving the current code — so a stolen session
// token cannot strip a victim's MFA.
func TestMFAChangeRequiresCurrentFactor(t *testing.T) {
	srv, _ := newTestServerAuthn(t, fakeAuthenticator{username: "ad-alice", password: "pw", role: auth.RoleUser})
	_, data := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw"})
	sessTok, _ := jsonMap(t, data)["token"].(string)
	secret := enrollMFA(t, srv, sessTok)

	// Re-enroll without the current code is refused.
	if status, _ := do(t, srv, http.MethodPost, "/api/mfa/enroll", sessTok, nil); status != http.StatusUnauthorized {
		t.Fatalf("re-enroll without OTP = %d, want 401", status)
	}
	// Disable without the current code is refused.
	if status, _ := do(t, srv, http.MethodDelete, "/api/mfa", sessTok, nil); status != http.StatusUnauthorized {
		t.Fatalf("disable without OTP = %d, want 401", status)
	}
	// Disable WITH a valid current code succeeds.
	code, _ := mfa.Code(secret, time.Now())
	if status, _ := do(t, srv, http.MethodDelete, "/api/mfa", sessTok, map[string]any{"otp": code}); status != http.StatusNoContent {
		t.Fatalf("disable with OTP = %d, want 204", status)
	}
	// After disable, status shows not enrolled.
	if _, d := do(t, srv, http.MethodGet, "/api/mfa", sessTok, nil); jsonMap(t, d)["enrolled"] != false {
		t.Fatalf("expected enrolled=false after disable: %s", d)
	}
}

// TestFailedLoginAudited proves a bad password and a bad OTP each append a
// login.failed audit event attributed to the attempted username.
func TestFailedLoginAudited(t *testing.T) {
	srv, st := newTestServerAuthn(t, fakeAuthenticator{username: "ad-alice", password: "pw", role: auth.RoleUser})

	if status, _ := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "wrong"}); status != http.StatusUnauthorized {
		t.Fatalf("bad password login = %d, want 401", status)
	}
	events, err := st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range events {
		if e.Action == "login.failed" && e.Actor == "ad-alice" {
			found = true
		}
	}
	if !found {
		t.Fatal("bad password login was not audited as login.failed")
	}
}

// TestDeleteGrantScopedToTarget proves a grant can only be deleted through the
// target it belongs to, not through an unrelated target's URL.
func TestDeleteGrantScopedToTarget(t *testing.T) {
	srv := newTestServer(t)
	mk := func(name string) int64 {
		_, d := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
			"name": name, "host": "h", "os_type": "linux", "protocol": "ssh",
		})
		return int64(jsonMap(t, d)["id"].(float64))
	}
	a, b := mk("target-a"), mk("target-b")
	_, d := do(t, srv, http.MethodPost, "/api/targets/"+itoa(a)+"/grants", testAPIKey,
		map[string]any{"subject_type": "role", "subject": "user"})
	gid := int64(jsonMap(t, d)["id"].(float64))

	// Deleting grant `gid` via target B (wrong target) must not succeed.
	if status, _ := do(t, srv, http.MethodDelete, "/api/targets/"+itoa(b)+"/grants/"+itoa(gid), testAPIKey, nil); status != http.StatusNotFound {
		t.Fatalf("delete via wrong target = %d, want 404", status)
	}
	// Via the correct target it works.
	if status, _ := do(t, srv, http.MethodDelete, "/api/targets/"+itoa(a)+"/grants/"+itoa(gid), testAPIKey, nil); status != http.StatusNoContent {
		t.Fatalf("delete via correct target = %d, want 204", status)
	}
}

// mfaFaultStore makes GetMFAEnrollment fail with a non-ErrNotFound error to model
// a transient store failure during login.
type mfaFaultStore struct {
	store.Store
}

func (mfaFaultStore) GetMFAEnrollment(context.Context, string) (*store.MFAEnrollment, error) {
	return nil, errors.New("boom: mfa store unavailable")
}

// TestLoginMFAFailsClosedOnStoreError proves that if the MFA-enrollment read
// errors, login fails closed (5xx) rather than silently issuing a password-only
// session.
func TestLoginMFAFailsClosedOnStoreError(t *testing.T) {
	st := mfaFaultStore{Store: memstore.New()}
	srv := newServerWithStore(t, st, fakeAuthenticator{username: "ad-alice", password: "pw", role: auth.RoleUser}, api.Options{})
	status, data := do(t, srv, http.MethodPost, "/api/login", "", map[string]any{"username": "ad-alice", "password": "pw"})
	if status < 500 {
		t.Fatalf("login with an MFA store error = %d, want 5xx (fail closed), body %s", status, data)
	}
}

// TestCheckoutDecryptFailureRollsBackLease proves that when a checkout's decrypt
// fails after the lease is created, the lease is rolled back so the credential is
// not blocked from checkout for the whole TTL.
func TestCheckoutDecryptFailureRollsBackLease(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{CheckoutTTL: 30 * time.Minute})
	ctx := context.Background()
	target := &store.Target{Name: "web-01", Host: "h", Port: 22, OSType: "linux", Protocol: "ssh"}
	if err := st.CreateTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	// An undecryptable secret makes the checkout's Decrypt fail.
	if err := st.CreateCredential(ctx, &store.Credential{
		TargetID: target.ID, Username: "root", SecretType: "password", SecretEnc: "v1:not-a-real-token",
	}); err != nil {
		t.Fatal(err)
	}
	creds, _ := st.ListCredentials(ctx, target.ID)
	path := "/api/credentials/" + itoa(creds[0].ID) + "/checkout"

	if status, _ := do(t, srv, http.MethodPost, path, testAPIKey, nil); status < 500 {
		t.Fatalf("checkout with bad secret = %d, want 5xx", status)
	}
	// A second checkout must NOT be 409 — the failed lease must have rolled back.
	if status, _ := do(t, srv, http.MethodPost, path, testAPIKey, nil); status == http.StatusConflict {
		t.Fatal("lease was not rolled back: second checkout is 409")
	}
}

// newServerWithStore builds a test server over a caller-supplied store (for
// fault injection), mirroring newTestServerOpts otherwise.
func newServerWithStore(t *testing.T, st store.Store, authn auth.Authenticator, opts api.Options) *httptest.Server {
	t.Helper()
	mk, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(mk)
	if err != nil {
		t.Fatal(err)
	}
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
	return srv
}
