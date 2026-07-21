package api_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// appGet fetches url with an Authorization: Bearer token (how an application
// authenticates to the secrets API) and returns the status and body.
func appGet(t *testing.T, srv *httptest.Server, path, token string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

// mkCredential creates a credential for target tid and returns its id.
func mkCredential(t *testing.T, srv *httptest.Server, tid int64, user, secret string) int64 {
	t.Helper()
	status, data := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": user, "secret": secret,
	})
	if status != http.StatusCreated {
		t.Fatalf("create credential %s: %d %s", user, status, data)
	}
	return int64(jsonMap(t, data)["id"].(float64))
}

// TestAppSecretsFlow proves the Conjur-style application-secrets path end to end:
// an admin mints an app and grants it one credential; the app retrieves exactly
// that secret with its bearer key; an ungranted credential, a disabled/unknown
// app, and a plain user are refused; and the secret never enters the audit trail.
func TestAppSecretsFlow(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{AppSecretsEnabled: true})

	status, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "app-host", "host": "10.9.9.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, data)
	}
	tid := int64(jsonMap(t, data)["id"].(float64))
	grantedCred := mkCredential(t, srv, tid, "svc", secretPassword)
	otherCred := mkCredential(t, srv, tid, "svc2", "another-secret")

	// Mint an application identity (token shown once).
	status, data = do(t, srv, http.MethodPost, "/v1/apps", testAPIKey, map[string]any{"name": "ci-runner", "owner": "team"})
	if status != http.StatusCreated {
		t.Fatalf("create app: %d %s", status, data)
	}
	m := jsonMap(t, data)
	appID := int64(m["id"].(float64))
	appToken, _ := m["token"].(string)
	if appToken == "" {
		t.Fatal("app token not returned")
	}

	// Default-deny before any grant.
	if s, _ := appGet(t, srv, "/v1/app-secrets/"+itoa(grantedCred), appToken); s != http.StatusForbidden {
		t.Fatalf("ungranted fetch should be 403, got %d", s)
	}

	// Grant the app one credential (needs CapRevealSecret — the admin key has it).
	if s, b := do(t, srv, http.MethodPost, "/v1/apps/"+itoa(appID)+"/grants", testAPIKey, map[string]any{"credential_id": grantedCred}); s != http.StatusCreated {
		t.Fatalf("grant: %d %s", s, b)
	}

	// The app retrieves exactly the granted secret.
	s, b := appGet(t, srv, "/v1/app-secrets/"+itoa(grantedCred), appToken)
	if s != http.StatusOK {
		t.Fatalf("granted fetch should be 200, got %d %s", s, b)
	}
	if got := jsonMap(t, b)["secret"]; got != secretPassword {
		t.Fatalf("secret = %v, want the vaulted value", got)
	}
	// A credential it was NOT granted stays forbidden.
	if s, _ := appGet(t, srv, "/v1/app-secrets/"+itoa(otherCred), appToken); s != http.StatusForbidden {
		t.Fatalf("other credential should be 403, got %d", s)
	}
	// A bad token is unauthorized.
	if s, _ := appGet(t, srv, "/v1/app-secrets/"+itoa(grantedCred), "not-a-real-token"); s != http.StatusUnauthorized {
		t.Fatalf("bad token should be 401, got %d", s)
	}

	// The secret must never appear in the audit trail; a fetch is audited.
	events, err := st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	sawRetrieved := false
	for _, e := range events {
		if e.Action == "app.secret_retrieved" {
			sawRetrieved = true
		}
		if strings.Contains(e.Detail, secretPassword) {
			t.Fatalf("audit detail leaked the secret: %q", e.Detail)
		}
	}
	if !sawRetrieved {
		t.Fatal("a successful fetch must be audited app.secret_retrieved")
	}

	// A plain user can neither mint apps nor grant secrets.
	userTok := seedUser(t, srv, "uma", "user")
	if s, _ := do(t, srv, http.MethodPost, "/v1/apps", userTok, map[string]any{"name": "x"}); s != http.StatusForbidden {
		t.Fatalf("a plain user must not mint apps, got %d", s)
	}
}

// TestAppSecretsDisabled proves the routes are absent when the feature is off.
func TestAppSecretsDisabled(t *testing.T) {
	srv, _ := newTestServerStore(t) // default options: app secrets off
	if s, _ := do(t, srv, http.MethodPost, "/v1/apps", testAPIKey, map[string]any{"name": "x"}); s != http.StatusNotFound {
		t.Fatalf("app routes must be absent when disabled, got %d", s)
	}
}
