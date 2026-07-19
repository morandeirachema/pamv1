package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/store"
)

// fakeConnector models a real SSH/WinRM target's password state. Rotate sets the
// on-target password (and records it so the test can prove the vault ends up
// holding exactly that); Verify succeeds only when the presented secret matches
// the on-target password. Out-of-band drift is simulated with setActual.
type fakeConnector struct {
	mu      sync.Mutex
	actual  string // password currently on the target ("" = accept any)
	lastNew string
}

// Rotate sets the on-target password to newSecret and records it.
func (f *fakeConnector) Rotate(_ context.Context, _ store.Target, _, _, newSecret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actual = newSecret
	f.lastNew = newSecret
	return nil
}

// Verify succeeds only when secret matches the current on-target password (and
// accepts any secret when none has been set).
func (f *fakeConnector) Verify(_ context.Context, _ store.Target, _, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.actual != "" && secret != f.actual {
		return fmt.Errorf("authentication failed")
	}
	return nil
}

// setActual simulates an out-of-band password change on the target.
func (f *fakeConnector) setActual(pw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actual = pw
}

// newSecret returns the last password Rotate was asked to set.
func (f *fakeConnector) newSecret() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastNew
}

// seedTargetCred creates a target and one credential of the given protocol and
// secret (and optional secret type), returning the credential id.
func seedTargetCred(t *testing.T, srv *httptest.Server, protocol, secretType, secret string) int64 {
	t.Helper()
	status, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "t-" + secret, "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": protocol,
	})
	if status != http.StatusCreated {
		t.Fatalf("seed target: %d %s", status, data)
	}
	targetID := int64(jsonMap(t, data)["id"].(float64))
	body := map[string]any{"target_id": targetID, "username": "root", "secret": secret}
	if secretType != "" {
		body["secret_type"] = secretType
	}
	status, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, body)
	if status != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", status, data)
	}
	return int64(jsonMap(t, data)["id"].(float64))
}

// TestCredentialRotation verifies rotation sets a new secret on the target,
// re-vaults exactly that secret without leaking it, and stamps rotated_at.
func TestCredentialRotation(t *testing.T) {
	fc := &fakeConnector{}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")

	status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", credID), testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("rotate: %d %s", status, data)
	}
	m := jsonMap(t, data)
	if m["rotated"] != true {
		t.Fatalf("rotated flag not set: %s", data)
	}
	if _, leaked := m["secret"]; leaked {
		t.Fatal("rotate response leaked the secret")
	}
	if fc.newSecret() == "" {
		t.Fatal("connector was never asked to set a new secret")
	}

	// The vault must now hold exactly the password the target was set to.
	status, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", credID), testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("reveal: %d %s", status, data)
	}
	revealed := jsonMap(t, data)["secret"].(string)
	if revealed != fc.newSecret() {
		t.Fatalf("vault holds %q, target was set to %q", revealed, fc.newSecret())
	}
	if revealed == "original-secret" {
		t.Fatal("secret was not actually rotated")
	}

	// rotated_at must be stamped.
	_, data = do(t, srv, http.MethodGet, "/api/credentials", testAPIKey, nil)
	var creds []map[string]any
	if err := json.Unmarshal(data, &creds); err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 || creds[0]["rotated_at"] == nil {
		t.Fatalf("rotated_at not set: %s", data)
	}
}

// TestRotationUnsupportedSecretType verifies rotating an ssh_key credential is
// rejected with 422.
func TestRotationUnsupportedSecretType(t *testing.T) {
	fc := &fakeConnector{}
	srv, _ := newTestServerOpts(t, nil, api.Options{Rotators: map[string]rotate.Rotator{"ssh": fc}})
	credID := seedTargetCred(t, srv, "ssh", "ssh_key", "KEYDATA")

	status, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", credID), testAPIKey, nil)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for ssh_key rotation, got %d", status)
	}
}

// TestReconcileInSyncAndDrift verifies reconcile reports in_sync, detects
// out-of-band drift, and that remediation brings vault and target back in sync.
func TestReconcileInSyncAndDrift(t *testing.T) {
	fc := &fakeConnector{}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")

	status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reconcile", credID), testAPIKey, nil)
	if status != http.StatusOK || jsonMap(t, data)["status"] != "in_sync" {
		t.Fatalf("expected in_sync: %d %s", status, data)
	}

	// Someone changed the password out of band: the vault is now stale.
	fc.setActual("changed-out-of-band")
	status, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reconcile", credID), testAPIKey, nil)
	if status != http.StatusOK || jsonMap(t, data)["status"] != "out_of_sync" {
		t.Fatalf("expected out_of_sync: %d %s", status, data)
	}

	// Remediate: rotate to a fresh PAM-managed secret, bringing target and vault
	// back in sync.
	status, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reconcile?remediate=true", credID), testAPIKey, nil)
	if status != http.StatusOK || jsonMap(t, data)["remediated"] != true {
		t.Fatalf("expected remediated: %d %s", status, data)
	}
	status, data = do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/reveal", credID), testAPIKey, nil)
	if status != http.StatusOK || jsonMap(t, data)["secret"].(string) != fc.newSecret() {
		t.Fatalf("vault not in sync after remediation: %s", data)
	}
}

// TestReconcileAllScan verifies the read-only scan reports the checked and
// out-of-sync counts.
func TestReconcileAllScan(t *testing.T) {
	fc := &fakeConnector{}
	srv, _ := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
	})
	seedTargetCred(t, srv, "ssh", "", "s1")

	status, data := do(t, srv, http.MethodGet, "/api/reconcile", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("reconcile scan: %d %s", status, data)
	}
	m := jsonMap(t, data)
	if m["checked"].(float64) != 1 || m["out_of_sync"].(float64) != 0 {
		t.Fatalf("unexpected scan result: %s", data)
	}
}
