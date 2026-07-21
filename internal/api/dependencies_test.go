package api_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/rotate"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestRotationPropagatesToDependency proves that rotating a credential updates a
// declared consumer (a Windows Service) over WinRM with the NEW secret, so the
// rotation does not break production.
func TestRotationPropagatesToDependency(t *testing.T) {
	fc := &fakeConnector{}
	fake := &fakeWinRM{result: winrm.Result{}}
	srv, st := newTestServerOpts(t, nil, api.Options{
		Rotators:  map[string]rotate.Rotator{"ssh": fc},
		Verifiers: map[string]rotate.Verifier{"ssh": fc},
		WinRM:     fake,
	})
	credID := seedTargetCred(t, srv, "ssh", "", "original-secret")

	// Declare a Windows Service that logs on with this credential.
	depURL := fmt.Sprintf("/api/credentials/%d/dependencies", credID)
	if code, body := do(t, srv, http.MethodPost, depURL, testAPIKey, map[string]any{
		"kind": "windows_service", "host": "app-01", "name": "MyService",
	}); code != http.StatusCreated {
		t.Fatalf("declare dependency: status %d body %s", code, body)
	}

	// Rotate the credential.
	if code, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/credentials/%d/rotate", credID), testAPIKey, nil); code != http.StatusOK {
		t.Fatalf("rotate: status %d body %s", code, data)
	}
	newSecret := fc.newSecret()
	if newSecret == "" {
		t.Fatal("rotation did not set a new secret")
	}

	// The consumer was updated over WinRM on its own host with the new secret.
	if fake.gotHost != "app-01" || fake.gotPort != 5985 {
		t.Fatalf("dependency WinRM target = %s:%d, want app-01:5985", fake.gotHost, fake.gotPort)
	}
	if !strings.Contains(fake.gotCmd, `sc.exe config "MyService"`) {
		t.Fatalf("dependency command = %q, want an sc.exe config for MyService", fake.gotCmd)
	}
	if !strings.Contains(fake.gotCmd, newSecret) {
		t.Fatal("the new secret was not injected into the dependency update")
	}

	// The propagation is audited (without the secret in the detail).
	events, err := st.ListAudit(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	var updated bool
	for _, e := range events {
		if e.Action == "credential.dependency_updated" && strings.Contains(e.Detail, "MyService@app-01") {
			updated = true
			if strings.Contains(e.Detail, newSecret) {
				t.Fatal("audit detail leaked the new secret")
			}
		}
	}
	if !updated {
		t.Fatal("no credential.dependency_updated audit event")
	}
}
