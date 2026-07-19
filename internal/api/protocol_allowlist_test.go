package api_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestProtocolAllowlist verifies that, with an allowlist, disallowed protocols
// cannot be created and pre-existing disallowed targets cannot be connected to.
func TestProtocolAllowlist(t *testing.T) {
	fake := &fakeWinRM{}
	srv, st := newTestServerOpts(t, nil, api.Options{
		WinRM:            fake,
		AllowedProtocols: []string{"ssh"},
	})

	// Creating an allowed protocol works; disallowed ones are rejected (422).
	if status, _ := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "lnx", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	}); status != http.StatusCreated {
		t.Fatalf("create ssh: want 201, got %d", status)
	}
	for _, proto := range []string{"winrm", "rdp"} {
		if status, _ := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
			"name": "t-" + proto, "host": "10.0.0.6", "port": 5986, "os_type": "windows", "protocol": proto,
		}); status != http.StatusUnprocessableEntity {
			t.Fatalf("create %s: want 422, got %d", proto, status)
		}
	}

	// A winrm target that predates the policy (injected via the store) can no
	// longer be connected to.
	ctx := context.Background()
	win := &store.Target{Name: "legacy-win", Host: "10.0.0.7", Port: 5986, OSType: "windows", Protocol: "winrm"}
	if err := st.CreateTarget(ctx, win); err != nil {
		t.Fatal(err)
	}
	status, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/winrm", win.ID), testAPIKey, map[string]any{"command": "whoami"})
	if status != http.StatusForbidden {
		t.Fatalf("connect to disallowed winrm target: want 403, got %d", status)
	}
}
