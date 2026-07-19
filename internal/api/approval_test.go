package api_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// seedApprovalTarget creates a WinRM target (optionally approval-gated) with a
// credential and returns its id.
func seedApprovalTarget(t *testing.T, srv *httptest.Server, requireApproval bool) int64 {
	t.Helper()
	status, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-ot", "host": "10.0.0.20", "port": 5986, "os_type": "windows",
		"protocol": "winrm", "require_approval": requireApproval,
	})
	if status != http.StatusCreated {
		t.Fatalf("create target: %d %s", status, data)
	}
	id := int64(jsonMap(t, data)["id"].(float64))
	status, data = do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": id, "username": "Administrator", "secret": "S3cret",
	})
	if status != http.StatusCreated {
		t.Fatalf("create credential: %d %s", status, data)
	}
	return id
}

// TestApprovalWorkflow exercises the full 4-eyes flow: blocked without approval,
// file a request, no self-approval, approval by a different principal unlocks the
// connect (with the credential injected), and a decided request cannot be redecided.
func TestApprovalWorkflow(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, _ := newTestServerOpts(t, nil, api.Options{WinRM: fake})
	targetID := seedApprovalTarget(t, srv, true)

	alice := seedUser(t, srv, "alice", "user") // connect-capable requester
	bob := seedUser(t, srv, "bob", "approver") // can approve, cannot connect
	run := fmt.Sprintf("/api/targets/%d/winrm", targetID)

	// Without an approval, a connect-capable user is blocked.
	if status, _ := do(t, srv, http.MethodPost, run, alice, map[string]any{"command": "whoami"}); status != http.StatusForbidden {
		t.Fatalf("connect without approval: want 403, got %d", status)
	}

	// Alice files an access request.
	status, data := do(t, srv, http.MethodPost, "/api/access-requests", alice, map[string]any{
		"target_id": targetID, "reason": "patch window",
	})
	if status != http.StatusCreated {
		t.Fatalf("file request: %d %s", status, data)
	}
	reqID := int64(jsonMap(t, data)["id"].(float64))

	// A requester without CapApprove cannot list/approve.
	if status, _ := do(t, srv, http.MethodGet, "/api/access-requests", alice, nil); status != http.StatusForbidden {
		t.Fatalf("alice list requests: want 403, got %d", status)
	}

	// Four-eyes: an admin who filed a request cannot approve their own.
	_, data = do(t, srv, http.MethodPost, "/api/access-requests", testAPIKey, map[string]any{"target_id": targetID})
	ownID := int64(jsonMap(t, data)["id"].(float64))
	if status, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", ownID), testAPIKey, nil); status != http.StatusForbidden {
		t.Fatalf("self-approval: want 403, got %d", status)
	}

	// Bob (approver, a different principal) approves Alice's request.
	if status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/approve", reqID), bob, nil); status != http.StatusOK {
		t.Fatalf("approve: %d %s", status, data)
	}

	// Now Alice can connect and the credential is injected into the fake runner.
	if status, data := do(t, srv, http.MethodPost, run, alice, map[string]any{"command": "whoami"}); status != http.StatusOK {
		t.Fatalf("connect after approval: %d %s", status, data)
	}
	if fake.gotCmd != "whoami" {
		t.Fatalf("runner did not execute: gotCmd=%q", fake.gotCmd)
	}

	// A decided request cannot be decided again.
	if status, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/access-requests/%d/deny", reqID), bob, nil); status != http.StatusConflict {
		t.Fatalf("re-decide: want 409, got %d", status)
	}
}

// TestApprovalBreakGlassBypass verifies break-glass bypasses the approval gate.
func TestApprovalBreakGlassBypass(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, _ := newTestServerOpts(t, nil, api.Options{WinRM: fake})
	targetID := seedApprovalTarget(t, srv, true)

	// Break-glass bypasses the approval gate (emergency access).
	if status, data := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/winrm", targetID), breakGlassKey, map[string]any{"command": "whoami"}); status != http.StatusOK {
		t.Fatalf("break-glass bypass: %d %s", status, data)
	}
}

// TestGlobalApprovalPolicyGatesUnflaggedTarget verifies the global RequireApproval
// policy gates a target that does not itself opt in.
func TestGlobalApprovalPolicyGatesUnflaggedTarget(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok\r\n"}}
	srv, _ := newTestServerOpts(t, nil, api.Options{WinRM: fake, RequireApproval: true})
	// Target does NOT set require_approval, but the global policy gates it.
	targetID := seedApprovalTarget(t, srv, false)
	alice := seedUser(t, srv, "alice", "user")
	if status, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/winrm", targetID), alice, map[string]any{"command": "whoami"}); status != http.StatusForbidden {
		t.Fatalf("global policy gate: want 403, got %d", status)
	}
}
