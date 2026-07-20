package api_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestBrokerApprovalRevokedAgentRefused proves a call parked before its agent key
// was revoked is NOT executed just because a human later approves it.
func TestBrokerApprovalRevokedAgentRefused(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, approvalRules))
	seedWinRMTarget(t, srv, "win-rev", "pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-rev"})
	m := jsonMap(t, ad)
	tok, _ := m["token"].(string)
	keyID := int64(m["id"].(float64))
	_, pd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-rev", "command": "x"}})
	callID, _ := jsonMap(t, pd)["call_id"].(string)

	// Revoke the agent key while its call is parked.
	if code, _ := do(t, srv, http.MethodDelete, fmt.Sprintf("/v1/agents/%d", keyID), testAPIKey, nil); code != http.StatusNoContent {
		t.Fatalf("revoke agent: %d", code)
	}
	// Approving the parked call must refuse (identity no longer valid).
	_, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey, map[string]any{"approve": true})
	if jsonMap(t, dd)["status"] == "executed" {
		t.Fatalf("revoked agent's call was executed: %s", dd)
	}
	if fake.gotPass != "" {
		t.Fatal("credential injected for a revoked agent")
	}
}

// TestBrokerApprovalRevealNotLeakedToApprover proves an approved, approval-gated
// reveal_credential does NOT hand the secret to the approver (only the decision
// status) while the requesting agent still collects it once via the resume token,
// and the plaintext never enters the audit chain.
func TestBrokerApprovalRevealNotLeakedToApprover(t *testing.T) {
	const rules = "rules:\n  - id: reveal-needs-human\n    tool: reveal_credential\n    effect: require_approval\n    approvers: [team]\n"
	srv, st := newTestServerOpts(t, nil, brokerOpts(t, &fakeWinRM{result: winrm.Result{}}, rules))
	seedWinRMTarget(t, srv, "win-rv", "top-secret-pw")
	creds, _ := st.ListCredentials(context.Background(), 0)
	credID := creds[0].ID
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-rv", "owner": "alice"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, pd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "reveal_credential", "args": map[string]any{"credential_id": credID}})
	m := jsonMap(t, pd)
	callID, _ := m["call_id"].(string)
	resume, _ := m["resume_token"].(string)
	if m["status"] != "pending_approval" || callID == "" || resume == "" {
		t.Fatalf("expected pending_approval with token: %s", pd)
	}

	// The approver's decision response carries the status but NOT the secret.
	_, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey, map[string]any{"approve": true})
	if jsonMap(t, dd)["status"] != "executed" {
		t.Fatalf("decision status: %s", dd)
	}
	if strings.Contains(string(dd), "top-secret-pw") {
		t.Fatalf("approver decision response leaked the secret: %s", dd)
	}
	// The requesting agent collects the secret once via resume.
	_, rd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls/"+callID+"/resume", tok, map[string]any{"token": resume})
	if res, _ := jsonMap(t, rd)["result"].(map[string]any); res["secret"] != "top-secret-pw" {
		t.Fatalf("agent resume did not receive the secret: %s", rd)
	}
	// A status poll never re-serves the token or the secret.
	_, gp := doBearer(t, srv, http.MethodGet, "/v1/tool-calls/"+callID, tok, nil)
	if strings.Contains(string(gp), "resume_token") || strings.Contains(string(gp), "top-secret-pw") {
		t.Fatalf("status poll leaked token/secret: %s", gp)
	}
	// The audit chain never holds the plaintext.
	_, aud := do(t, srv, http.MethodGet, "/v1/audit", testAPIKey, nil)
	if strings.Contains(string(aud), "top-secret-pw") {
		t.Fatal("secret leaked into the broker audit chain")
	}
}

// TestBrokerSelfApprovalRefused proves the human who owns an agent cannot approve
// their own agent's parked call (four-eyes).
func TestBrokerSelfApprovalRefused(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, &fakeWinRM{result: winrm.Result{Stdout: "ok"}}, approvalRules))
	seedWinRMTarget(t, srv, "win-sa", "pw")
	// Agent owned by the bootstrap admin (whose actor name is "bootstrap-admin").
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-sa", "owner": "bootstrap-admin"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	_, pd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-sa", "command": "x"}})
	callID, _ := jsonMap(t, pd)["call_id"].(string)

	if code, _ := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey, map[string]any{"approve": true}); code != http.StatusForbidden {
		t.Fatalf("owner self-approval: want 403, got %d", code)
	}
}
