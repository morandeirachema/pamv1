package api_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// approvalRules parks winrm_exec for a human decision.
const approvalRules = "rules:\n  - id: needs-human\n    tool: winrm_exec\n    effect: require_approval\n    approvers: [team]\n    scope: \"t:{target}:x\"\n"

// TestBrokerApprovalResume proves the full approval flow: a require_approval call
// parks with a single-use resume token, a human approver executes it server-side
// (JIT, no credential leak), the agent collects the result once via the token, a
// replay is rejected, and the chain records the approval and stays intact.
func TestBrokerApprovalResume(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "contoso\\svc\r\n", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, approvalRules))
	seedWinRMTarget(t, srv, "win-ap", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-ap", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	// 1. Agent call parks for approval and gets a resume token; no injection yet.
	_, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-ap", "command": "whoami"}})
	m := jsonMap(t, data)
	if m["status"] != "pending_approval" {
		t.Fatalf("want pending_approval: %s", data)
	}
	callID, _ := m["call_id"].(string)
	resume, _ := m["resume_token"].(string)
	if callID == "" || resume == "" {
		t.Fatalf("missing call_id/resume_token: %s", data)
	}
	if fake.gotPass != "" {
		t.Fatal("credential injected before approval")
	}

	// 2. Approver sees the pending call.
	_, ld := do(t, srv, http.MethodGet, "/v1/approvals", testAPIKey, nil)
	if !strings.Contains(string(ld), callID) || !strings.Contains(string(ld), "win-ap") {
		t.Fatalf("approvals list missing the call: %s", ld)
	}

	// 3. Approve → executes JIT server-side with the vaulted secret, leaks nothing.
	st, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey, map[string]any{"approve": true})
	if st != http.StatusOK || jsonMap(t, dd)["status"] != "executed" {
		t.Fatalf("approve decision: %d %s", st, dd)
	}
	if fake.gotPass != "vault-pw" {
		t.Fatalf("runner got %q, want vault-pw", fake.gotPass)
	}
	if strings.Contains(string(dd), "vault-pw") {
		t.Fatal("decision response leaked the credential")
	}

	// 4. Agent resumes with the single-use token → executed result.
	st, rd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls/"+callID+"/resume", tok, map[string]any{"token": resume})
	if st != http.StatusOK || jsonMap(t, rd)["status"] != "executed" {
		t.Fatalf("resume: %d %s", st, rd)
	}
	if res, _ := jsonMap(t, rd)["result"].(map[string]any); res["stdout"] != "contoso\\svc\r\n" {
		t.Fatalf("resume result wrong: %s", rd)
	}

	// 5. Single-use: a second resume is rejected.
	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls/"+callID+"/resume", tok, map[string]any{"token": resume}); st != http.StatusNotFound {
		t.Fatalf("second resume: want 404, got %d", st)
	}

	// 6. The chain records the human approval and verifies intact.
	_, aud := do(t, srv, http.MethodGet, "/v1/audit", testAPIKey, nil)
	if !strings.Contains(string(aud), "broker.approval.granted") {
		t.Fatalf("audit missing approval.granted: %s", aud)
	}
	if _, vd := do(t, srv, http.MethodGet, "/v1/audit/verify", testAPIKey, nil); jsonMap(t, vd)["ok"] != true {
		t.Fatal("audit chain not intact after approval")
	}
}

// TestBrokerResumeNotBurnedBeforeApproval proves an early resume (before the
// human decides) fails WITHOUT spending the single-use token, so the agent can
// still collect the result once the call is approved.
func TestBrokerResumeNotBurnedBeforeApproval(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, approvalRules))
	seedWinRMTarget(t, srv, "win-early", "pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-early"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	_, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-early", "command": "x"}})
	m := jsonMap(t, data)
	callID, _ := m["call_id"].(string)
	resume, _ := m["resume_token"].(string)

	// Resuming before the approver decides fails and must NOT spend the token.
	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls/"+callID+"/resume", tok, map[string]any{"token": resume}); st != http.StatusNotFound {
		t.Fatalf("early resume: want 404, got %d", st)
	}
	if st, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey, map[string]any{"approve": true}); st != http.StatusOK || jsonMap(t, dd)["status"] != "executed" {
		t.Fatalf("approve: %d %s", st, dd)
	}
	// The still-valid token now collects the result.
	if st, rd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls/"+callID+"/resume", tok, map[string]any{"token": resume}); st != http.StatusOK || jsonMap(t, rd)["status"] != "executed" {
		t.Fatalf("resume after approval: %d %s (token wrongly burned by the early resume?)", st, rd)
	}
}

// TestBrokerApprovalReject proves a rejected approval denies the call (no
// injection) and that a parked call can be decided only once.
func TestBrokerApprovalReject(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, approvalRules))
	seedWinRMTarget(t, srv, "win-rj", "pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-rj"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	_, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-rj", "command": "x"}})
	callID, _ := jsonMap(t, data)["call_id"].(string)

	st, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey, map[string]any{"approve": false})
	if st != http.StatusOK || jsonMap(t, dd)["status"] != "denied" {
		t.Fatalf("reject: %d %s", st, dd)
	}
	if fake.gotPass != "" {
		t.Fatal("credential injected for a rejected call")
	}
	// A parked call decides only once.
	if st, _ := do(t, srv, http.MethodPost, "/v1/approvals/"+callID+"/decision", testAPIKey, map[string]any{"approve": true}); st != http.StatusNotFound {
		t.Fatalf("double decision: want 404, got %d", st)
	}
}

// TestBrokerArgCap proves an oversized argument set is rejected before execution.
func TestBrokerArgCap(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	opts := brokerOpts(t, fake, brokerRules)
	opts.BrokerMaxArgBytes = 32
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-cap", "pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-cap"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	big := strings.Repeat("A", 200)
	_, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-cap", "command": big}})
	m := jsonMap(t, data)
	if m["status"] != "failed" || !strings.Contains(fmt.Sprint(m["reason"]), "limit") {
		t.Fatalf("want failed (arg cap): %s", data)
	}
	if fake.gotPass != "" {
		t.Fatal("oversized call still injected a credential")
	}
}

// TestBrokerRateLimit proves the per-agent tool-call rate limit returns 429.
func TestBrokerRateLimit(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	opts := brokerOpts(t, fake, brokerRules)
	opts.BrokerRatePerMin = 1
	srv, _ := newTestServerOpts(t, nil, opts)
	seedWinRMTarget(t, srv, "win-rl", "pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-rl"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	call := func() int {
		st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-rl", "command": "x"}})
		return st
	}
	if st := call(); st != http.StatusOK {
		t.Fatalf("first call: want 200, got %d", st)
	}
	if st := call(); st != http.StatusTooManyRequests {
		t.Fatalf("second call: want 429, got %d", st)
	}
}
