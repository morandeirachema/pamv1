package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// TestMCPEndpoint proves the MCP JSON-RPC transport is at parity with REST:
// initialize/tools/list/tools/call/ping all work, a tool call routes through the
// same broker (JIT injection, no leak), and unknown methods / bad auth are
// handled per JSON-RPC / transport rules.
func TestMCPEndpoint(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "contoso\\svc\r\n", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, brokerRules))
	seedWinRMTarget(t, srv, "win-mcp", "vault-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-mcp"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	rpc := func(id int, method string, params map[string]any) []byte {
		body := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
		if params != nil {
			body["params"] = params
		}
		st, data := doBearer(t, srv, http.MethodPost, "/mcp", tok, body)
		if st != http.StatusOK {
			t.Fatalf("mcp %s status %d: %s", method, st, data)
		}
		return data
	}

	if !strings.Contains(string(rpc(1, "initialize", nil)), "protocolVersion") {
		t.Fatal("initialize missing protocolVersion")
	}
	if lb := rpc(2, "tools/list", nil); !strings.Contains(string(lb), "winrm_exec") || !strings.Contains(string(lb), "inputSchema") {
		t.Fatalf("tools/list: %s", lb)
	}

	// tools/call routes through the broker: executed, JIT injection, no leak.
	cb := rpc(3, "tools/call", map[string]any{"name": "winrm_exec", "arguments": map[string]any{"target": "win-mcp", "command": "whoami"}})
	if !strings.Contains(string(cb), "executed") {
		t.Fatalf("tools/call: %s", cb)
	}
	if fake.gotPass != "vault-pw" {
		t.Fatalf("runner got %q, want vault-pw", fake.gotPass)
	}
	if strings.Contains(string(cb), "vault-pw") {
		t.Fatal("mcp tools/call leaked the credential")
	}

	if !strings.Contains(string(rpc(4, "ping", nil)), `"result"`) {
		t.Fatal("ping had no result")
	}

	// Unknown method → JSON-RPC -32601.
	var nf struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rpc(5, "bogus/method", nil), &nf)
	if nf.Error == nil || nf.Error.Code != -32601 {
		t.Fatalf("unknown method not -32601: %+v", nf.Error)
	}

	// Bad bearer → transport 401.
	if st, _ := doBearer(t, srv, http.MethodPost, "/mcp", "bad", map[string]any{"jsonrpc": "2.0", "id": 9, "method": "ping"}); st != http.StatusUnauthorized {
		t.Fatalf("mcp bad token: want 401, got %d", st)
	}
}

// TestMCPResume proves the MCP transport shares the approval/resume flow with
// REST: a require_approval tool call parks, a human approves via REST, and the
// agent collects the result once via MCP broker/resume.
func TestMCPResume(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, approvalRules))
	seedWinRMTarget(t, srv, "win-mcpr", "pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-mcpr"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	// tools/call parks for approval; read call_id + resume_token from structured content.
	_, cd := doBearer(t, srv, http.MethodPost, "/mcp", tok, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "winrm_exec", "arguments": map[string]any{"target": "win-mcpr", "command": "x"}}})
	var parked struct {
		Result struct {
			StructuredContent struct {
				CallID      string `json:"call_id"`
				ResumeToken string `json:"resume_token"`
				Status      string `json:"status"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(cd, &parked); err != nil {
		t.Fatal(err)
	}
	sc := parked.Result.StructuredContent
	if sc.Status != "pending_approval" || sc.CallID == "" || sc.ResumeToken == "" {
		t.Fatalf("expected pending_approval with token: %s", cd)
	}

	// A human approves via REST.
	if st, dd := do(t, srv, http.MethodPost, "/v1/approvals/"+sc.CallID+"/decision", testAPIKey, map[string]any{"approve": true}); st != http.StatusOK || jsonMap(t, dd)["status"] != "executed" {
		t.Fatalf("approve: %d %s", st, dd)
	}

	// The agent collects the result via MCP broker/resume (single-use).
	_, rd := doBearer(t, srv, http.MethodPost, "/mcp", tok, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "broker/resume", "params": map[string]any{"token": sc.ResumeToken}})
	if !strings.Contains(string(rd), "executed") {
		t.Fatalf("mcp resume: %s", rd)
	}
	// A second resume is rejected (token spent) — JSON-RPC error.
	_, rd2 := doBearer(t, srv, http.MethodPost, "/mcp", tok, map[string]any{"jsonrpc": "2.0", "id": 3, "method": "broker/resume", "params": map[string]any{"token": sc.ResumeToken}})
	if !strings.Contains(string(rd2), "error") {
		t.Fatalf("second mcp resume should error: %s", rd2)
	}
}
