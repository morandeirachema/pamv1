package api_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/winrm"
)

// brokerOpts builds api.Options with the agent broker enabled over the given
// policy and a fake WinRM runner.
func brokerOpts(t *testing.T, fake *fakeWinRM, rules string) api.Options {
	t.Helper()
	engine, err := policy.Load(strings.NewReader(rules))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return api.Options{WinRM: fake, BrokerPolicy: engine, BrokerAuditKey: key, BrokerAuditSignKey: priv}
}

// doBearer issues a request authenticated with an agent Bearer token.
func doBearer(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	return res.StatusCode, data
}

const brokerRules = `
rules:
  - id: allow-winrm
    tool: winrm_exec
    effect: allow
    scope: "target:{target}:exec"
    ttl_seconds: 60
  - id: deny-rotate
    tool: rotate_credential
    effect: deny
    reason: rotation is not brokered to agents
  - id: allow-ghost
    tool: ghost_tool
    effect: allow
`

// seedWinRMTarget creates a WinRM target with an explicit name plus a credential
// whose secret is distinct from the name, so a leak check is meaningful.
func seedWinRMTarget(t *testing.T, srv *httptest.Server, name, secret string) {
	t.Helper()
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": name, "host": "10.0.0.9", "port": 5985, "os_type": "windows", "protocol": "winrm",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	if st, d := do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": tid, "username": "svc", "secret": secret,
	}); st != http.StatusCreated {
		t.Fatalf("seed credential: %d %s", st, d)
	}
}

// TestBrokerJITInjection proves the broker's core guarantee: an allowed tool call
// executes server-side with a just-in-time credential the agent never sees, the
// runner receives the *vaulted* secret, and the response leaks nothing.
func TestBrokerJITInjection(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "contoso\\svc\r\n", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, brokerRules))

	// A WinRM target "win-01" whose credential secret is distinct from its name.
	seedWinRMTarget(t, srv, "win-01", "vaulted-pw")

	// Mint an agent key (admin only), then call the tool as the agent.
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-1", "owner": "alice"})
	agentTok, _ := jsonMap(t, ad)["token"].(string)
	if agentTok == "" {
		t.Fatalf("no agent token: %s", ad)
	}

	status, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", agentTok, map[string]any{
		"tool": "winrm_exec",
		"args": map[string]any{"target": "win-01", "command": "whoami"},
	})
	if status != http.StatusOK {
		t.Fatalf("tool call: %d %s", status, data)
	}
	m := jsonMap(t, data)
	if m["status"] != "executed" {
		t.Fatalf("status = %v: %s", m["status"], data)
	}
	result, _ := m["result"].(map[string]any)
	if result["stdout"] != "contoso\\svc\r\n" {
		t.Fatalf("stdout = %v: %s", result["stdout"], data)
	}
	// JIT injection proof: the runner received the vaulted secret.
	if fake.gotPass != "vaulted-pw" {
		t.Fatalf("runner got password %q, want vaulted-pw", fake.gotPass)
	}
	// The credential must never appear in the agent-facing response.
	if strings.Contains(string(data), "vaulted-pw") {
		t.Fatal("tool-call response leaked the credential")
	}
}

// TestBrokerDenyAndAudit proves a denied tool returns status=denied (HTTP 200)
// and that the broker audit chain records activity and verifies intact.
func TestBrokerDenyAndAudit(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, brokerRules))
	seedWinRMTarget(t, srv, "win-02", "s3cr3t")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-2", "owner": "bob"})
	agentTok, _ := jsonMap(t, ad)["token"].(string)

	// A denied tool: HTTP 200 with status "denied" (decision is in the body).
	status, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", agentTok, map[string]any{
		"tool": "rotate_credential", "args": map[string]any{"credential_id": 1},
	})
	if status != http.StatusOK || jsonMap(t, data)["status"] != "denied" {
		t.Fatalf("deny: %d %s", status, data)
	}

	// A tool with no matching rule is denied by default (fail-closed).
	if _, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", agentTok, map[string]any{"tool": "nope"}); jsonMap(t, d)["status"] != "denied" {
		t.Fatalf("no-rule tool should be denied: %s", d)
	}

	// A tool the policy allows but that isn't registered fails (misconfig).
	if _, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", agentTok, map[string]any{"tool": "ghost_tool"}); jsonMap(t, d)["status"] != "failed" {
		t.Fatalf("allowed-but-unregistered tool should fail: %s", d)
	}

	// The broker audit chain verifies intact (admin reads it).
	_, vd := do(t, srv, http.MethodGet, "/v1/audit/verify", testAPIKey, nil)
	if jsonMap(t, vd)["ok"] != true {
		t.Fatalf("audit chain not intact: %s", vd)
	}

	// A missing/invalid agent credential is rejected at the transport layer (401).
	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", "bogus", map[string]any{"tool": "winrm_exec"}); st != http.StatusUnauthorized {
		t.Fatalf("bad agent token: want 401, got %d", st)
	}
}

// TestBrokerLookupAndAuditRoutes covers GET /v1/tool-calls/{id} (found + 404),
// GET /v1/audit, and the signed GET /v1/audit/head checkpoint.
func TestBrokerLookupAndAuditRoutes(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, brokerRules))
	seedWinRMTarget(t, srv, "win-l", "pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-l"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	_, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-l", "command": "x"}})
	callID, _ := jsonMap(t, data)["call_id"].(string)

	if st, gd := doBearer(t, srv, http.MethodGet, "/v1/tool-calls/"+callID, tok, nil); st != http.StatusOK || jsonMap(t, gd)["status"] != "executed" {
		t.Fatalf("get tool-call: %d %s", st, gd)
	}
	if st, _ := doBearer(t, srv, http.MethodGet, "/v1/tool-calls/nope", tok, nil); st != http.StatusNotFound {
		t.Fatalf("unknown call id: want 404, got %d", st)
	}
	if _, aud := do(t, srv, http.MethodGet, "/v1/audit", testAPIKey, nil); !strings.Contains(string(aud), "broker.tool_call") {
		t.Fatalf("audit list missing broker events: %s", aud)
	}
	_, hd := do(t, srv, http.MethodGet, "/v1/audit/head", testAPIKey, nil)
	if m := jsonMap(t, hd); m["signature"] == nil || m["last_id"] == nil {
		t.Fatalf("head checkpoint incomplete: %s", hd)
	}
}

// TestBrokerRequireApproval proves a require_approval rule parks the call
// (pending_approval, no execution) — the seam the resume flow will extend.
func TestBrokerRequireApproval(t *testing.T) {
	const rules = "rules:\n  - id: needs-human\n    tool: winrm_exec\n    effect: require_approval\n    approvers: [team]\n    scope: \"t:{target}:x\"\n"
	fake := &fakeWinRM{}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, rules))
	seedWinRMTarget(t, srv, "win-appr", "pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-appr"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	_, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-appr", "command": "x"}})
	m := jsonMap(t, data)
	if m["status"] != "pending_approval" || m["approval_id"] == nil {
		t.Fatalf("want pending_approval with an approval_id: %s", data)
	}
	if fake.gotPass != "" {
		t.Fatal("credential injected for a pending-approval call")
	}
}

// TestBrokerObeysApproval proves an agent is subject to the same approval gate as
// a human: an allow policy does NOT let it reach an approval-required target
// without an approved request (fail-closed).
func TestBrokerObeysApproval(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, brokerRules))
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "prod-win", "host": "10.0.0.9", "port": 5985, "os_type": "windows", "protocol": "winrm", "require_approval": true,
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{"target_id": tid, "username": "svc", "secret": "pw"})
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, data := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{
		"tool": "winrm_exec", "args": map[string]any{"target": "prod-win", "command": "whoami"},
	})
	if jsonMap(t, data)["status"] == "executed" {
		t.Fatalf("agent executed on an approval-required target without approval: %s", data)
	}
	if fake.gotPass != "" {
		t.Fatal("credential was injected despite no approval")
	}
}

// TestAgentRoleGrant proves a role:agent grant is creatable (regression: it was
// rejected) and that it scopes a target to agents.
func TestAgentRoleGrant(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, brokerRules))
	_, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "granted-win", "host": "10.0.0.9", "port": 5985, "os_type": "windows", "protocol": "winrm",
	})
	tid := int64(jsonMap(t, td)["id"].(float64))
	do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{"target_id": tid, "username": "svc", "secret": "pw"})

	// A user grant (not agent) means the agent is NOT authorized...
	do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", tid), testAPIKey, map[string]any{"subject_type": "role", "subject": "user"})
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	if _, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "granted-win", "command": "x"}}); jsonMap(t, d)["status"] == "executed" {
		t.Fatal("agent executed on a target granted only to role:user")
	}
	// ...but a role:agent grant is creatable and authorizes the agent.
	if st, d := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", tid), testAPIKey, map[string]any{"subject_type": "role", "subject": "agent"}); st != http.StatusCreated {
		t.Fatalf("role:agent grant: want 201, got %d %s", st, d)
	}
	if _, d := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "granted-win", "command": "x"}}); jsonMap(t, d)["status"] != "executed" {
		t.Fatalf("agent with role:agent grant should execute: %s", d)
	}
}

// TestAgentKeyRevocation proves an admin can list agent keys and revoke one, and
// that a revoked token stops authenticating.
func TestAgentKeyRevocation(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, &fakeWinRM{}, brokerRules))
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-rev", "owner": "a"})
	m := jsonMap(t, ad)
	tok, _ := m["token"].(string)
	id := int64(m["id"].(float64))

	if _, ld := do(t, srv, http.MethodGet, "/v1/agents", testAPIKey, nil); !strings.Contains(string(ld), "bot-rev") {
		t.Fatalf("agent not listed: %s", ld)
	}
	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "nope"}); st != http.StatusOK {
		t.Fatalf("token should authenticate before revoke, got %d", st)
	}
	if st, _ := do(t, srv, http.MethodDelete, fmt.Sprintf("/v1/agents/%d", id), testAPIKey, nil); st != http.StatusNoContent {
		t.Fatalf("revoke: want 204, got %d", st)
	}
	if st, _ := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "nope"}); st != http.StatusUnauthorized {
		t.Fatalf("revoked token must 401, got %d", st)
	}
}

// TestBrokerAttributesAudit proves the sensitive winrm.run audit event is
// attributed to the agent, not the "unknown" fallback.
func TestBrokerAttributesAudit(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok", ExitCode: 0}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, brokerRules))
	seedWinRMTarget(t, srv, "win-attr", "pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-attr", "owner": "a"})
	tok, _ := jsonMap(t, ad)["token"].(string)
	doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "winrm_exec", "args": map[string]any{"target": "win-attr", "command": "x"}})

	_, aud := do(t, srv, http.MethodGet, "/api/audit?limit=100", testAPIKey, nil)
	var events []map[string]any
	if err := json.Unmarshal(aud, &events); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range events {
		if e["action"] == "winrm.run" {
			found = true
			if e["actor"] != "bot-attr" {
				t.Fatalf("winrm.run actor = %v, want bot-attr", e["actor"])
			}
		}
	}
	if !found {
		t.Fatal("no winrm.run audit event was recorded")
	}
}
