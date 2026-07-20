package api_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
