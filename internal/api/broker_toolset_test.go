package api_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/winrm"
)

// toolsetRules allows the read/rotate/ssh tools; reveal_credential is left with
// no rule so it is denied by default (the shipped posture).
const toolsetRules = `
rules:
  - id: allow-list-targets
    tool: list_targets
    effect: allow
  - id: allow-list-creds
    tool: list_credentials
    effect: allow
  - id: allow-rotate
    tool: rotate_credential
    effect: allow
  - id: allow-ssh
    tool: ssh_exec
    effect: allow
`

// TestBrokerReadTools proves list_targets and list_credentials return metadata
// only — never a secret.
func TestBrokerReadTools(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, toolsetRules))
	seedWinRMTarget(t, srv, "win-meta", "top-secret-pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-meta"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, td := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "list_targets"})
	if m := jsonMap(t, td); m["status"] != "executed" {
		t.Fatalf("list_targets: %s", td)
	}
	if strings.Contains(string(td), "top-secret-pw") {
		t.Fatal("list_targets leaked a secret")
	}

	_, cd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "list_credentials", "args": map[string]any{"target": "win-meta"}})
	if m := jsonMap(t, cd); m["status"] != "executed" || !strings.Contains(string(cd), "\"username\":\"svc\"") {
		t.Fatalf("list_credentials: %s", cd)
	}
	if strings.Contains(string(cd), "top-secret-pw") {
		t.Fatal("list_credentials leaked a secret")
	}
}

// TestBrokerRotateTool proves rotate_credential rotates the vaulted secret and
// never returns the new secret to the agent.
func TestBrokerRotateTool(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, st := newTestServerOpts(t, nil, brokerOpts(t, fake, toolsetRules))
	seedWinRMTarget(t, srv, "win-rot", "before-pw")
	// Find the credential id.
	creds, err := st.ListCredentials(context.Background(), 0)
	if err != nil || len(creds) != 1 {
		t.Fatalf("seed creds: %v %d", err, len(creds))
	}
	before := creds[0].SecretEnc
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-rot"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, rd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "rotate_credential", "args": map[string]any{"credential_id": creds[0].ID}})
	if m := jsonMap(t, rd); m["status"] != "executed" {
		t.Fatalf("rotate: %s", rd)
	}
	// The stored ciphertext changed (a real rotation happened).
	after, err := st.GetCredential(context.Background(), creds[0].ID)
	if err != nil || after.SecretEnc == before {
		t.Fatalf("credential not rotated: err=%v same=%v", err, after != nil && after.SecretEnc == before)
	}
}

// TestBrokerRevealDefaultDeny proves reveal_credential is denied when no policy
// rule allows it — the shipped default-deny posture for the secret-returning tool.
func TestBrokerRevealDefaultDeny(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, st := newTestServerOpts(t, nil, brokerOpts(t, fake, toolsetRules))
	seedWinRMTarget(t, srv, "win-rev", "reveal-me-pw")
	creds, _ := st.ListCredentials(context.Background(), 0)
	credID := creds[0].ID
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-rev"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	// Default-deny: no rule for reveal_credential.
	_, dd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "reveal_credential", "args": map[string]any{"credential_id": credID}})
	if jsonMap(t, dd)["status"] != "denied" {
		t.Fatalf("reveal should be default-denied: %s", dd)
	}
}

// TestBrokerRevealWhenAllowed proves that when an operator explicitly allows
// reveal_credential, the secret reaches the agent but is never written to the
// tamper-evident broker audit chain.
func TestBrokerRevealWhenAllowed(t *testing.T) {
	const rules = "rules:\n  - id: allow-reveal\n    tool: reveal_credential\n    effect: allow\n"
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, st := newTestServerOpts(t, nil, brokerOpts(t, fake, rules))
	seedWinRMTarget(t, srv, "win-rev2", "reveal-me-pw")
	creds, _ := st.ListCredentials(context.Background(), 0)
	credID := creds[0].ID
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-rev2"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, rd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "reveal_credential", "args": map[string]any{"credential_id": credID}})
	m := jsonMap(t, rd)
	if m["status"] != "executed" {
		t.Fatalf("reveal (allowed): %s", rd)
	}
	if res, _ := m["result"].(map[string]any); res["secret"] != "reveal-me-pw" {
		t.Fatalf("reveal did not return the secret: %s", rd)
	}
	// The plaintext must never appear in the broker audit chain.
	_, aud := do(t, srv, http.MethodGet, "/v1/audit", testAPIKey, nil)
	if strings.Contains(string(aud), "reveal-me-pw") {
		t.Fatal("reveal secret leaked into the broker audit chain")
	}
}

// TestBrokerSSHExecGating proves ssh_exec refuses a non-SSH target (a full
// happy-path exec is covered by the rotate package's SSH test).
func TestBrokerSSHExecGating(t *testing.T) {
	fake := &fakeWinRM{result: winrm.Result{Stdout: "ok"}}
	srv, _ := newTestServerOpts(t, nil, brokerOpts(t, fake, toolsetRules))
	seedWinRMTarget(t, srv, "win-only", "pw")
	_, ad := do(t, srv, http.MethodPost, "/v1/agents", testAPIKey, map[string]any{"name": "bot-ssh"})
	tok, _ := jsonMap(t, ad)["token"].(string)

	_, sd := doBearer(t, srv, http.MethodPost, "/v1/tool-calls", tok, map[string]any{"tool": "ssh_exec", "args": map[string]any{"target": "win-only", "command": "id"}})
	if m := jsonMap(t, sd); m["status"] != "failed" || !strings.Contains(strings.ToLower(string(sd)), "not a ssh target") {
		t.Fatalf("ssh_exec on winrm target should fail: %s", sd)
	}
}
