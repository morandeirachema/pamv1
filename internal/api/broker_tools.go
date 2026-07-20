package api

import (
	"context"
	"fmt"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/broker"
	"github.com/morandeirachema/pamv1/internal/store"
)

// registerBrokerTools populates the broker's tool registry with the pamv1
// operations exposed to AI agents. Each tool re-checks target grants and injects
// the credential just-in-time inside Execute, returning only the result (except
// reveal_credential, the deliberate secret-returning tool, shipped default-deny).
func (s *Server) registerBrokerTools(reg *broker.Registry) {
	reg.Register(&winrmExecTool{s: s})
	reg.Register(&sshExecTool{s: s})
	reg.Register(&listTargetsTool{s: s})
	reg.Register(&listCredentialsTool{s: s})
	reg.Register(&rotateCredentialTool{s: s})
	reg.Register(&revealCredentialTool{s: s})
}

// targetByName resolves a target by its unique name.
func (s *Server) targetByName(ctx context.Context, name string) (*store.Target, error) {
	targets, err := s.store.ListTargets(ctx)
	if err != nil {
		return nil, err
	}
	for i := range targets {
		if targets[i].Name == name {
			return &targets[i], nil
		}
	}
	return nil, fmt.Errorf("target %q not found", name)
}

// authorizeAgentTarget resolves a named target and enforces, in one place, every
// gate an agent tool must pass before touching it: an optional expected protocol,
// the protocol allowlist, the agent's target grants, and the four-eyes approval
// gate (skipped only when the call was itself human-approved). It centralizes the
// checks winrm_exec and ssh_exec share.
func (s *Server) authorizeAgentTarget(ctx context.Context, p *auth.Principal, name, wantProto string) (*store.Target, error) {
	target, err := s.targetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if wantProto != "" && target.Protocol != wantProto {
		return nil, fmt.Errorf("target %q is not a %s target", name, wantProto)
	}
	if !s.protocolAllowed(target.Protocol) {
		return nil, fmt.Errorf("%s is not allowed by policy", target.Protocol)
	}
	grants, err := s.store.ListTargetGrants(ctx, target.ID)
	if err != nil {
		return nil, err
	}
	if !auth.CanConnectTarget(p, grants) {
		return nil, fmt.Errorf("agent not authorized for target %q", name)
	}
	if !broker.Approved(ctx) {
		if ok, err := s.enforceApproval(ctx, target); err != nil {
			return nil, err
		} else if !ok {
			return nil, fmt.Errorf("target %q requires an approved access request", name)
		}
	}
	return target, nil
}

// firstCredential returns a target's first credential, or an error if it has none.
func (s *Server) firstCredential(ctx context.Context, target *store.Target) (*store.Credential, error) {
	creds, err := s.store.ListCredentials(ctx, target.ID)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, fmt.Errorf("target %q has no credential", target.Name)
	}
	return &creds[0], nil
}

// authorizeAgentCredential resolves a credential by id and checks the agent is
// granted its target (the same grant gate the connect tools apply), returning the
// credential and its target.
func (s *Server) authorizeAgentCredential(ctx context.Context, p *auth.Principal, credID int64) (*store.Credential, *store.Target, error) {
	cred, err := s.store.GetCredential(ctx, credID)
	if err != nil {
		return nil, nil, err
	}
	target, err := s.store.GetTarget(ctx, cred.TargetID)
	if err != nil {
		return nil, nil, err
	}
	grants, err := s.store.ListTargetGrants(ctx, target.ID)
	if err != nil {
		return nil, nil, err
	}
	if !auth.CanConnectTarget(p, grants) {
		return nil, nil, fmt.Errorf("agent not authorized for target %q", target.Name)
	}
	return cred, target, nil
}

// argInt64 reads a numeric argument (JSON numbers decode to float64).
func argInt64(args broker.Args, key string) (int64, bool) {
	switch v := args[key].(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	}
	return 0, false
}

// winrmExecTool runs a command on a Windows target over WinRM using the target's
// vaulted credential (injected just-in-time), returning only the command output.
type winrmExecTool struct{ s *Server }

// Name is the tool's identifier used in policy rules and tool calls.
func (t *winrmExecTool) Name() string { return "winrm_exec" }

// Description is shown to agents in MCP tools/list.
func (t *winrmExecTool) Description() string {
	return "Run a command on a Windows target over WinRM; returns exit_code, stdout, stderr."
}

// InputSchema declares the tool's arguments.
func (t *winrmExecTool) InputSchema() map[string]string {
	return map[string]string{"target": "string", "command": "string"}
}

// Capability is the role capability an agent must hold to invoke any tool.
func (t *winrmExecTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute resolves the target + credential, checks the agent's target grants,
// and runs the command with a just-in-time credential. The credential is never
// part of the returned result.
func (t *winrmExecTool) Execute(ctx context.Context, p *auth.Principal, args broker.Args) (broker.Result, error) {
	name, _ := args["target"].(string)
	command, _ := args["command"].(string)
	if name == "" || command == "" {
		return broker.Result{}, fmt.Errorf("winrm_exec requires target and command")
	}
	target, err := t.s.authorizeAgentTarget(ctx, p, name, "winrm")
	if err != nil {
		return broker.Result{}, err
	}
	cred, err := t.s.firstCredential(ctx, target)
	if err != nil {
		return broker.Result{}, err
	}
	res, err := t.s.execWinRM(ctx, target, cred, command, p.Name)
	if err != nil {
		return broker.Result{}, err
	}
	return broker.Result{Data: map[string]any{
		"target":    target.Name,
		"exit_code": res.ExitCode,
		"stdout":    res.Stdout,
		"stderr":    res.Stderr,
	}}, nil
}

// sshExecTool runs a one-shot command on a Linux/SSH target using the target's
// vaulted credential (injected just-in-time), returning only the output. It is a
// non-interactive exec (no PTY/shell); interactive sessions still go through the
// recording proxy.
type sshExecTool struct{ s *Server }

// Name is the tool's identifier used in policy rules and tool calls.
func (t *sshExecTool) Name() string { return "ssh_exec" }

// Description is shown to agents in MCP tools/list.
func (t *sshExecTool) Description() string {
	return "Run a one-shot command on an SSH target; returns exit_code and output."
}

// InputSchema declares the tool's arguments.
func (t *sshExecTool) InputSchema() map[string]string {
	return map[string]string{"target": "string", "command": "string"}
}

// Capability is the capability an agent must hold to invoke any tool.
func (t *sshExecTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute authorizes the target, decrypts the credential just-in-time, and runs
// the command over a one-shot SSH connection. The credential never leaves.
func (t *sshExecTool) Execute(ctx context.Context, p *auth.Principal, args broker.Args) (broker.Result, error) {
	name, _ := args["target"].(string)
	command, _ := args["command"].(string)
	if name == "" || command == "" {
		return broker.Result{}, fmt.Errorf("ssh_exec requires target and command")
	}
	target, err := t.s.authorizeAgentTarget(ctx, p, name, "ssh")
	if err != nil {
		return broker.Result{}, err
	}
	cred, err := t.s.firstCredential(ctx, target)
	if err != nil {
		return broker.Result{}, err
	}
	secret, err := t.s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		return broker.Result{}, fmt.Errorf("credential decrypt failed")
	}
	res, err := t.s.sshConnector.Exec(ctx, *target, cred.Username, secret, command)
	if err != nil {
		return broker.Result{}, err
	}
	t.s.auditAs(ctx, p.Name, "ssh.exec", fmt.Sprintf("target:%s user:%s exit:%d", target.Name, cred.Username, res.ExitCode))
	return broker.Result{Data: map[string]any{
		"target":    target.Name,
		"exit_code": res.ExitCode,
		"output":    res.Output,
	}}, nil
}

// listTargetsTool returns target inventory metadata (never secrets).
type listTargetsTool struct{ s *Server }

// Name is the tool's identifier.
func (t *listTargetsTool) Name() string { return "list_targets" }

// Description is shown to agents in MCP tools/list.
func (t *listTargetsTool) Description() string {
	return "List targets (metadata only: id, name, host, os_type, protocol)."
}

// InputSchema declares the tool's arguments (none).
func (t *listTargetsTool) InputSchema() map[string]string { return map[string]string{} }

// Capability is the capability an agent must hold to invoke any tool.
func (t *listTargetsTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute returns target metadata; credential material is never included.
func (t *listTargetsTool) Execute(ctx context.Context, _ *auth.Principal, _ broker.Args) (broker.Result, error) {
	targets, err := t.s.store.ListTargets(ctx)
	if err != nil {
		return broker.Result{}, err
	}
	list := make([]map[string]any, 0, len(targets))
	for _, tg := range targets {
		list = append(list, map[string]any{"id": tg.ID, "name": tg.Name, "host": tg.Host, "os_type": tg.OSType, "protocol": tg.Protocol})
	}
	return broker.Result{Data: map[string]any{"targets": list}}, nil
}

// listCredentialsTool returns credential metadata (never the secret; SecretEnc is
// json:"-" and is not read here).
type listCredentialsTool struct{ s *Server }

// Name is the tool's identifier.
func (t *listCredentialsTool) Name() string { return "list_credentials" }

// Description is shown to agents in MCP tools/list.
func (t *listCredentialsTool) Description() string {
	return "List credential metadata (id, target_id, username, secret_type); never the secret."
}

// InputSchema declares the tool's arguments (optional target name filter).
func (t *listCredentialsTool) InputSchema() map[string]string {
	return map[string]string{"target": "string"}
}

// Capability is the capability an agent must hold to invoke any tool.
func (t *listCredentialsTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute lists credential metadata, optionally filtered to one named target.
func (t *listCredentialsTool) Execute(ctx context.Context, _ *auth.Principal, args broker.Args) (broker.Result, error) {
	var targetID int64
	if name, _ := args["target"].(string); name != "" {
		target, err := t.s.targetByName(ctx, name)
		if err != nil {
			return broker.Result{}, err
		}
		targetID = target.ID
	}
	creds, err := t.s.store.ListCredentials(ctx, targetID)
	if err != nil {
		return broker.Result{}, err
	}
	list := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		list = append(list, map[string]any{"id": c.ID, "target_id": c.TargetID, "username": c.Username, "secret_type": c.SecretType})
	}
	return broker.Result{Data: map[string]any{"credentials": list}}, nil
}

// rotateCredentialTool rotates a credential's secret. The new secret is vaulted
// and never returned to the agent.
type rotateCredentialTool struct{ s *Server }

// Name is the tool's identifier.
func (t *rotateCredentialTool) Name() string { return "rotate_credential" }

// Description is shown to agents in MCP tools/list.
func (t *rotateCredentialTool) Description() string {
	return "Rotate a credential's secret (by credential_id); returns success only, never the new secret."
}

// InputSchema declares the tool's arguments.
func (t *rotateCredentialTool) InputSchema() map[string]string {
	return map[string]string{"credential_id": "int"}
}

// Capability is the capability an agent must hold to invoke any tool.
func (t *rotateCredentialTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute rotates the credential after checking the agent's target grant. The
// rotated secret stays in the vault; only a rotated-at timestamp is returned.
func (t *rotateCredentialTool) Execute(ctx context.Context, p *auth.Principal, args broker.Args) (broker.Result, error) {
	credID, ok := argInt64(args, "credential_id")
	if !ok {
		return broker.Result{}, fmt.Errorf("rotate_credential requires credential_id")
	}
	cred, target, err := t.s.authorizeAgentCredential(ctx, p, credID)
	if err != nil {
		return broker.Result{}, err
	}
	rotatedAt, err := t.s.rotateCredential(ctx, cred, target)
	if err != nil {
		return broker.Result{}, err
	}
	t.s.auditAs(ctx, p.Name, "credential.rotate", fmt.Sprintf("credential:%d target:%s reason:agent-broker", cred.ID, target.Name))
	return broker.Result{Data: map[string]any{"credential_id": cred.ID, "rotated": true, "rotated_at": rotatedAt}}, nil
}

// revealCredentialTool is the deliberate secret-returning tool: it decrypts and
// returns a credential to the agent. It breaks the "agent never holds a secret"
// default, so it is shipped default-deny (no policy rule allows it unless an
// operator adds one) and additionally honors PAM_REVEAL_DISABLED. The plaintext
// is returned only in the agent response, never written to any audit record.
type revealCredentialTool struct{ s *Server }

// Name is the tool's identifier.
func (t *revealCredentialTool) Name() string { return "reveal_credential" }

// Description is shown to agents in MCP tools/list.
func (t *revealCredentialTool) Description() string {
	return "Reveal a credential's secret to the agent (by credential_id). Default-deny; breaks JIT confinement."
}

// InputSchema declares the tool's arguments.
func (t *revealCredentialTool) InputSchema() map[string]string {
	return map[string]string{"credential_id": "int"}
}

// Capability is the capability an agent must hold to invoke any tool.
func (t *revealCredentialTool) Capability() auth.Capability { return auth.CapCallTool }

// Execute decrypts and returns the credential after the reveal-disabled check and
// the agent's target grant. The secret goes only to the agent response; the
// broker audit chain records the reveal action, never the plaintext.
func (t *revealCredentialTool) Execute(ctx context.Context, p *auth.Principal, args broker.Args) (broker.Result, error) {
	if t.s.rt().revealDisabled {
		return broker.Result{}, fmt.Errorf("credential reveal is disabled by policy")
	}
	credID, ok := argInt64(args, "credential_id")
	if !ok {
		return broker.Result{}, fmt.Errorf("reveal_credential requires credential_id")
	}
	cred, target, err := t.s.authorizeAgentCredential(ctx, p, credID)
	if err != nil {
		return broker.Result{}, err
	}
	secret, err := t.s.vault.Decrypt(ctx, cred.SecretEnc, store.CredentialAAD(target.ID, cred.ID))
	if err != nil {
		return broker.Result{}, fmt.Errorf("credential decrypt failed")
	}
	t.s.auditAs(ctx, p.Name, "credential.reveal", fmt.Sprintf("credential:%d target:%s user:%s via:agent-broker", cred.ID, target.Name, cred.Username))
	return broker.Result{Sensitive: true, Data: map[string]any{
		"credential_id": cred.ID,
		"target":        target.Name,
		"username":      cred.Username,
		"secret_type":   cred.SecretType,
		"secret":        secret,
	}}, nil
}
