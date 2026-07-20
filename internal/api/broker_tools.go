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
// the credential just-in-time inside Execute, returning only the result.
func (s *Server) registerBrokerTools(reg *broker.Registry) {
	reg.Register(&winrmExecTool{s: s})
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
	target, err := t.s.targetByName(ctx, name)
	if err != nil {
		return broker.Result{}, err
	}
	if target.Protocol != "winrm" {
		return broker.Result{}, fmt.Errorf("target %q is not a winrm target", name)
	}
	if !t.s.protocolAllowed("winrm") {
		return broker.Result{}, fmt.Errorf("winrm is not allowed by policy")
	}
	// Agents obey target grants exactly like human principals.
	grants, err := t.s.store.ListTargetGrants(ctx, target.ID)
	if err != nil {
		return broker.Result{}, err
	}
	if !auth.CanConnectTarget(p, grants) {
		return broker.Result{}, fmt.Errorf("agent not authorized for target %q", name)
	}
	// Agents obey the same approval gate as humans: a target (or global OT policy)
	// that requires an approved access request blocks the agent too. In this
	// increment an agent has no way to obtain approval, so an approval-required
	// target is fail-closed for agents until the broker approval flow lands.
	if ok, err := t.s.enforceApproval(ctx, target); err != nil {
		return broker.Result{}, err
	} else if !ok {
		return broker.Result{}, fmt.Errorf("target %q requires an approved access request", name)
	}
	creds, err := t.s.store.ListCredentials(ctx, target.ID)
	if err != nil {
		return broker.Result{}, err
	}
	if len(creds) == 0 {
		return broker.Result{}, fmt.Errorf("target %q has no credential", name)
	}
	cred := creds[0]
	res, err := t.s.execWinRM(ctx, target, &cred, command, p.Name)
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
