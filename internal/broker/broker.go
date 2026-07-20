// Package broker is the AI-agent access broker's decision loop, shared by the
// REST and MCP transports. It resolves a policy decision for a tool call and its
// arguments, and on allow executes the tool server-side (which injects the target
// credential just-in-time), returning ONLY the result to the agent — the agent
// never holds a credential. Every outcome is written to the hash-chained audit.
package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/store"
)

// Status is a tool-call outcome. Callers key on this, not the HTTP status code.
type Status string

const (
	StatusExecuted        Status = "executed"
	StatusPendingApproval Status = "pending_approval"
	StatusDenied          Status = "denied"
	StatusFailed          Status = "failed"
)

// Args are a tool call's arguments (decoded from JSON).
type Args = map[string]any

// Result is a tool's output. For exec/rotate/list tools it never carries
// credential material — the plaintext lives only inside Execute.
type Result struct{ Data map[string]any }

// Tool is one brokered operation wrapping a pamv1 action.
type Tool interface {
	Name() string
	Description() string
	InputSchema() map[string]string // field -> "string|int|bool" (validation + MCP tools/list)
	Capability() auth.Capability
	Execute(ctx context.Context, p *auth.Principal, args Args) (Result, error)
}

// Registry holds the available tools by name.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{tools: map[string]Tool{}} }

// Register adds a tool (last registration for a name wins).
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
}

// Get returns the tool with the given name.
func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// List returns the tools sorted by name (for MCP tools/list).
func (r *Registry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// Call is a tool-call request from an agent.
type Call struct {
	SessionID string
	Tool      string
	Args      Args
}

// Outcome is the terminal (or pending) result of a tool call.
type Outcome struct {
	CallID     string         `json:"call_id"`
	Status     Status         `json:"status"`
	Result     map[string]any `json:"result,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	RuleID     string         `json:"rule_id,omitempty"`
	Scope      string         `json:"scope,omitempty"`
	ApprovalID string         `json:"approval_id,omitempty"`
}

const maxRemembered = 4096

// Broker runs the shared policy loop.
type Broker struct {
	engine   *policy.Engine
	registry *Registry
	chain    *auditchain.Chain
	log      *slog.Logger

	mu    sync.Mutex
	calls map[string]Outcome // call_id -> latest outcome (in-memory; persisted in a later increment)
	order []string           // insertion order, for bounded eviction
}

// New builds a Broker over a policy engine, tool registry, and audit chain.
func New(engine *policy.Engine, reg *Registry, chain *auditchain.Chain) *Broker {
	return &Broker{engine: engine, registry: reg, chain: chain, log: logging.Component("broker"), calls: map[string]Outcome{}}
}

// Tools returns the registered tools (for MCP tools/list).
func (b *Broker) Tools() []Tool { return b.registry.List() }

// ProcessCall evaluates policy and, on allow, executes the tool server-side,
// returning only the result. Deny and (for now) require_approval are terminal
// here; the approval decision + resume flow lands in a later increment.
func (b *Broker) ProcessCall(ctx context.Context, id *agentid.Identity, c Call) Outcome {
	out := Outcome{CallID: newCallID()}

	// Policy decides first: deny and require_approval need no tool, and an unknown
	// tool with no matching rule is denied by default (fail-closed), never run.
	d := b.engine.Evaluate(c.Tool, c.Args)
	out.RuleID, out.Scope, out.Reason = d.RuleID, d.Scope, d.Reason
	switch d.Effect {
	case policy.EffectDeny:
		out.Status = StatusDenied
	case policy.EffectRequireApproval:
		out.Status = StatusPendingApproval
		out.ApprovalID = out.CallID
	case policy.EffectAllow:
		tool, ok := b.registry.Get(c.Tool)
		if !ok {
			out.Status, out.Reason = StatusFailed, "unknown tool: "+c.Tool
			break
		}
		// Record the intent in the tamper-evident chain BEFORE running a
		// side-effecting action, so an executed action can never be missing from
		// the authoritative log. If the chain is unavailable, refuse to run (fail
		// closed) rather than execute unauditably.
		if err := b.chainEvent(ctx, id, c, "broker.tool_call.requested", out, ""); err != nil {
			b.log.Error("broker audit chain unavailable; refusing tool call", "call", out.CallID, "err", err)
			out.Status, out.Reason = StatusFailed, "audit log unavailable; call refused"
			break
		}
		res, err := tool.Execute(ctx, id.Principal(), c.Args)
		if err != nil {
			out.Status, out.Reason = StatusFailed, err.Error()
		} else {
			out.Status, out.Result = StatusExecuted, res.Data
		}
	default:
		out.Status, out.Reason = StatusFailed, "policy returned no effect"
	}

	b.remember(out)
	// Record the terminal outcome (best-effort: for a side-effecting call the
	// "requested" event above already durably captured it in the chain).
	if err := b.chainEvent(ctx, id, c, "broker.tool_call."+string(out.Status), out, out.Reason); err != nil {
		b.log.Error("broker audit chain append failed", "call", out.CallID, "err", err)
	}
	return out
}

// Lookup returns the latest known outcome for a call id.
func (b *Broker) Lookup(callID string) (Outcome, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.calls[callID]
	return o, ok
}

// remember stores the outcome, evicting the oldest when over the cap.
func (b *Broker) remember(out Outcome) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.calls[out.CallID]; !exists {
		b.order = append(b.order, out.CallID)
		if len(b.order) > maxRemembered {
			delete(b.calls, b.order[0])
			b.order = b.order[1:]
		}
	}
	b.calls[out.CallID] = out
}

// chainEvent appends one broker audit event (a pre-execution "requested" record
// or a terminal outcome) to the tamper-evident chain and returns any error so the
// caller can fail closed. The request arguments (never a credential — the broker
// injects that) are recorded so the trail shows what was asked.
func (b *Broker) chainEvent(ctx context.Context, id *agentid.Identity, c Call, action string, out Outcome, reason string) error {
	detail := fmt.Sprintf("tool:%s call:%s rule:%s args:%s", c.Tool, out.CallID, out.RuleID, argsSummary(c.Args))
	if reason != "" {
		detail += " reason:" + reason
	}
	_, err := b.chain.Append(ctx, store.BrokerAuditEvent{
		Actor:      id.AgentName,
		OnBehalfOf: id.OnBehalfOf,
		ActorChain: chainJSON(id.ActorChain),
		Action:     action,
		Detail:     detail,
		Scope:      out.Scope,
	})
	return err
}

// argsSummary renders the call arguments as compact JSON, capped so a large or
// hostile argument can't bloat an audit row.
func argsSummary(args Args) string {
	b, err := json.Marshal(args)
	if err != nil {
		return "{}"
	}
	const cap = 512
	if len(b) > cap {
		return string(b[:cap]) + "…"
	}
	return string(b)
}

// chainJSON renders a delegation actor chain as a JSON array ("" when empty).
func chainJSON(chain []string) string {
	if len(chain) == 0 {
		return ""
	}
	b, _ := json.Marshal(chain)
	return string(b)
}

// newCallID returns an opaque, unguessable call identifier.
func newCallID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return "call_" + hex.EncodeToString(b[:])
}
