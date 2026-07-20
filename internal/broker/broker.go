// Package broker is the AI-agent access broker's decision loop, shared by the
// REST and MCP transports. It resolves a policy decision for a tool call and its
// arguments, and on allow executes the tool server-side (which injects the target
// credential just-in-time), returning ONLY the result to the agent — the agent
// never holds a credential. Every outcome is written to the hash-chained audit.
package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/alert"
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

// terminal reports whether the status is a final outcome (not awaiting a human).
func (s Status) terminal() bool {
	return s == StatusExecuted || s == StatusDenied || s == StatusFailed
}

// Args are a tool call's arguments (decoded from JSON).
type Args = map[string]any

// Result is a tool's output. For exec/rotate/list tools it never carries
// credential material — the plaintext lives only inside Execute. Sensitive marks
// a result that DOES carry a secret (only reveal_credential), so the broker
// delivers it exactly once and never retains it in the in-memory poll cache.
type Result struct {
	Data      map[string]any
	Sensitive bool
}

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
	CallID      string         `json:"call_id"`
	Status      Status         `json:"status"`
	Result      map[string]any `json:"result,omitempty"`
	Reason      string         `json:"reason,omitempty"`
	RuleID      string         `json:"rule_id,omitempty"`
	Scope       string         `json:"scope,omitempty"`
	ApprovalID  string         `json:"approval_id,omitempty"`
	ResumeToken string         `json:"resume_token,omitempty"` // single-use ticket to collect a post-approval result
}

const (
	maxRemembered = 4096 // bound on the in-memory outcome/poll cache
	maxParked     = 1024 // bound on simultaneously-pending approvals (DoS guard)
)

// TokenStore mints and spends the single-use resume tokens for parked calls.
// The store implements it; it is an interface so the broker stays transport- and
// storage-agnostic.
type TokenStore interface {
	CreateBrokerToken(ctx context.Context, t *store.BrokerToken) error
	ConsumeBrokerToken(ctx context.Context, jti string) (callID string, err error)
	PeekBrokerToken(ctx context.Context, jti string) (callID string, err error)
}

// parkedCall is a require_approval tool call awaiting a human decision. It holds
// the requesting agent identity and arguments so the broker can execute it
// server-side (JIT) once approved.
type parkedCall struct {
	id        *agentid.Identity
	call      Call
	scope     string
	ruleID    string
	reason    string
	requested time.Time
}

// PendingApproval is an approver-facing view of a parked call (no credential).
type PendingApproval struct {
	CallID     string    `json:"call_id"`
	Tool       string    `json:"tool"`
	Args       Args      `json:"args"`
	Agent      string    `json:"agent"`
	OnBehalfOf string    `json:"on_behalf_of,omitempty"`
	Scope      string    `json:"scope,omitempty"`
	RuleID     string    `json:"rule_id,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	Requested  time.Time `json:"requested_at"`
}

// Broker runs the shared policy loop.
type Broker struct {
	engine   *policy.Engine
	registry *Registry
	chain    *auditchain.Chain
	log      *slog.Logger

	tokens      TokenStore
	notifier    alert.Notifier
	tokenTTL    time.Duration
	maxArgBytes int

	mu     sync.Mutex
	calls  map[string]Outcome     // call_id -> latest outcome (in-memory)
	order  []string               // insertion order, for bounded eviction
	parked map[string]*parkedCall // call_id -> parked approval-pending call
}

// New builds a Broker over a policy engine, tool registry, and audit chain.
func New(engine *policy.Engine, reg *Registry, chain *auditchain.Chain) *Broker {
	return &Broker{
		engine: engine, registry: reg, chain: chain,
		log: logging.Component("broker"), notifier: alert.Noop{}, tokenTTL: 15 * time.Minute,
		calls: map[string]Outcome{}, parked: map[string]*parkedCall{},
	}
}

// WithApproval wires the approval flow: single-use resume tokens (tokenTTL
// lifetime) and an alerter notified when a call is parked. Called by main when
// the broker is enabled; without it, require_approval calls still park and can be
// decided, but no resume token is minted.
func (b *Broker) WithApproval(tokens TokenStore, notifier alert.Notifier, tokenTTL time.Duration) *Broker {
	b.tokens = tokens
	if notifier != nil {
		b.notifier = notifier
	}
	if tokenTTL > 0 {
		b.tokenTTL = tokenTTL
	}
	return b
}

// WithArgCap sets the maximum serialized size (bytes) of a tool call's arguments;
// 0 disables the cap. A hostile or accidental oversized argument is rejected
// before policy evaluation.
func (b *Broker) WithArgCap(n int) *Broker {
	b.maxArgBytes = n
	return b
}

type approvedKey struct{}

// WithApproved marks a context as carrying a human approval for the current tool
// call, so a tool's target-level approval gate treats it as satisfied (the
// approver just provided four-eyes for this exact call).
func WithApproved(ctx context.Context) context.Context {
	return context.WithValue(ctx, approvedKey{}, true)
}

// Approved reports whether the context carries a human approval (see WithApproved).
func Approved(ctx context.Context) bool {
	v, _ := ctx.Value(approvedKey{}).(bool)
	return v
}

// Tools returns the registered tools (for MCP tools/list).
func (b *Broker) Tools() []Tool { return b.registry.List() }

// ProcessCall evaluates policy and, on allow, executes the tool server-side,
// returning only the result. Deny and (for now) require_approval are terminal
// here; the approval decision + resume flow lands in a later increment.
func (b *Broker) ProcessCall(ctx context.Context, id *agentid.Identity, c Call) Outcome {
	out := Outcome{CallID: newCallID()}

	// Reject an oversized argument set before doing any work — the cap bounds both
	// audit-row bloat and a hostile payload. Recorded as a failure, still audited.
	if b.maxArgBytes > 0 {
		if raw, _ := json.Marshal(c.Args); len(raw) > b.maxArgBytes {
			out.Status, out.Reason = StatusFailed, fmt.Sprintf("arguments exceed %d-byte limit", b.maxArgBytes)
			b.remember(out)
			if err := b.chainEvent(ctx, id, c, "broker.tool_call.failed", out, out.Reason); err != nil {
				b.log.Error("broker audit chain append failed", "call", out.CallID, "err", err)
			}
			return out
		}
	}

	// Policy decides first: deny and require_approval need no tool, and an unknown
	// tool with no matching rule is denied by default (fail-closed), never run.
	d := b.engine.Evaluate(c.Tool, c.Args)
	out.RuleID, out.Scope, out.Reason = d.RuleID, d.Scope, d.Reason
	var sensitive bool // the executed result carries a secret (reveal_credential)
	switch d.Effect {
	case policy.EffectDeny:
		out.Status = StatusDenied
	case policy.EffectRequireApproval:
		out.Status = StatusPendingApproval
		out.ApprovalID = out.CallID
		b.park(ctx, id, c, &out)
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
			out.Status, out.Result, sensitive = StatusExecuted, res.Data, res.Sensitive
		}
	default:
		out.Status, out.Reason = StatusFailed, "policy returned no effect"
	}

	// A secret-bearing immediate result is delivered once in the returned outcome
	// but never retained in the poll cache — there is no resume token for an
	// allow (non-parked) call, so it can never be collected again.
	stored := out
	if sensitive {
		stored.Result = nil
	}
	b.remember(stored)
	// Record the terminal outcome (best-effort: for a side-effecting call the
	// "requested" event above already durably captured it in the chain).
	if err := b.chainEvent(ctx, id, c, "broker.tool_call."+string(out.Status), out, out.Reason); err != nil {
		b.log.Error("broker audit chain append failed", "call", out.CallID, "err", err)
	}
	return out
}

// park stores an approval-pending call, notifies an approver, and (when a token
// store is wired) mints a single-use resume token returned in out.ResumeToken.
func (b *Broker) park(ctx context.Context, id *agentid.Identity, c Call, out *Outcome) {
	b.mu.Lock()
	full := len(b.parked) >= maxParked
	if !full {
		b.parked[out.CallID] = &parkedCall{id: id, call: c, scope: out.Scope, ruleID: out.RuleID, reason: out.Reason, requested: time.Now().UTC()}
	}
	b.mu.Unlock()
	// Fail closed rather than let unbounded pending approvals exhaust memory.
	if full {
		out.Status, out.Reason, out.ApprovalID = StatusFailed, "too many pending approvals; try again later", ""
		b.log.Warn("broker parked-approval cap reached; refusing new require_approval call", "cap", maxParked)
		return
	}

	if b.tokens != nil {
		token := newOpaqueToken()
		bt := store.BrokerToken{JTI: hashToken(token), CallID: out.CallID, ExpiresAt: time.Now().Add(b.tokenTTL).UTC()}
		if err := b.tokens.CreateBrokerToken(ctx, &bt); err != nil {
			b.log.Error("broker resume token mint failed", "call", out.CallID, "err", err)
		} else {
			out.ResumeToken = token
		}
	}
	b.notifier.Notify(ctx, alert.Event{
		Type:   "broker.approval.pending",
		Actor:  id.AgentName,
		Detail: fmt.Sprintf("agent %q requests %s (call %s, rule %s)", id.AgentName, c.Tool, out.CallID, out.RuleID),
		Time:   time.Now().UTC(),
	})
}

// PendingApprovals lists the parked calls awaiting a human decision.
func (b *Broker) PendingApprovals() []PendingApproval {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]PendingApproval, 0, len(b.parked))
	for callID, p := range b.parked {
		out = append(out, PendingApproval{
			CallID: callID, Tool: p.call.Tool, Args: p.call.Args,
			Agent: p.id.AgentName, OnBehalfOf: p.id.OnBehalfOf, Scope: p.scope,
			RuleID: p.ruleID, Reason: p.reason, Requested: p.requested,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requested.Before(out[j].Requested) })
	return out
}

// Decide resolves a parked approval: on approve the broker executes the tool
// server-side (JIT credential injection) and stores the terminal result; on
// reject the call becomes denied. Either way the decision is recorded in the
// tamper-evident chain attributed to the human approver. Unknown/expired call ->
// ok=false.
func (b *Broker) Decide(ctx context.Context, callID, approver string, approve bool) (Outcome, bool) {
	b.mu.Lock()
	p, ok := b.parked[callID]
	if ok {
		delete(b.parked, callID)
	}
	b.mu.Unlock()
	if !ok {
		return Outcome{}, false
	}

	out := Outcome{CallID: callID, RuleID: p.ruleID, Scope: p.scope}
	if !approve {
		out.Status, out.Reason = StatusDenied, "rejected by "+approver
		b.chainApproval(ctx, p, approver, "broker.approval.denied", out)
		b.remember(out)
		return out, true
	}

	b.chainApproval(ctx, p, approver, "broker.approval.granted", out)
	tool, exists := b.registry.Get(p.call.Tool)
	if !exists {
		out.Status, out.Reason = StatusFailed, "unknown tool: "+p.call.Tool
		b.remember(out)
		_ = b.chainEvent(ctx, p.id, p.call, "broker.tool_call.failed", out, out.Reason)
		return out, true
	}
	// Record intent before the side effect, fail closed if the chain is down.
	if err := b.chainEvent(ctx, p.id, p.call, "broker.tool_call.requested", out, ""); err != nil {
		out.Status, out.Reason = StatusFailed, "audit log unavailable; call refused"
		b.remember(out)
		return out, true
	}
	// The human approval satisfies any target-level four-eyes gate for this call.
	res, err := tool.Execute(WithApproved(ctx), p.id.Principal(), p.call.Args)
	if err != nil {
		out.Status, out.Reason = StatusFailed, err.Error()
	} else {
		out.Status, out.Result = StatusExecuted, res.Data
	}
	b.remember(out)
	if err := b.chainEvent(ctx, p.id, p.call, "broker.tool_call."+string(out.Status), out, out.Reason); err != nil {
		b.log.Error("broker audit chain append failed", "call", out.CallID, "err", err)
	}
	return out, true
}

// Resume spends a single-use token and returns the stored outcome for its bound
// call, so an agent collects a post-approval result exactly once. It peeks the
// token first and refuses to spend it while the call is still pending (so an
// early resume can't burn the ticket before the result exists); the token is
// consumed only once a terminal outcome is actually returned. A used, expired,
// unknown token, or a still-pending call yields ok=false.
func (b *Broker) Resume(ctx context.Context, token string) (Outcome, bool) {
	if b.tokens == nil {
		return Outcome{}, false
	}
	jti := hashToken(token)
	callID, err := b.tokens.PeekBrokerToken(ctx, jti)
	if err != nil {
		return Outcome{}, false
	}
	out, ok := b.Lookup(callID)
	if !ok || !out.Status.terminal() {
		return Outcome{}, false // don't spend the token before the call is collectable
	}
	if _, err := b.tokens.ConsumeBrokerToken(ctx, jti); err != nil {
		return Outcome{}, false // lost the single-use race
	}
	return out, true
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

// newOpaqueToken returns a high-entropy resume token (the secret handed to the
// agent); only its hash is stored.
func newOpaqueToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return "brt_" + hex.EncodeToString(b[:])
}

// hashToken returns the hex SHA-256 of a resume token, used as its stored JTI so
// the plaintext token is never persisted.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// chainApproval records a human approval decision in the tamper-evident chain,
// attributed to the approver, over the agent's parked call.
func (b *Broker) chainApproval(ctx context.Context, p *parkedCall, approver, action string, out Outcome) {
	if _, err := b.chain.Append(ctx, store.BrokerAuditEvent{
		Actor:      approver,
		OnBehalfOf: p.id.AgentName,
		ActorChain: chainJSON(p.id.ActorChain),
		Action:     action,
		Detail:     fmt.Sprintf("tool:%s call:%s rule:%s args:%s", p.call.Tool, out.CallID, out.RuleID, argsSummary(p.call.Args)),
		Scope:      out.Scope,
	}); err != nil {
		b.log.Error("broker approval audit append failed", "call", out.CallID, "err", err)
	}
}
