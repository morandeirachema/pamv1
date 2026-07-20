package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/agentid"
	"github.com/morandeirachema/pamv1/internal/auditchain"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/policy"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
)

// failAppendStore wraps a real memstore but makes broker-audit appends fail, so a
// test can simulate the audit chain being unavailable.
type failAppendStore struct{ *memstore.Memstore }

func (failAppendStore) AppendBrokerAudit(context.Context, *store.BrokerAuditEvent) error {
	return errors.New("audit store unavailable")
}

// recordingTool notes whether Execute ran.
type recordingTool struct{ ran *bool }

func (recordingTool) Name() string                   { return "t" }
func (recordingTool) Description() string            { return "test tool" }
func (recordingTool) InputSchema() map[string]string { return nil }
func (recordingTool) Capability() auth.Capability    { return auth.CapCallTool }
func (t recordingTool) Execute(context.Context, *auth.Principal, Args) (Result, error) {
	*t.ran = true
	return Result{Data: map[string]any{"ok": true}}, nil
}

func newTestChain(t *testing.T, st store.Store) *auditchain.Chain {
	t.Helper()
	key := make([]byte, auditchain.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := auditchain.New(context.Background(), key, priv, st)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func allowEngine(t *testing.T) *policy.Engine {
	t.Helper()
	e, err := policy.Load(strings.NewReader("rules:\n  - id: a\n    tool: t\n    effect: allow\n"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestProcessCallFailsClosedWhenAuditUnavailable proves a side-effecting call is
// NOT executed if its pre-execution audit record cannot be written to the chain —
// an executed action must never be missing from the authoritative log.
func TestProcessCallFailsClosedWhenAuditUnavailable(t *testing.T) {
	chain := newTestChain(t, failAppendStore{memstore.New()})
	reg := NewRegistry()
	ran := false
	reg.Register(recordingTool{ran: &ran})
	b := New(allowEngine(t), reg, chain)

	out := b.ProcessCall(context.Background(), &agentid.Identity{AgentName: "bot"}, Call{Tool: "t"})
	if out.Status != StatusFailed {
		t.Fatalf("status = %q, want failed when the audit chain is unavailable", out.Status)
	}
	if ran {
		t.Fatal("tool executed despite the audit chain being unavailable — must fail closed")
	}
}

// TestProcessCallExecutesWhenAuditWorks is the positive control: with a working
// chain the same allow rule runs the tool.
func TestProcessCallExecutesWhenAuditWorks(t *testing.T) {
	chain := newTestChain(t, memstore.New())
	reg := NewRegistry()
	ran := false
	reg.Register(recordingTool{ran: &ran})
	b := New(allowEngine(t), reg, chain)

	out := b.ProcessCall(context.Background(), &agentid.Identity{AgentName: "bot"}, Call{Tool: "t"})
	if out.Status != StatusExecuted || !ran {
		t.Fatalf("status=%q ran=%v, want executed/true", out.Status, ran)
	}
}
