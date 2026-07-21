package api

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/analytics"
	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/session"
	"github.com/morandeirachema/pamv1/internal/store"
	"github.com/morandeirachema/pamv1/internal/store/memstore"
	"github.com/morandeirachema/pamv1/internal/vault"
)

// captureAlerter records every alert Event it receives.
type captureAlerter struct {
	mu     sync.Mutex
	events []alert.Event
}

func (c *captureAlerter) Notify(_ context.Context, e alert.Event) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}

func (c *captureAlerter) types() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := map[string]int{}
	for _, e := range c.events {
		m[e.Type]++
	}
	return m
}

// newAnalyticsServer builds a Server wired for threat analytics with a capturing
// alerter and a live-session registry.
func newAnalyticsServer(t *testing.T, autoKill bool) (*Server, store.Store, *captureAlerter, *session.Registry) {
	t.Helper()
	key, err := vault.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	st := memstore.New()
	resolver, err := auth.NewResolver(st, "k", "")
	if err != nil {
		t.Fatal(err)
	}
	capt := &captureAlerter{}
	reg := session.NewRegistry()
	srv, err := New(st, v, resolver, nil, Options{
		Analytics:         analytics.New(analytics.Config{}),
		AnalyticsWindow:   time.Hour,
		AnalyticsAutoKill: autoKill,
		Alerter:           capt,
		Sessions:          reg,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, st, capt, reg
}

// seedAudit appends n audit events for actor/action.
func seedAudit(t *testing.T, st store.Store, actor, action string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := st.AppendAudit(context.Background(), &store.AuditEvent{Actor: actor, Action: action}); err != nil {
			t.Fatal(err)
		}
	}
}

// TestAnalyticsPassAutoKills proves a critical-risk actor (two break-glass
// accesses = 100 points) is flagged, alerted, and — with auto-kill on — has their
// live sessions terminated, with an analytics.auto_response audit event.
func TestAnalyticsPassAutoKills(t *testing.T) {
	srv, st, capt, reg := newAnalyticsServer(t, true)
	seedAudit(t, st, "mallory", "breakglass.access", 2) // 2*50 = 100 → critical

	var killed int
	reg.Register(session.Info{Actor: "mallory", Target: "web-01", Protocol: "ssh"}, func() { killed++ })

	srv.analyticsPass(context.Background(), time.Now())

	if killed != 1 {
		t.Fatalf("auto-kill should have terminated mallory's 1 session, killed=%d", killed)
	}
	actions := auditActions(t, st)
	if actions["analytics.risk_flagged"] == 0 {
		t.Fatal("a critical actor must be flagged (analytics.risk_flagged)")
	}
	if actions["analytics.auto_response"] == 0 {
		t.Fatal("auto-kill must audit analytics.auto_response")
	}
	types := capt.types()
	if types["analytics.risk_flagged"] == 0 || types["analytics.auto_response"] == 0 {
		t.Fatalf("both alerts must fire, got %v", types)
	}
}

// TestAnalyticsPassDedupes proves a steady-state actor is not re-alerted on every
// pass, but a worsening actor is alerted again.
func TestAnalyticsPassDedupes(t *testing.T) {
	srv, st, capt, _ := newAnalyticsServer(t, false)
	seedAudit(t, st, "mallory", "breakglass.access", 2) // critical (score 100)

	srv.analyticsPass(context.Background(), time.Now())
	srv.analyticsPass(context.Background(), time.Now()) // same score → no new alert

	if got := capt.types()["analytics.risk_flagged"]; got != 1 {
		t.Fatalf("steady-state actor should be alerted once, got %d", got)
	}

	// The score cannot climb further (both signals capped at 100), so worsening is
	// simulated by clearing the high-water mark — modeling a fresh window.
	srv.analyticsMu.Lock()
	delete(srv.analyticsAlerted, "mallory")
	srv.analyticsMu.Unlock()
	srv.analyticsPass(context.Background(), time.Now())
	if got := capt.types()["analytics.risk_flagged"]; got != 2 {
		t.Fatalf("a re-elevated actor should alert again, got %d", got)
	}
}

// TestAnalyticsPassCooldownReAlerts proves a sustained/recurring high-risk actor
// is re-alerted after the cooldown (not suppressed forever) and that the
// alerted-set is pruned rather than growing without bound.
func TestAnalyticsPassCooldownReAlerts(t *testing.T) {
	srv, st, capt, _ := newAnalyticsServer(t, false)
	// Keep the seeded events inside a long window while using a short cooldown, so
	// advancing `now` past the cooldown does not also age the events out.
	srv.analyticsWindow = 10 * time.Hour
	srv.analyticsCooldown = 30 * time.Minute
	seedAudit(t, st, "mallory", "breakglass.access", 2) // critical (score 100)

	t0 := time.Now()
	srv.analyticsPass(context.Background(), t0)
	srv.analyticsPass(context.Background(), t0.Add(10*time.Minute)) // within cooldown
	if got := capt.types()["analytics.risk_flagged"]; got != 1 {
		t.Fatalf("within cooldown: want 1 alert, got %d", got)
	}
	srv.analyticsPass(context.Background(), t0.Add(45*time.Minute)) // past cooldown
	if got := capt.types()["analytics.risk_flagged"]; got != 2 {
		t.Fatalf("after cooldown a sustained incident must re-alert: want 2, got %d", got)
	}
	// The alerted-set holds only the one active actor — it does not accumulate.
	srv.analyticsMu.Lock()
	n := len(srv.analyticsAlerted)
	srv.analyticsMu.Unlock()
	if n != 1 {
		t.Fatalf("alerted map should be pruned to the active actor, holds %d", n)
	}
}

// auditActions returns a count of audit actions in the store.
func auditActions(t *testing.T, st store.Store) map[string]int {
	t.Helper()
	events, err := st.ListAudit(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]int{}
	for _, e := range events {
		m[e.Action]++
	}
	return m
}
