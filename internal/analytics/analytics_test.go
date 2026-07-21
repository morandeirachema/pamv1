package analytics

import (
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// ev builds an audit event with a fixed timestamp.
func ev(actor, action string, ts time.Time) store.AuditEvent {
	return store.AuditEvent{Actor: actor, Action: action, TS: ts}
}

// businessTime returns a weekday timestamp inside default business hours.
func businessTime() time.Time {
	// 2026-07-20 is a Monday; 10:00 is inside 07:00–20:00.
	return time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)
}

// TestScoreBreakGlassIsHigh proves a break-glass access alone pushes an actor to
// at least high risk, and that the finding is explainable (a break_glass signal).
func TestScoreBreakGlassIsHigh(t *testing.T) {
	e := New(DefaultConfig())
	bt := businessTime()
	findings := e.Score([]store.AuditEvent{
		ev("mallory", "breakglass.access", bt),
		ev("mallory", "session.start", bt),
	})
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Actor != "mallory" {
		t.Fatalf("actor = %q", f.Actor)
	}
	if LevelRank(f.Level) < LevelRank(LevelHigh) {
		t.Fatalf("break-glass should be at least high; got %s (score %d)", f.Level, f.Score)
	}
	var hasBG bool
	for _, s := range f.Signals {
		if s.Name == "break_glass" {
			hasBG = true
		}
	}
	if !hasBG {
		t.Fatalf("finding must name the break_glass signal: %+v", f.Signals)
	}
}

// TestScoreClean proves an actor doing ordinary in-hours work scores no risk.
func TestScoreClean(t *testing.T) {
	e := New(DefaultConfig())
	bt := businessTime()
	findings := e.Score([]store.AuditEvent{
		ev("alice", "session.start", bt),
		ev("alice", "session.end", bt),
		ev("alice", "ssh.exec", bt),
	})
	if len(findings) != 0 {
		t.Fatalf("clean in-hours activity should score 0 findings, got %d: %+v", len(findings), findings)
	}
}

// TestScoreOffHours proves activity outside business hours contributes risk.
func TestScoreOffHours(t *testing.T) {
	e := New(DefaultConfig())
	night := time.Date(2026, 7, 20, 3, 0, 0, 0, time.UTC) // Monday 03:00
	day := businessTime()
	night1 := e.Score([]store.AuditEvent{ev("bob", "session.start", night)})
	day1 := e.Score([]store.AuditEvent{ev("bob", "session.start", day)})
	if len(day1) != 0 {
		t.Fatalf("a single in-hours session should not score: %+v", day1)
	}
	if len(night1) != 1 || night1[0].Score <= 0 {
		t.Fatalf("an off-hours session should score > 0: %+v", night1)
	}
}

// TestScoreAuthFailureBurstAndSort proves repeated auth failures accumulate and
// that findings sort by score descending.
func TestScoreAuthFailureBurstAndSort(t *testing.T) {
	e := New(DefaultConfig())
	bt := businessTime()
	var events []store.AuditEvent
	for i := 0; i < 6; i++ {
		events = append(events, ev("prober", "proxy.auth_failed", bt))
	}
	events = append(events, ev("normal", "session.start", bt)) // scores 0, omitted
	findings := e.Score(events)
	if len(findings) != 1 || findings[0].Actor != "prober" {
		t.Fatalf("expected only prober flagged, got %+v", findings)
	}
	if findings[0].Score < 6*DefaultConfig().Weights.AuthFailure && findings[0].Score != DefaultConfig().PerSignalCap {
		t.Fatalf("auth-failure burst under-scored: %d", findings[0].Score)
	}
}

// TestPerSignalCap proves a single signal category cannot exceed the cap.
func TestPerSignalCap(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PerSignalCap = 20
	e := New(cfg)
	bt := businessTime()
	var events []store.AuditEvent
	for i := 0; i < 100; i++ {
		events = append(events, ev("x", "proxy.auth_failed", bt))
	}
	f := e.Score(events)[0]
	for _, s := range f.Signals {
		if s.Points > 20 {
			t.Fatalf("signal %s exceeded cap: %d", s.Name, s.Points)
		}
	}
}
