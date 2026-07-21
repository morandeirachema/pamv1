package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/analytics"
)

// maxAnalyticsWindow caps how far back the risk endpoint will score, so a large
// ?window_min= can't make a single request load the entire audit history into
// memory (an authenticated-but-bounded resource-exhaustion guard).
const maxAnalyticsWindow = 7 * 24 * time.Hour

// analyticsAlert records the last risk alert raised for an actor: the score it
// fired at and when. It drives both the "only re-alert on a worsening trend"
// dedup and the cooldown that lets a sustained/recurring incident re-alert.
type analyticsAlert struct {
	score int
	at    time.Time
}

// analyticsRisk scores the recent audit window into per-actor behavioral risk
// findings and returns them, highest score first. An optional ?min_level=
// (medium|high|critical) filters the result, and ?window_min= overrides how far
// back to score. Read-only (CapReadAudit) — an auditor reviews risk without
// changing any access.
func (s *Server) analyticsRisk(w http.ResponseWriter, r *http.Request) {
	if s.analytics == nil {
		writeError(w, http.StatusNotFound, "threat analytics is not enabled")
		return
	}
	window := s.analyticsWindow
	if q := r.URL.Query().Get("window_min"); q != "" {
		if m, err := time.ParseDuration(q + "m"); err == nil && m > 0 {
			window = m
		}
	}
	if window > maxAnalyticsWindow {
		window = maxAnalyticsWindow
	}
	since := time.Now().Add(-window)
	events, err := s.store.ExportAudit(r.Context(), since, time.Time{})
	if err != nil {
		storeError(w, err)
		return
	}
	findings := s.analytics.Score(events)
	if minLevel := r.URL.Query().Get("min_level"); minLevel != "" {
		want := analytics.LevelRank(minLevel)
		filtered := findings[:0:0]
		for _, f := range findings {
			if analytics.LevelRank(f.Level) >= want {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window_minutes": int(window.Minutes()),
		"since":          since,
		"scored_events":  len(events),
		"findings":       findings,
	})
}

// RunAnalyticsWorker runs the background threat-analytics scorer until ctx is
// cancelled: each tick it scores the recent audit window and, for any actor at
// high or critical risk it has not already alerted on at that score, appends an
// audit event, fires the alert channel, and — when auto-kill is on and the actor
// is critical — terminates their live sessions. Safe to call in a goroutine; a
// no-op when analytics or the interval is disabled.
func (s *Server) RunAnalyticsWorker(ctx context.Context, interval time.Duration) {
	if s.analytics == nil || interval <= 0 {
		return
	}
	s.log.Info("threat-analytics worker started",
		"interval", interval.String(), "window", s.analyticsWindow.String(), "auto_kill", s.analyticsAutoKill)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.analyticsPass(ctx, time.Now())
		}
	}
}

// analyticsPass performs one scoring pass as of now, alerting on and optionally
// responding to newly elevated actors. now is passed explicitly so the pass is
// testable without wall-clock dependence.
func (s *Server) analyticsPass(ctx context.Context, now time.Time) {
	since := now.Add(-s.analyticsWindow)
	events, err := s.store.ExportAudit(ctx, since, now)
	if err != nil {
		s.log.Error("analytics: audit export failed", "err", err)
		return
	}
	// Evict actors whose last alert has passed the cooldown. This bounds the map
	// (actor names from auth-failure events are attacker-controlled, so they must
	// not accumulate forever) and lets a sustained or recurring incident re-alert
	// and, if critical, be re-killed rather than being suppressed permanently.
	s.analyticsMu.Lock()
	for actor, st := range s.analyticsAlerted {
		if now.Sub(st.at) >= s.analyticsCooldown {
			delete(s.analyticsAlerted, actor)
		}
	}
	s.analyticsMu.Unlock()

	for _, f := range s.analytics.Score(events) {
		if analytics.LevelRank(f.Level) < analytics.LevelRank(analytics.LevelHigh) {
			continue // only high/critical are actionable
		}
		// Alert when the actor's risk is newly elevated — its score exceeds the last
		// one we alerted on within the cooldown (a worsening trend), or the cooldown
		// has lapsed and pruned the prior entry (a sustained/recurring incident). A
		// steady state within the cooldown is not re-alerted every pass.
		s.analyticsMu.Lock()
		prev := s.analyticsAlerted[f.Actor]
		newlyElevated := f.Score > prev.score
		if newlyElevated {
			s.analyticsAlerted[f.Actor] = analyticsAlert{score: f.Score, at: now}
		}
		s.analyticsMu.Unlock()
		if !newlyElevated {
			continue
		}

		detail := fmt.Sprintf("actor:%s score:%d level:%s signals:%s events:%d",
			f.Actor, f.Score, f.Level, f.SignalSummary(), f.Events)
		s.auditAs(ctx, "system-analytics", "analytics.risk_flagged", detail)
		s.log.Warn("threat analytics flagged an actor", "actor", f.Actor, "score", f.Score, "level", f.Level)
		s.alerter.Notify(ctx, alert.Event{
			Type: "analytics.risk_flagged", Actor: f.Actor, Detail: detail, Time: now,
		})

		// Automated response: cut off a critical-risk actor's live sessions.
		if s.analyticsAutoKill && f.Level == analytics.LevelCritical && s.sessions != nil {
			if killed := s.sessions.KillByActor(f.Actor); killed > 0 {
				resp := fmt.Sprintf("actor:%s action:kill-sessions killed:%d score:%d", f.Actor, killed, f.Score)
				s.auditAs(ctx, "system-analytics", "analytics.auto_response", resp)
				s.log.Warn("threat analytics killed sessions", "actor", f.Actor, "killed", killed)
				s.alerter.Notify(ctx, alert.Event{
					Type: "analytics.auto_response", Actor: f.Actor, Detail: resp, Time: now,
				})
			}
		}
	}
}
