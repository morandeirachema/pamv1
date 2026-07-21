// Package analytics is pamv1's privileged threat-analytics engine: a behavioral
// risk scorer over the audit trail (the CyberArk PTA / Wallix analytics gap).
// It is deliberately deterministic and explainable — every point of an actor's
// risk score traces back to a named signal (break-glass use, blocked commands,
// authentication-failure bursts, off-hours activity, decryption failures,
// session velocity) — rather than an opaque ML model, so a reviewer can defend
// each finding. The API surfaces the scores and a background worker alerts on
// and optionally responds to high-risk actors.
package analytics

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/store"
)

// Risk levels, from an actor's total score via the Config thresholds.
const (
	LevelLow      = "low"
	LevelMedium   = "medium"
	LevelHigh     = "high"
	LevelCritical = "critical"
)

// Weights assigns a per-occurrence point value to each behavioral signal. Each
// signal's total contribution is capped (see PerSignalCap) so one noisy category
// cannot alone peg an actor to critical.
type Weights struct {
	BreakGlass     int // any break-glass access/unseal — inherently elevated
	CommandBlocked int // a command the guard refused (attempted dangerous action)
	AuthFailure    int // failed auth / denied authz / denied session (probing)
	OffHours       int // sensitive action outside business hours / on a weekend
	DecryptFailure int // a credential decrypt failed (tampering / AAD mismatch)
	VelocityOver   int // per session past the velocity threshold (burst of access)
}

// Config tunes the scorer: signal weights, per-signal caps, level thresholds,
// business hours (local time) and the session-velocity threshold.
type Config struct {
	Weights       Weights
	PerSignalCap  int // max points any single signal category may contribute
	MediumScore   int // total score at/above which an actor is "medium"
	HighScore     int // …"high"
	CriticalScore int // …"critical"
	BusinessStart int // first business hour, inclusive [0,23]
	BusinessEnd   int // first non-business hour, exclusive [1,24]
	VelocityLimit int // sessions within the window before velocity counts as risk
}

// DefaultConfig returns sensible defaults: business hours 07:00–20:00 Mon–Fri,
// break-glass and blocked commands weigh heaviest, medium/high/critical at
// 25/50/80 points. A single break-glass access alone reaches "high" (it is the
// emergency path and should always surface); two reach "critical".
func DefaultConfig() Config {
	return Config{
		Weights: Weights{
			BreakGlass:     50,
			CommandBlocked: 25,
			AuthFailure:    8,
			OffHours:       5,
			DecryptFailure: 15,
			VelocityOver:   4,
		},
		PerSignalCap:  100,
		MediumScore:   25,
		HighScore:     50,
		CriticalScore: 80,
		BusinessStart: 7,
		BusinessEnd:   20,
		VelocityLimit: 8,
	}
}

// Signal is one named contributor to an actor's risk score.
type Signal struct {
	Name   string `json:"name"`
	Count  int    `json:"count"`
	Points int    `json:"points"`
}

// Finding is the aggregate risk assessment for one actor over the scored window.
type Finding struct {
	Actor   string    `json:"actor"`
	Score   int       `json:"score"`
	Level   string    `json:"level"`
	Signals []Signal  `json:"signals"`
	Events  int       `json:"events"`
	FirstTS time.Time `json:"first_ts"`
	LastTS  time.Time `json:"last_ts"`
}

// SignalSummary renders the finding's signals as a compact "name=points" list
// for an audit detail or alert body.
func (f Finding) SignalSummary() string {
	parts := make([]string, 0, len(f.Signals))
	for _, s := range f.Signals {
		parts = append(parts, fmt.Sprintf("%s=%d", s.Name, s.Points))
	}
	return strings.Join(parts, ",")
}

// Engine scores audit events into per-actor risk findings.
type Engine struct {
	cfg Config
}

// New builds an Engine with cfg, filling any zero threshold/hours field from the
// defaults so a partially-specified config is still usable.
func New(cfg Config) *Engine {
	d := DefaultConfig()
	if cfg.PerSignalCap <= 0 {
		cfg.PerSignalCap = d.PerSignalCap
	}
	if cfg.MediumScore <= 0 {
		cfg.MediumScore = d.MediumScore
	}
	if cfg.HighScore <= 0 {
		cfg.HighScore = d.HighScore
	}
	if cfg.CriticalScore <= 0 {
		cfg.CriticalScore = d.CriticalScore
	}
	if cfg.BusinessEnd <= 0 || cfg.BusinessEnd > 24 {
		cfg.BusinessStart, cfg.BusinessEnd = d.BusinessStart, d.BusinessEnd
	}
	if cfg.VelocityLimit <= 0 {
		cfg.VelocityLimit = d.VelocityLimit
	}
	if cfg.Weights == (Weights{}) {
		cfg.Weights = d.Weights
	}
	return &Engine{cfg: cfg}
}

// signal action classification.
var (
	breakGlassActions = map[string]bool{"breakglass.access": true, "breakglass.unseal": true}
	cmdBlockedActions = map[string]bool{"command.blocked": true}
	authFailActions   = map[string]bool{
		"proxy.auth_failed": true, "login.failed": true, "authz.denied": true,
		"session.denied": true, "access.denied": true, "db.session.denied": true,
	}
	decryptActions = map[string]bool{"credential.decrypt_failed": true}
	// sensitive "activity" actions that count toward off-hours and velocity.
	activityActions = map[string]bool{
		"session.start": true, "db.session.start": true, "session.cert_issued": true,
		"ssh.exec": true, "winrm.run": true, "rdp.connect": true,
	}
)

// perActor accumulates raw signal counts for one actor while scanning events.
type perActor struct {
	counts  map[string]int
	events  int
	firstTS time.Time
	lastTS  time.Time
}

// Score computes a risk finding per actor from events (the caller chooses the
// window). It is a pure function of its inputs — no clock, no I/O — so a given
// event set always yields the same findings. Findings are returned sorted by
// score descending; actors with a zero score are omitted.
func (e *Engine) Score(events []store.AuditEvent) []Finding {
	byActor := map[string]*perActor{}
	for _, ev := range events {
		if ev.Actor == "" {
			continue
		}
		pa := byActor[ev.Actor]
		if pa == nil {
			pa = &perActor{counts: map[string]int{}, firstTS: ev.TS, lastTS: ev.TS}
			byActor[ev.Actor] = pa
		}
		pa.events++
		if ev.TS.Before(pa.firstTS) {
			pa.firstTS = ev.TS
		}
		if ev.TS.After(pa.lastTS) {
			pa.lastTS = ev.TS
		}
		switch {
		case breakGlassActions[ev.Action]:
			pa.counts["break_glass"]++
		case cmdBlockedActions[ev.Action]:
			pa.counts["command_blocked"]++
		case authFailActions[ev.Action]:
			pa.counts["auth_failure"]++
		case decryptActions[ev.Action]:
			pa.counts["decrypt_failure"]++
		}
		if activityActions[ev.Action] {
			pa.counts["activity"]++
			if e.offHours(ev.TS) {
				pa.counts["off_hours"]++
			}
		}
	}

	findings := make([]Finding, 0, len(byActor))
	for actor, pa := range byActor {
		f := e.finding(actor, pa)
		if f.Score > 0 {
			findings = append(findings, f)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Score != findings[j].Score {
			return findings[i].Score > findings[j].Score
		}
		return findings[i].Actor < findings[j].Actor
	})
	return findings
}

// finding turns one actor's raw counts into a scored, leveled Finding.
func (e *Engine) finding(actor string, pa *perActor) Finding {
	w := e.cfg.Weights
	f := Finding{Actor: actor, Events: pa.events, FirstTS: pa.firstTS, LastTS: pa.lastTS}
	add := func(name string, count, weight int) {
		if count <= 0 || weight <= 0 {
			return
		}
		pts := count * weight
		if pts > e.cfg.PerSignalCap {
			pts = e.cfg.PerSignalCap
		}
		f.Signals = append(f.Signals, Signal{Name: name, Count: count, Points: pts})
		f.Score += pts
	}
	add("break_glass", pa.counts["break_glass"], w.BreakGlass)
	add("command_blocked", pa.counts["command_blocked"], w.CommandBlocked)
	add("auth_failure", pa.counts["auth_failure"], w.AuthFailure)
	add("off_hours", pa.counts["off_hours"], w.OffHours)
	add("decrypt_failure", pa.counts["decrypt_failure"], w.DecryptFailure)
	// Velocity: only the sessions beyond the limit contribute.
	if over := pa.counts["activity"] - e.cfg.VelocityLimit; over > 0 {
		add("high_velocity", over, w.VelocityOver)
	}
	f.Level = e.level(f.Score)
	// Present the strongest signals first.
	sort.SliceStable(f.Signals, func(i, j int) bool { return f.Signals[i].Points > f.Signals[j].Points })
	return f
}

// level maps a total score to a risk level via the configured thresholds.
func (e *Engine) level(score int) string {
	switch {
	case score >= e.cfg.CriticalScore:
		return LevelCritical
	case score >= e.cfg.HighScore:
		return LevelHigh
	case score >= e.cfg.MediumScore:
		return LevelMedium
	default:
		return LevelLow
	}
}

// offHours reports whether ts falls outside business hours (in ts's own
// location) or on a weekend.
func (e *Engine) offHours(ts time.Time) bool {
	if wd := ts.Weekday(); wd == time.Saturday || wd == time.Sunday {
		return true
	}
	h := ts.Hour()
	return h < e.cfg.BusinessStart || h >= e.cfg.BusinessEnd
}

// LevelRank returns an ordinal for a level so callers can filter "high and
// above". An unknown level ranks 0 (low).
func LevelRank(level string) int {
	switch level {
	case LevelCritical:
		return 3
	case LevelHigh:
		return 2
	case LevelMedium:
		return 1
	default:
		return 0
	}
}
