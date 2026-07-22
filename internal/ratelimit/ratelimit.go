// Package ratelimit provides a small per-key fixed-window rate limiter shared by
// the API auth endpoints and the SSH/PostgreSQL proxies, so both throttle online
// guessing with identical, tested logic instead of two near-duplicate copies.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter allows perMin events per key per minute (a fixed window). It is safe for
// concurrent use and periodically evicts expired keys so the map can't grow
// unbounded under source-IP churn (e.g. an attacker cycling an IPv6 /64).
type Limiter struct {
	perMin    int
	mu        sync.Mutex
	hits      map[string]*window
	nextSweep time.Time
	clock     func() time.Time // nil ⇒ time.Now; injectable for tests
}

type window struct {
	count int
	reset time.Time
}

// New builds a limiter allowing perMin events per key per minute. perMin <= 0
// disables limiting (Allow always returns true).
func New(perMin int) *Limiter {
	return &Limiter{perMin: perMin, hits: make(map[string]*window)}
}

// Allow reports whether an event for key fits within the current minute's budget,
// opening or advancing the window and incrementing the count. A nil limiter or
// perMin <= 0 never throttles.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.perMin <= 0 {
		return true
	}
	now := time.Now
	if l.clock != nil {
		now = l.clock
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	t := now()
	if t.After(l.nextSweep) {
		for k, w := range l.hits {
			if t.After(w.reset) {
				delete(l.hits, k)
			}
		}
		l.nextSweep = t.Add(time.Minute)
	}
	w := l.hits[key]
	if w == nil || t.After(w.reset) {
		l.hits[key] = &window{count: 1, reset: t.Add(time.Minute)}
		return true
	}
	if w.count >= l.perMin {
		return false
	}
	w.count++
	return true
}

// SetClock injects a time source (for tests); passing nil restores time.Now.
func (l *Limiter) SetClock(f func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clock = f
}
