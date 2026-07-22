package proxy

import (
	"net"
	"sync"
	"time"
)

// authRateLimiter is a per-source-IP fixed-window limiter guarding the SSH and
// PostgreSQL proxy authentication paths against online guessing of the
// operator-chosen PAM key. It mirrors the API server's auth limiter; the proxies
// are otherwise an unthrottled password oracle.
type authRateLimiter struct {
	perMin    int
	mu        sync.Mutex
	hits      map[string]*rlWindow
	nextSweep time.Time
	now       func() time.Time // injectable clock for tests; nil = time.Now
}

type rlWindow struct {
	count int
	reset time.Time
}

// newAuthRateLimiter builds a limiter allowing perMin attempts per source IP per
// minute; perMin <= 0 disables limiting (allow always returns true).
func newAuthRateLimiter(perMin int) *authRateLimiter {
	return &authRateLimiter{perMin: perMin, hits: make(map[string]*rlWindow)}
}

// allow reports whether another auth attempt from key (a source IP) fits within
// the current minute's budget, advancing the window and evicting stale entries.
func (rl *authRateLimiter) allow(key string) bool {
	if rl == nil || rl.perMin <= 0 {
		return true
	}
	clock := rl.now
	if clock == nil {
		clock = time.Now
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := clock()
	if now.After(rl.nextSweep) {
		for k, w := range rl.hits {
			if now.After(w.reset) {
				delete(rl.hits, k)
			}
		}
		rl.nextSweep = now.Add(time.Minute)
	}
	w := rl.hits[key]
	if w == nil || now.After(w.reset) {
		rl.hits[key] = &rlWindow{count: 1, reset: now.Add(time.Minute)}
		return true
	}
	if w.count >= rl.perMin {
		return false
	}
	w.count++
	return true
}

// remoteHost extracts the host portion of a net.Addr, for limiter keying.
func remoteHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}
