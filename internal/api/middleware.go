package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// withSecurityHeaders sets baseline hardening headers on every response.
// (The portal sets its own Content-Security-Policy.)
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// rateLimiter is a per-key fixed-window limiter (keyed by client IP). It guards
// authentication endpoints against brute force.
type rateLimiter struct {
	perMin    int
	mu        sync.Mutex
	hits      map[string]*window
	nextSweep time.Time
}

type window struct {
	count int
	reset time.Time
}

// newRateLimiter builds a fixed-window limiter allowing perMin requests per key
// per minute; perMin <= 0 disables limiting.
func newRateLimiter(perMin int) *rateLimiter {
	return &rateLimiter{perMin: perMin, hits: make(map[string]*window)}
}

// allow reports whether a request for key fits within the current minute's
// budget, opening or advancing the window and incrementing the count as needed.
func (rl *rateLimiter) allow(key string) bool {
	if rl.perMin <= 0 {
		return true // disabled
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	// Periodically evict expired windows so the map can't grow unbounded — an
	// attacker cycling source IPs (e.g. an IPv6 /64) against the public auth
	// endpoints would otherwise mint one permanent entry per address.
	if now.After(rl.nextSweep) {
		for k, wv := range rl.hits {
			if now.After(wv.reset) {
				delete(rl.hits, k)
			}
		}
		rl.nextSweep = now.Add(time.Minute)
	}
	w := rl.hits[key]
	if w == nil || now.After(w.reset) {
		rl.hits[key] = &window{count: 1, reset: now.Add(time.Minute)}
		return true
	}
	if w.count >= rl.perMin {
		return false
	}
	w.count++
	return true
}

// rateLimit wraps a handler with per-IP rate limiting for auth endpoints.
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authLimiter.allow(s.clientIP(r)) {
			s.log.Warn("rate limited", "path", r.URL.Path, "remote", r.RemoteAddr)
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many attempts; try again shortly")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP resolves the address the rate limiter keys on. With no trusted proxy
// (trustedProxyHops==0) it uses the direct RemoteAddr, so a spoofed
// X-Forwarded-For can never evade throttling. With N trusted hops it takes the
// (N+1)-th address from the right of X-Forwarded-For — the client as seen by the
// outermost hop WE control — so per-IP throttling still works behind a
// TLS-terminating reverse proxy without trusting attacker-supplied header entries.
func (s *Server) clientIP(r *http.Request) string {
	direct := remoteHost(r.RemoteAddr)
	if s.trustedProxyHops <= 0 {
		return direct
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return direct
	}
	parts := strings.Split(xff, ",")
	// The rightmost entry is the address the nearest proxy saw; walk left past the
	// hops we trust to reach the real client. Clamp to the first entry if the chain
	// is shorter than the configured trust depth (a truncated/short header).
	idx := len(parts) - s.trustedProxyHops
	if idx < 0 {
		idx = 0
	}
	if idx > len(parts)-1 {
		idx = len(parts) - 1
	}
	if ip := strings.TrimSpace(parts[idx]); ip != "" {
		return ip
	}
	return direct
}

// remoteHost extracts the host portion of a remote address, falling back to the
// raw value when it has no port.
func remoteHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
