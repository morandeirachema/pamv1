package api

import (
	"net"
	"net/http"
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
	perMin int
	mu     sync.Mutex
	hits   map[string]*window
}

type window struct {
	count int
	reset time.Time
}

func newRateLimiter(perMin int) *rateLimiter {
	return &rateLimiter{perMin: perMin, hits: make(map[string]*window)}
}

func (rl *rateLimiter) allow(key string) bool {
	if rl.perMin <= 0 {
		return true // disabled
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
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
		if !s.authLimiter.allow(clientIP(r)) {
			s.log.Warn("rate limited", "path", r.URL.Path, "remote", r.RemoteAddr)
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many attempts; try again shortly")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
