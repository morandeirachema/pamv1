package api

import (
	"net"
	"net/http"
	"strings"
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

// rateLimit wraps a handler with per-IP rate limiting for auth endpoints. The
// limiter itself lives in internal/ratelimit (shared with the proxies).
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authLimiter.Allow(s.clientIP(r)) {
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
