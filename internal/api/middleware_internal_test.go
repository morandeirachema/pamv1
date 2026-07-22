package api

import (
	"net/http"
	"testing"
)

// TestClientIPTrustedProxy verifies the rate-limiter key resolution: RemoteAddr
// when no proxy is trusted (so a spoofed XFF can't evade throttling), and the
// correct client entry from X-Forwarded-For when N hops are trusted.
func TestClientIPTrustedProxy(t *testing.T) {
	mk := func(remote, xff string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return r
	}
	cases := []struct {
		name string
		hops int
		req  *http.Request
		want string
	}{
		{"no-proxy-uses-remoteaddr", 0, mk("203.0.113.9:5555", "1.2.3.4"), "203.0.113.9"},
		{"no-proxy-ignores-spoofed-xff", 0, mk("10.0.0.1:40000", "9.9.9.9, 8.8.8.8"), "10.0.0.1"},
		{"one-hop-takes-rightmost", 1, mk("10.0.0.1:40000", "203.0.113.7, 10.0.0.9"), "10.0.0.9"},
		{"two-hops-walks-left", 2, mk("10.0.0.1:40000", "203.0.113.7, 172.16.0.1, 10.0.0.9"), "172.16.0.1"},
		{"short-chain-clamps", 3, mk("10.0.0.1:40000", "203.0.113.7"), "203.0.113.7"},
		{"trusted-but-no-xff-falls-back", 1, mk("10.0.0.1:40000", ""), "10.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{trustedProxyHops: tc.hops}
			if got := s.clientIP(tc.req); got != tc.want {
				t.Fatalf("clientIP(hops=%d) = %q, want %q", tc.hops, got, tc.want)
			}
		})
	}
}
