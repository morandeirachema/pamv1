package proxy

import "net"

// remoteHost extracts the host portion of a net.Addr, for keying the shared
// auth rate limiter (internal/ratelimit) by source IP.
func remoteHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}
