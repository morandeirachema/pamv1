// Package discovery finds candidate targets by probing hosts for the management
// ports pamv1 can broker (SSH, WinRM, RDP). It only checks reachability — a TCP
// connect — and never authenticates; onboarding a discovered candidate is a
// separate, deliberate step.
package discovery

import (
	"context"
	"fmt"
	"net"
	"sort"
	"time"
)

// Candidate is a reachable host:port classified by the protocol pamv1 would use.
type Candidate struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // ssh | winrm | rdp
	OSType   string `json:"os_type"`  // linux | windows
}

// portProtocol maps a well-known management port to (protocol, os_type).
var portProtocol = map[int][2]string{
	22:   {"ssh", "linux"},
	5985: {"winrm", "windows"},
	5986: {"winrm", "windows"},
	3389: {"rdp", "windows"},
}

// DefaultPorts is the set probed when none is given.
func DefaultPorts() []int { return []int{22, 3389, 5985, 5986} }

// Scanner probes hosts for open management ports.
type Scanner struct {
	// Timeout bounds each individual TCP connect (default 1s).
	Timeout time.Duration
	// Dial lets tests inject a dialer; defaults to net.Dialer.DialContext.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// timeout returns the per-connect timeout, or 1s when unset.
func (s Scanner) timeout() time.Duration {
	if s.Timeout <= 0 {
		return time.Second
	}
	return s.Timeout
}

// dial connects to addr using the injected dialer, falling back to net.Dialer.
func (s Scanner) dial(ctx context.Context, addr string) (net.Conn, error) {
	if s.Dial != nil {
		return s.Dial(ctx, "tcp", addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}

// Scan probes every host×port combination and returns the reachable ones,
// classified. ports defaults to DefaultPorts(); unknown ports are skipped.
func (s Scanner) Scan(ctx context.Context, hosts []string, ports []int) []Candidate {
	if len(ports) == 0 {
		ports = DefaultPorts()
	}
	var out []Candidate
	for _, host := range hosts {
		for _, port := range ports {
			pp, known := portProtocol[port]
			if !known {
				continue
			}
			dctx, cancel := context.WithTimeout(ctx, s.timeout())
			conn, err := s.dial(dctx, net.JoinHostPort(host, fmt.Sprintf("%d", port)))
			cancel()
			if err != nil {
				continue
			}
			_ = conn.Close()
			out = append(out, Candidate{Host: host, Port: port, Protocol: pp[0], OSType: pp[1]})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	return out
}
