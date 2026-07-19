// Package metrics exposes a tiny, dependency-free Prometheus text-format
// collector for pamv1. It tracks a deliberately small, low-sensitivity set of
// counters and gauges (request counts by status, audit volume, break-glass use,
// active sessions) — enough for dashboards and alerting without pulling in a
// metrics client library or leaking secret material.
package metrics

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// Metrics is a concurrency-safe collector.
type Metrics struct {
	mu           sync.Mutex
	httpRequests map[int]uint64 // status code -> count
	auditTotal   uint64
	breakglass   uint64
	authFailures uint64
	rotations    uint64

	// activeSessions supplies the current live-session count (0 if unset).
	activeSessions func() int
}

// New returns an empty collector.
func New() *Metrics {
	return &Metrics{httpRequests: make(map[int]uint64)}
}

// HTTPRequest records one served request with the given status code.
func (m *Metrics) HTTPRequest(status int) {
	m.mu.Lock()
	m.httpRequests[status]++
	if status == 401 || status == 403 {
		m.authFailures++
	}
	m.mu.Unlock()
}

// Audit records one appended audit event.
func (m *Metrics) Audit() { m.inc(&m.auditTotal) }

// BreakGlass records one break-glass access.
func (m *Metrics) BreakGlass() { m.inc(&m.breakglass) }

// Rotation records one credential rotation.
func (m *Metrics) Rotation() { m.inc(&m.rotations) }

// inc atomically increments the given counter under the lock.
func (m *Metrics) inc(p *uint64) {
	m.mu.Lock()
	*p++
	m.mu.Unlock()
}

// SetActiveSessionsSource wires the live-session gauge to a source (e.g. the
// session registry's List length).
func (m *Metrics) SetActiveSessionsSource(fn func() int) {
	m.mu.Lock()
	m.activeSessions = fn
	m.mu.Unlock()
}

// WritePrometheus renders the current values in Prometheus text exposition
// format (version 0.0.4).
func (m *Metrics) WritePrometheus(w io.Writer) {
	m.mu.Lock()
	// Snapshot under the lock; write outside it.
	statuses := make([]int, 0, len(m.httpRequests))
	for s := range m.httpRequests {
		statuses = append(statuses, s)
	}
	sort.Ints(statuses)
	reqs := make(map[int]uint64, len(m.httpRequests))
	for s, v := range m.httpRequests {
		reqs[s] = v
	}
	auditTotal, breakglass, authFailures, rotations := m.auditTotal, m.breakglass, m.authFailures, m.rotations
	active := 0
	if m.activeSessions != nil {
		active = m.activeSessions()
	}
	m.mu.Unlock()

	fmt.Fprintln(w, "# HELP pam_http_requests_total Total HTTP requests handled, by status code.")
	fmt.Fprintln(w, "# TYPE pam_http_requests_total counter")
	for _, s := range statuses {
		fmt.Fprintf(w, "pam_http_requests_total{status=\"%d\"} %d\n", s, reqs[s])
	}

	writeCounter(w, "pam_audit_events_total", "Total audit events appended.", auditTotal)
	writeCounter(w, "pam_breakglass_access_total", "Total break-glass accesses.", breakglass)
	writeCounter(w, "pam_auth_failures_total", "Total 401/403 responses.", authFailures)
	writeCounter(w, "pam_credential_rotations_total", "Total credential rotations.", rotations)

	fmt.Fprintln(w, "# HELP pam_active_sessions Current live proxied sessions.")
	fmt.Fprintln(w, "# TYPE pam_active_sessions gauge")
	fmt.Fprintf(w, "pam_active_sessions %d\n", active)
}

// writeCounter emits a single Prometheus counter (HELP, TYPE and value lines).
func writeCounter(w io.Writer, name, help string, v uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	fmt.Fprintf(w, "%s %d\n", name, v)
}
