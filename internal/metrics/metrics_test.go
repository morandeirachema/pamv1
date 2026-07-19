package metrics

import (
	"strings"
	"testing"
)

// TestWritePrometheus checks the exposition output for each recorded metric.
func TestWritePrometheus(t *testing.T) {
	m := New()
	m.HTTPRequest(200)
	m.HTTPRequest(200)
	m.HTTPRequest(403) // also bumps auth failures
	m.Audit()
	m.BreakGlass()
	m.Rotation()
	m.SetActiveSessionsSource(func() int { return 3 })

	var sb strings.Builder
	m.WritePrometheus(&sb)
	out := sb.String()

	for _, want := range []string{
		`pam_http_requests_total{status="200"} 2`,
		`pam_http_requests_total{status="403"} 1`,
		"pam_auth_failures_total 1",
		"pam_audit_events_total 1",
		"pam_breakglass_access_total 1",
		"pam_credential_rotations_total 1",
		"pam_active_sessions 3",
		"# TYPE pam_http_requests_total counter",
		"# TYPE pam_active_sessions gauge",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q\n---\n%s", want, out)
		}
	}
}

// TestActiveSessionsDefaultsZero checks the gauge reads 0 when no source is set.
func TestActiveSessionsDefaultsZero(t *testing.T) {
	m := New()
	var sb strings.Builder
	m.WritePrometheus(&sb)
	if !strings.Contains(sb.String(), "pam_active_sessions 0") {
		t.Fatal("active sessions should default to 0 without a source")
	}
}
