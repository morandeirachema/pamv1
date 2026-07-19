package api_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestReadyzAndHealthz(t *testing.T) {
	srv := newTestServer(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		status, body := do(t, srv, http.MethodGet, path, "", nil)
		if status != http.StatusOK {
			t.Fatalf("%s: status %d body %s", path, status, body)
		}
	}
}

func TestMetricsEndpoint(t *testing.T) {
	srv := newTestServer(t)
	// Generate traffic: a couple of authenticated requests (audited) and a 401.
	do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	do(t, srv, http.MethodGet, "/api/targets", "wrong-key", nil) // 401

	status, body := do(t, srv, http.MethodGet, "/metrics", "", nil)
	if status != http.StatusOK {
		t.Fatalf("metrics: status %d", status)
	}
	out := string(body)
	for _, want := range []string{
		"pam_http_requests_total",
		"pam_audit_events_total",
		"pam_auth_failures_total",
		"pam_active_sessions",
		"# TYPE pam_http_requests_total counter",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	// The 401 must have been counted as an auth failure (status label present).
	if !strings.Contains(out, `status="401"`) {
		t.Errorf("expected a 401 in the request counter:\n%s", out)
	}
}
