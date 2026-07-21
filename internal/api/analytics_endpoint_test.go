package api_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/analytics"
	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/store"
)

// TestAnalyticsRiskEndpoint proves GET /api/analytics/risk scores the audit trail
// and enforces CapReadAudit (an auditor may read it, a plain user may not).
func TestAnalyticsRiskEndpoint(t *testing.T) {
	srv, st := newTestServerOpts(t, nil, api.Options{Analytics: analytics.New(analytics.Config{})})

	// Two break-glass accesses for one actor → a critical finding.
	for i := 0; i < 2; i++ {
		if err := st.AppendAudit(context.Background(), &store.AuditEvent{Actor: "mallory", Action: "breakglass.access"}); err != nil {
			t.Fatal(err)
		}
	}

	status, data := do(t, srv, http.MethodGet, "/api/analytics/risk?min_level=high", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("risk endpoint: %d %s", status, data)
	}
	m := jsonMap(t, data)
	findings, _ := m["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("want 1 high+ finding, got %d: %s", len(findings), data)
	}
	f := findings[0].(map[string]any)
	if f["actor"] != "mallory" || f["level"] != "critical" {
		t.Fatalf("finding = %v, want mallory/critical", f)
	}

	// RBAC: an auditor may read, a plain user may not.
	auditorTok := seedUser(t, srv, "theo", "auditor")
	if s, _ := do(t, srv, http.MethodGet, "/api/analytics/risk", auditorTok, nil); s != http.StatusOK {
		t.Fatalf("auditor should read analytics, got %d", s)
	}
	userTok := seedUser(t, srv, "uma", "user")
	if s, _ := do(t, srv, http.MethodGet, "/api/analytics/risk", userTok, nil); s != http.StatusForbidden {
		t.Fatalf("a plain user must not read analytics, got %d", s)
	}
}
