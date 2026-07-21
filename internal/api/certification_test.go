package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// campaignItem mirrors the fields the test inspects.
type campaignItem struct {
	ID          int64  `json:"id"`
	Kind        string `json:"kind"`
	Subject     string `json:"subject"`
	SubjectType string `json:"subject_type"`
	Decision    string `json:"decision"`
}

// TestCertificationCampaign proves a campaign snapshots current access, a revoke
// decision deletes the underlying grant, certify keeps it, and a closed campaign
// refuses further decisions.
func TestCertificationCampaign(t *testing.T) {
	srv := newTestServer(t)

	// A target with a grant, and a safe with a member — the access to review.
	tc, td := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-cert", "host": "10.0.0.9", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	if tc != http.StatusCreated {
		t.Fatalf("create target: %d %s", tc, td)
	}
	targetID := int64(jsonMap(t, td)["id"].(float64))
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/targets/%d/grants", targetID), testAPIKey,
		map[string]any{"subject_type": "role", "subject": "user"}); code != http.StatusCreated {
		t.Fatalf("create grant: %d", code)
	}
	sc, sd := do(t, srv, http.MethodPost, "/api/safes", testAPIKey, map[string]any{"name": "cert-safe"})
	if sc != http.StatusCreated {
		t.Fatalf("create safe: %d %s", sc, sd)
	}
	safeID := int64(jsonMap(t, sd)["id"].(float64))
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/safes/%d/members", safeID), testAPIKey,
		map[string]any{"subject_type": "role", "subject": "auditor"}); code != http.StatusCreated {
		t.Fatalf("add safe member: %d", code)
	}

	// Create the campaign — it snapshots both access items.
	cc, cd := do(t, srv, http.MethodPost, "/api/campaigns", testAPIKey, map[string]any{"name": "Q3 review"})
	if cc != http.StatusCreated {
		t.Fatalf("create campaign: %d %s", cc, cd)
	}
	m := jsonMap(t, cd)
	if int(m["items"].(float64)) < 2 {
		t.Fatalf("campaign captured %v items, want >= 2", m["items"])
	}
	campaignID := int64(m["campaign"].(map[string]any)["id"].(float64))

	// Read the items; revoke the target grant, certify the safe member.
	_, gd := do(t, srv, http.MethodGet, fmt.Sprintf("/api/campaigns/%d", campaignID), testAPIKey, nil)
	var got struct {
		Items []campaignItem `json:"items"`
	}
	if err := json.Unmarshal(gd, &got); err != nil {
		t.Fatal(err)
	}
	var grantItem, memberItem int64
	for _, it := range got.Items {
		switch it.Kind {
		case "target_grant":
			grantItem = it.ID
		case "safe_member":
			memberItem = it.ID
		}
	}
	if grantItem == 0 || memberItem == 0 {
		t.Fatalf("expected a target_grant and a safe_member item, got %+v", got.Items)
	}

	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/campaigns/%d/items/%d/decision", campaignID, grantItem), testAPIKey,
		map[string]any{"decision": "revoke"}); code != http.StatusNoContent {
		t.Fatalf("revoke item: %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/campaigns/%d/items/%d/decision", campaignID, memberItem), testAPIKey,
		map[string]any{"decision": "certify"}); code != http.StatusNoContent {
		t.Fatalf("certify item: %d", code)
	}

	// The revoked grant is actually gone from the target.
	_, grants := do(t, srv, http.MethodGet, fmt.Sprintf("/api/targets/%d/grants", targetID), testAPIKey, nil)
	var gs []map[string]any
	if err := json.Unmarshal(grants, &gs); err != nil {
		t.Fatal(err)
	}
	if len(gs) != 0 {
		t.Fatalf("revoke did not delete the underlying grant: %s", grants)
	}
	// The certified safe member is retained.
	_, members := do(t, srv, http.MethodGet, fmt.Sprintf("/api/safes/%d/members", safeID), testAPIKey, nil)
	var ms []map[string]any
	if err := json.Unmarshal(members, &ms); err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("certified safe member should be retained, got %s", members)
	}

	// Close the campaign; further decisions are refused.
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/campaigns/%d/close", campaignID), testAPIKey, nil); code != http.StatusNoContent {
		t.Fatalf("close campaign: %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, fmt.Sprintf("/api/campaigns/%d/items/%d/decision", campaignID, memberItem), testAPIKey,
		map[string]any{"decision": "revoke"}); code != http.StatusConflict {
		t.Fatalf("decision on a closed campaign: want 409, got %d", code)
	}
}

// TestCertificationAuthz proves campaign management needs CapManageUsers and
// reading needs CapReadAudit.
func TestCertificationAuthz(t *testing.T) {
	srv := newTestServer(t)
	userTok := seedUser(t, srv, "bob", "user")       // no CapManageUsers, no CapReadAudit
	auditorTok := seedUser(t, srv, "amy", "auditor") // CapReadAudit, no CapManageUsers

	if code, _ := do(t, srv, http.MethodPost, "/api/campaigns", userTok, map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Fatalf("user create campaign: want 403, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/campaigns", userTok, nil); code != http.StatusForbidden {
		t.Fatalf("user list campaigns: want 403, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodGet, "/api/campaigns", auditorTok, nil); code != http.StatusOK {
		t.Fatalf("auditor list campaigns: want 200, got %d", code)
	}
	if code, _ := do(t, srv, http.MethodPost, "/api/campaigns", auditorTok, map[string]any{"name": "x"}); code != http.StatusForbidden {
		t.Fatalf("auditor create campaign: want 403, got %d", code)
	}
}
