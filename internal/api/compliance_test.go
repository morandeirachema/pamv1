package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// getWithKey performs a GET and returns the full response for header inspection.
func getWithKey(t *testing.T, srv *httptest.Server, path, apiKey string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-API-Key", apiKey)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

// TestAuditExportJSON verifies the JSON export carries a matching SHA-256 in both
// body and header and is deterministic over a fixed time window.
func TestAuditExportJSON(t *testing.T) {
	srv := newTestServer(t)
	// Generate a couple of audit events.
	do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	seedUser(t, srv, "alice", "auditor")

	resp, body := getWithKey(t, srv, "/api/audit/export", testAPIKey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("missing attachment disposition: %q", resp.Header.Get("Content-Disposition"))
	}
	hdrDigest := resp.Header.Get("X-PAM-Export-SHA256")
	if hdrDigest == "" {
		t.Fatal("missing X-PAM-Export-SHA256 header")
	}
	var out struct {
		Count  int `json:"count"`
		Events []struct {
			Action string `json:"action"`
		} `json:"events"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Count < 2 || len(out.Events) != out.Count {
		t.Fatalf("count mismatch: count=%d events=%d", out.Count, len(out.Events))
	}
	// The header digest must be the SHA-256 of the exact delivered bytes, so a
	// regulator can sha256sum the downloaded file and match it.
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != hdrDigest {
		t.Fatalf("header digest %q != sha256(body)", hdrDigest)
	}

	// Deterministic over a fixed range: two exports of the same closed window
	// (here an empty historical window) produce the same digest, so a regulator
	// re-running the export can confirm nothing changed.
	const window = "/api/audit/export?since=2000-01-01T00:00:00Z&until=2000-01-02T00:00:00Z"
	r1, _ := getWithKey(t, srv, window, testAPIKey)
	r2, _ := getWithKey(t, srv, window, testAPIKey)
	if r1.Header.Get("X-PAM-Export-SHA256") != r2.Header.Get("X-PAM-Export-SHA256") {
		t.Fatal("export digest is not deterministic over a fixed range")
	}
}

// TestAuditExportCSVAndFilter verifies CSV output and the ?action= filter scoping.
func TestAuditExportCSVAndFilter(t *testing.T) {
	srv := newTestServer(t)
	do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})

	resp, body := getWithKey(t, srv, "/api/audit/export?format=csv", testAPIKey)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		t.Fatalf("csv export: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.HasPrefix(string(body), "id,ts,actor,action,detail") {
		t.Fatalf("csv header missing: %q", string(body)[:min(40, len(body))])
	}

	// Filter by action: only target.create rows come back.
	status, fbody := do(t, srv, http.MethodGet, "/api/audit/export?action=target.create", testAPIKey, nil)
	if status != http.StatusOK {
		t.Fatalf("filtered export: %d", status)
	}
	var out struct {
		Events []struct {
			Action string `json:"action"`
		} `json:"events"`
	}
	json.Unmarshal(fbody, &out)
	if len(out.Events) == 0 {
		t.Fatal("expected at least one target.create event")
	}
	for _, e := range out.Events {
		if e.Action != "target.create" {
			t.Fatalf("filter leaked action %q", e.Action)
		}
	}
}

// TestAuditExportRequiresReadAudit verifies the export requires CapReadAudit
// (auditor allowed, plain user forbidden).
func TestAuditExportRequiresReadAudit(t *testing.T) {
	srv := newTestServer(t)
	auditor := seedUser(t, srv, "bob", "auditor")
	user := seedUser(t, srv, "carol", "user")

	if status, _ := do(t, srv, http.MethodGet, "/api/audit/export", auditor, nil); status != http.StatusOK {
		t.Fatalf("auditor export: want 200, got %d", status)
	}
	if status, _ := do(t, srv, http.MethodGet, "/api/audit/export", user, nil); status != http.StatusForbidden {
		t.Fatalf("user export: want 403, got %d", status)
	}
}
