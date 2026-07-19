package api_test

import (
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
)

// The RDP tunnel authorizes before upgrading to WebSocket, so these checks are
// exercised with ordinary HTTP requests. (Full guacd bridging is covered by the
// internal/guacd handshake test.)

// TestRDPDisabledWhenNoGuacd verifies the RDP endpoint is 404 when no guacd is
// configured.
func TestRDPDisabledWhenNoGuacd(t *testing.T) {
	srv := newTestServer(t) // no GuacdAddr
	if status, _ := do(t, srv, http.MethodGet, "/api/targets/1/rdp?token="+testAPIKey, "", nil); status != http.StatusNotFound {
		t.Fatalf("rdp without guacd should be 404, got %d", status)
	}
}

// TestRDPAuthAndTargetChecks verifies the pre-WebSocket-upgrade auth and protocol
// checks: missing token, a non-connecting role, and a non-RDP target.
func TestRDPAuthAndTargetChecks(t *testing.T) {
	srv, _ := newTestServerOpts(t, nil, api.Options{GuacdAddr: "127.0.0.1:4822"})

	// Seed an RDP target (as admin) and a non-connecting user.
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "win-rdp", "host": "10.0.0.5", "port": 3389, "os_type": "windows", "protocol": "rdp",
	})
	rdpID := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, http.MethodPost, "/api/credentials", testAPIKey, map[string]any{
		"target_id": rdpID, "username": "Administrator", "secret": "s",
	})
	auditorTok := seedUser(t, srv, "theo", "auditor")

	// SSH target to prove protocol validation.
	_, data = do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "lnx", "host": "h", "os_type": "linux", "protocol": "ssh",
	})
	sshID := int64(jsonMap(t, data)["id"].(float64))

	cases := []struct {
		name, path, token string
		want              int
	}{
		{"no token", "/api/targets/" + itoa(rdpID) + "/rdp", "", http.StatusUnauthorized},
		{"auditor forbidden", "/api/targets/" + itoa(rdpID) + "/rdp?token=" + auditorTok, "", http.StatusForbidden},
		{"non-rdp target", "/api/targets/" + itoa(sshID) + "/rdp?token=" + testAPIKey, "", http.StatusUnprocessableEntity},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if status, _ := do(t, srv, http.MethodGet, c.path, "", nil); status != c.want {
				t.Fatalf("%s: status %d, want %d", c.name, status, c.want)
			}
		})
	}
}
