package api_test

import (
	"net/http"
	"testing"

	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/session"
)

// TestKillOnRevoke proves that revoking access terminates in-flight proxied
// sessions: deleting a user's grant to a target kills their session to THAT target
// (only), and revoking their login kills all of their sessions.
func TestKillOnRevoke(t *testing.T) {
	reg := session.NewRegistry()
	srv, _ := newTestServerOpts(t, nil, api.Options{Sessions: reg})

	// Seed a target and grant "alice" to it.
	_, data := do(t, srv, http.MethodPost, "/api/targets", testAPIKey, map[string]any{
		"name": "web-01", "host": "10.0.0.5", "port": 22, "os_type": "linux", "protocol": "ssh",
	})
	tid := itoa(int64(jsonMap(t, data)["id"].(float64)))
	_, gd := do(t, srv, http.MethodPost, "/api/targets/"+tid+"/grants", testAPIKey, map[string]any{
		"subject_type": "user", "subject": "alice",
	})
	gid := itoa(int64(jsonMap(t, gd)["id"].(float64)))

	// Register live sessions: alice→web-01, alice→db-01, bob→web-01.
	killed := map[string]bool{}
	reg.Register(session.Info{Actor: "alice", Target: "web-01", Protocol: "ssh"}, func() { killed["a-web"] = true })
	reg.Register(session.Info{Actor: "alice", Target: "db-01", Protocol: "ssh"}, func() { killed["a-db"] = true })
	reg.Register(session.Info{Actor: "bob", Target: "web-01", Protocol: "ssh"}, func() { killed["b-web"] = true })

	// Deleting alice's grant to web-01 kills only her web-01 session.
	if s, _ := do(t, srv, http.MethodDelete, "/api/targets/"+tid+"/grants/"+gid, testAPIKey, nil); s != http.StatusNoContent {
		t.Fatalf("delete grant: %d", s)
	}
	if !killed["a-web"] {
		t.Fatal("alice's web-01 session should be killed on grant revocation")
	}
	if killed["a-db"] || killed["b-web"] {
		t.Fatal("grant revocation killed unrelated sessions")
	}

	// Revoking bob's login kills all of bob's sessions.
	if s, _ := do(t, srv, http.MethodPost, "/api/login-sessions/revoke", testAPIKey, map[string]any{"username": "bob"}); s != http.StatusOK {
		t.Fatalf("revoke bob: %d", s)
	}
	if !killed["b-web"] {
		t.Fatal("bob's session should be killed on login revocation")
	}
}
