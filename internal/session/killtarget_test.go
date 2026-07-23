package session

import "testing"

// TestKillByActorTarget verifies that only the matching actor+target sessions are
// killed, leaving the same actor's sessions to other targets (and other actors')
// running.
func TestKillByActorTarget(t *testing.T) {
	r := NewRegistry()
	killed := map[string]bool{}
	mk := func(id, actor, target string) {
		r.Register(Info{Actor: actor, Target: target, Protocol: "ssh"}, func() { killed[id] = true })
	}
	mk("a-web", "alice", "web-01")
	mk("a-db", "alice", "db-01")
	mk("b-web", "bob", "web-01")

	if n := r.KillByActorTarget("alice", "web-01"); n != 1 {
		t.Fatalf("KillByActorTarget = %d, want 1", n)
	}
	if !killed["a-web"] {
		t.Fatal("alice's web-01 session should have been killed")
	}
	if killed["a-db"] {
		t.Fatal("alice's db-01 session must NOT be killed (still authorized)")
	}
	if killed["b-web"] {
		t.Fatal("bob's web-01 session must NOT be killed")
	}
}
