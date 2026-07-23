package session

import "testing"

// TestConcurrentSessionCaps verifies the per-actor and global concurrent-session
// limits enforced by AllowNew.
func TestConcurrentSessionCaps(t *testing.T) {
	r := NewRegistry()
	r.SetLimits(2, 3) // 2 per actor, 3 total

	noop := func() {}
	// alice can open 2, then is capped.
	r.Register(Info{Actor: "alice"}, noop)
	if !r.AllowNew("alice") {
		t.Fatal("alice should be allowed a 2nd session")
	}
	r.Register(Info{Actor: "alice"}, noop)
	if r.AllowNew("alice") {
		t.Fatal("alice must be capped at 2 sessions")
	}
	// bob is unaffected by alice's per-actor cap...
	if !r.AllowNew("bob") {
		t.Fatal("bob should be allowed")
	}
	r.Register(Info{Actor: "bob"}, noop)
	// ...but the global cap of 3 is now reached: nobody new.
	if r.AllowNew("bob") || r.AllowNew("carol") {
		t.Fatal("global cap of 3 must block further sessions")
	}
	// Freeing one slot re-opens capacity.
	for _, i := range r.List() {
		if i.Actor == "bob" {
			r.Remove(i.ID)
			break
		}
	}
	if !r.AllowNew("carol") {
		t.Fatal("a freed slot should allow a new session")
	}
}

// TestUnlimitedByDefault confirms 0/0 (the default) never caps.
func TestUnlimitedByDefault(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 1000; i++ {
		if !r.AllowNew("alice") {
			t.Fatal("default limits must be unlimited")
		}
		r.Register(Info{Actor: "alice"}, func() {})
	}
}
