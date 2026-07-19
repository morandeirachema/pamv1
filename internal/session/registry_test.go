package session

import (
	"testing"
	"time"
)

// TestRegistry covers register, list, kill (found and unknown id) and remove.
func TestRegistry(t *testing.T) {
	r := NewRegistry()
	killed := false
	id := r.Register(Info{Actor: "alice", Target: "web-01", Protocol: "ssh", Started: time.Unix(1, 0)}, func() { killed = true })
	if id == "" {
		t.Fatal("empty id")
	}

	list := r.List()
	if len(list) != 1 || list[0].Actor != "alice" || list[0].ID != id {
		t.Fatalf("unexpected list: %+v", list)
	}

	if !r.Kill(id) {
		t.Fatal("kill should find the session")
	}
	if !killed {
		t.Fatal("kill func not invoked")
	}
	if r.Kill("nope") {
		t.Fatal("kill of unknown id should return false")
	}

	r.Remove(id)
	if len(r.List()) != 0 {
		t.Fatal("session should be gone after Remove")
	}
}

// TestRegistryOrdering checks List returns sessions oldest first.
func TestRegistryOrdering(t *testing.T) {
	r := NewRegistry()
	r.Register(Info{Actor: "b", Started: time.Unix(2, 0)}, nil)
	r.Register(Info{Actor: "a", Started: time.Unix(1, 0)}, nil)
	list := r.List()
	if list[0].Actor != "a" || list[1].Actor != "b" {
		t.Fatalf("expected oldest first, got %+v", list)
	}
}
