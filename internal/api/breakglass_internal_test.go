package api

import (
	"testing"
	"time"
)

// TestUnsealAddRejectsPoison proves a malformed or duplicate share is refused
// without discarding shares legitimate operators have already contributed, so one
// bad submission can't reset a forming quorum.
func TestUnsealAddRejectsPoison(t *testing.T) {
	u := newUnsealState()
	now := time.Now()

	if _, ok := u.add([]byte{1, 2, 3, 4, 5}, now); !ok {
		t.Fatal("first valid share was rejected")
	}
	if _, ok := u.add([]byte{2, 9}, now); ok {
		t.Fatal("a wrong-length share must be rejected")
	}
	if _, ok := u.add([]byte{1, 9, 9, 9, 9}, now); ok {
		t.Fatal("a duplicate x-coordinate share must be rejected")
	}
	// The first share survived the poison attempts: a valid distinct-x share brings
	// the pool to 2.
	if got, ok := u.add([]byte{2, 2, 2, 2, 2}, now); !ok || len(got) != 2 {
		t.Fatalf("valid second share: ok=%v len=%d (was the pool wiped?)", ok, len(got))
	}
}
