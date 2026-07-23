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

	// Shamir shares carry the x-coordinate in their LAST byte (see shamir.Split).
	if _, ok := u.add([]byte{1, 2, 3, 4, 5}, now); !ok { // x=5
		t.Fatal("first valid share was rejected")
	}
	if _, ok := u.add([]byte{2, 9}, now); ok {
		t.Fatal("a wrong-length share must be rejected")
	}
	if _, ok := u.add([]byte{9, 9, 9, 9, 5}, now); ok { // x=5 duplicates the first share
		t.Fatal("a duplicate x-coordinate share must be rejected")
	}
	// Regression: a valid distinct-x share whose LEADING byte happens to collide
	// with the first share's must be accepted (the earlier bug compared the wrong
	// byte and spuriously rejected it, making the quorum unseal flaky).
	if got, ok := u.add([]byte{1, 8, 8, 8, 7}, now); !ok || len(got) != 2 { // leading 1==1, x=7 distinct
		t.Fatalf("valid distinct-x share with a colliding leading byte was rejected: ok=%v len=%d", ok, len(got))
	}
}
