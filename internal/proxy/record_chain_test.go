package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// hexSHA returns the hex-encoded SHA-256 of s.
func hexSHA(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestRecordChain verifies each link is SHA-256(prevChain||fileHash) and that
// the chain head persists across a reload of the same directory.
func TestRecordChain(t *testing.T) {
	dir := t.TempDir()
	c := newRecordChain(dir)

	h1 := hexSHA("recording-1")
	h2 := hexSHA("recording-2")
	c1 := c.append(h1)
	c2 := c.append(h2)

	if c1 == "" || c2 == "" || c1 == c2 {
		t.Fatalf("chain hashes should be non-empty and distinct: %q %q", c1, c2)
	}

	// c2 must equal SHA-256(c1_bytes || h2_bytes) — the defining chain property.
	c1b, _ := hex.DecodeString(c1)
	h2b, _ := hex.DecodeString(h2)
	want := sha256.Sum256(append(append([]byte{}, c1b...), h2b...))
	if c2 != hex.EncodeToString(want[:]) {
		t.Fatalf("chain link broken: c2=%s want=%s", c2, hex.EncodeToString(want[:]))
	}

	// The head persists: a new chain over the same dir continues from c2.
	c3 := newRecordChain(dir).append(hexSHA("recording-3"))
	c2b, _ := hex.DecodeString(c2)
	h3b, _ := hex.DecodeString(hexSHA("recording-3"))
	want3 := sha256.Sum256(append(append([]byte{}, c2b...), h3b...))
	if c3 != hex.EncodeToString(want3[:]) {
		t.Fatalf("chain did not persist across reload: c3=%s want=%s", c3, hex.EncodeToString(want3[:]))
	}
}
