package proxy

import "testing"

// TestCommandGuard checks pattern matching, comment/blank skipping, the nil-guard
// no-op, and fail-loud compilation.
func TestCommandGuard(t *testing.T) {
	g, err := NewCommandGuard([]string{
		"# dangerous filesystem wipes",
		`rm\s+-rf`,
		"",
		"(?i)drop\\s+table",
	})
	if err != nil {
		t.Fatalf("NewCommandGuard: %v", err)
	}
	if g.Size() != 2 {
		t.Fatalf("Size = %d, want 2 (comment + blank skipped)", g.Size())
	}
	cases := []struct {
		cmd     string
		blocked bool
	}{
		{"rm -rf /", true},
		{"DROP TABLE users", true},
		{"drop table users", true}, // case-insensitive pattern
		{"ls -la", false},
		{"select * from users", false},
	}
	for _, c := range cases {
		if _, got := g.Blocked(c.cmd); got != c.blocked {
			t.Errorf("Blocked(%q) = %v, want %v", c.cmd, got, c.blocked)
		}
	}

	// A nil guard blocks nothing.
	var nilGuard *CommandGuard
	if _, blocked := nilGuard.Blocked("rm -rf /"); blocked {
		t.Fatal("nil guard must not block")
	}
	if nilGuard.Size() != 0 {
		t.Fatal("nil guard Size must be 0")
	}

	// An all-comment set yields a nil guard (nothing to enforce).
	empty, err := NewCommandGuard([]string{"# only a comment", "  "})
	if err != nil || empty != nil {
		t.Fatalf("all-comment set: guard=%v err=%v, want nil,nil", empty, err)
	}

	// A malformed pattern is a fail-loud error.
	if _, err := NewCommandGuard([]string{"("}); err == nil {
		t.Fatal("expected an error for a malformed pattern")
	}
}
