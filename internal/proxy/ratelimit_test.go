package proxy

import (
	"testing"
	"time"
)

// TestAuthRateLimiter verifies per-IP throttling: attempts within the budget are
// allowed, the next is denied, a different IP has its own budget, and the window
// resets after a minute.
func TestAuthRateLimiter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rl := newAuthRateLimiter(3)
	rl.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if !rl.allow("10.0.0.1") {
			t.Fatalf("attempt %d should be allowed within budget", i+1)
		}
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("4th attempt from the same IP should be denied")
	}
	// A different source IP keeps its own independent budget.
	if !rl.allow("10.0.0.2") {
		t.Fatal("a different IP should be allowed")
	}
	// After the window elapses, the budget refreshes.
	now = now.Add(61 * time.Second)
	if !rl.allow("10.0.0.1") {
		t.Fatal("attempt after the window resets should be allowed")
	}
}

// TestAuthRateLimiterDisabled confirms perMin<=0 (and a nil limiter) never throttle.
func TestAuthRateLimiterDisabled(t *testing.T) {
	rl := newAuthRateLimiter(0)
	for i := 0; i < 1000; i++ {
		if !rl.allow("10.0.0.1") {
			t.Fatal("a disabled limiter must always allow")
		}
	}
	var nilRL *authRateLimiter
	if !nilRL.allow("10.0.0.1") {
		t.Fatal("a nil limiter must always allow")
	}
}
