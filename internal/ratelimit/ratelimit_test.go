package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// TestLimiter verifies per-key throttling: events within the budget are allowed,
// the next is denied, a different key has its own budget, and the window resets.
func TestLimiter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := New(3)
	l.SetClock(func() time.Time { return now })

	for i := 0; i < 3; i++ {
		if !l.Allow("10.0.0.1") {
			t.Fatalf("event %d should be allowed within budget", i+1)
		}
	}
	if l.Allow("10.0.0.1") {
		t.Fatal("4th event from the same key should be denied")
	}
	if !l.Allow("10.0.0.2") {
		t.Fatal("a different key should have its own budget")
	}
	// After the window elapses, the budget refreshes and stale keys are swept.
	now = now.Add(61 * time.Second)
	if !l.Allow("10.0.0.1") {
		t.Fatal("event after the window resets should be allowed")
	}
}

// TestLimiterDisabled confirms perMin<=0 and a nil limiter never throttle.
func TestLimiterDisabled(t *testing.T) {
	l := New(0)
	for i := 0; i < 1000; i++ {
		if !l.Allow("k") {
			t.Fatal("a disabled limiter must always allow")
		}
	}
	var nilL *Limiter
	if !nilL.Allow("k") {
		t.Fatal("a nil limiter must always allow")
	}
}

// TestLimiterConcurrent runs Allow from many goroutines to shake out races under
// the -race detector (the map and window are mutex-guarded).
func TestLimiterConcurrent(t *testing.T) {
	l := New(100)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.Allow("shared-key")
			}
		}()
	}
	wg.Wait()
}
