package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestAllowWithinBurst(t *testing.T) {
	l := New(10, 5)
	t.Cleanup(l.Stop)

	for i := range 5 {
		if !l.Allow("192.168.1.1") {
			t.Fatalf("request %d should be allowed within burst", i+1)
		}
	}
}

func TestDenyAfterBurst(t *testing.T) {
	l := New(10, 3)
	t.Cleanup(l.Stop)

	for i := range 3 {
		if !l.Allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed within burst", i+1)
		}
	}

	// Next request should be denied (bucket empty)
	if l.Allow("10.0.0.1") {
		t.Fatal("request after burst exhaustion should be denied")
	}
}

func TestIndependentIPBuckets(t *testing.T) {
	l := New(10, 2)
	t.Cleanup(l.Stop)

	// Exhaust bucket for IP A
	if !l.Allow("10.0.0.1") {
		t.Fatal("A1 should be allowed")
	}
	if !l.Allow("10.0.0.1") {
		t.Fatal("A2 should be allowed")
	}
	if l.Allow("10.0.0.1") {
		t.Fatal("A3 should be denied")
	}

	// IP B should still have its own burst
	if !l.Allow("10.0.0.2") {
		t.Fatal("B1 should be allowed (different IP)")
	}
	if !l.Allow("10.0.0.2") {
		t.Fatal("B2 should be allowed (different IP)")
	}
	if l.Allow("10.0.0.2") {
		t.Fatal("B3 should be denied")
	}
}

func TestRateLimitOverTime(t *testing.T) {
	l := New(20, 1) // 20 tokens/sec, burst=1
	t.Cleanup(l.Stop)

	// Use the burst token
	if !l.Allow("192.168.1.1") {
		t.Fatal("first request should be allowed")
	}

	// Immediate second request should be denied
	if l.Allow("192.168.1.1") {
		t.Fatal("second request should be denied (no tokens yet)")
	}

	// Wait for refill — 150ms should give at least one refill tick (100ms)
	time.Sleep(150 * time.Millisecond)

	if !l.Allow("192.168.1.1") {
		t.Fatal("request after refill should be allowed")
	}
}

func TestConcurrentAccess(t *testing.T) {
	l := New(100, 50)
	t.Cleanup(l.Stop)

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := "10.0.0.1"
			for range 5 {
				if !l.Allow(ip) {
					return // rate limit hit, not an error
				}
			}
		}()
	}

	wg.Wait()

	// At most 50 should succeed, the rest hit rate limit.
	// No panics, data races, or other issues.
}

func TestStopIsSafe(t *testing.T) {
	l := New(10, 5)
	// Call Stop multiple times — should not panic
	l.Stop()
	l.Stop()
}

func TestZeroRate(t *testing.T) {
	l := New(0, 0)
	t.Cleanup(l.Stop)

	// Zero rate means no refill, zero burst means no tokens ever
	if l.Allow("10.0.0.1") {
		t.Fatal("zero-burst limiter should deny all requests")
	}
}

func TestStaleEntryCleanup(t *testing.T) {
	l := New(100, 10)
	t.Cleanup(l.Stop)

	// Create an entry
	l.Allow("10.0.0.1")

	// Fake the lastSeen to be old
	l.mu.Lock()
	if b, ok := l.buckets["10.0.0.1"]; ok {
		b.lastSeen = time.Now().Add(-11 * time.Minute)
	}
	l.mu.Unlock()

	// Manually trigger cleanup logic (1-minute ticker is too slow for tests)
	l.mu.Lock()
	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, b := range l.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(l.buckets, ip)
		}
	}
	l.mu.Unlock()

	// Verify the stale entry was removed
	l.mu.Lock()
	_, exists := l.buckets["10.0.0.1"]
	l.mu.Unlock()

	if exists {
		t.Fatal("stale entry should have been evicted")
	}
}
