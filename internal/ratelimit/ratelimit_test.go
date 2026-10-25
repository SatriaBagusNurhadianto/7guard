package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func TestAllowBasic(t *testing.T) {
	l := New(60, 5)

	// First 5 should be allowed (burst)
	for i := 0; i < 5; i++ {
		allowed, _ := l.Allow("test-key")
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 6th should be denied
	allowed, retryAfter := l.Allow("test-key")
	if allowed {
		t.Error("6th request should be denied")
	}
	if retryAfter < 1 {
		t.Errorf("retryAfter should be >= 1, got %d", retryAfter)
	}
}

func TestAllowDifferentKeys(t *testing.T) {
	l := New(60, 2)

	// Exhaust key1
	l.Allow("key1")
	l.Allow("key1")
	allowed, _ := l.Allow("key1")
	if allowed {
		t.Error("key1 should be exhausted")
	}

	// key2 should still work
	allowed, _ = l.Allow("key2")
	if !allowed {
		t.Error("key2 should be allowed")
	}
}

func TestAllowRefill(t *testing.T) {
	l := New(60, 1) // 1 token per second effectively

	l.Allow("key")
	allowed, _ := l.Allow("key")
	if allowed {
		t.Error("should be denied after burst exhausted")
	}

	// Wait for refill
	time.Sleep(1100 * time.Millisecond)
	allowed, _ = l.Allow("key")
	if !allowed {
		t.Error("should be allowed after refill")
	}
}

func TestConcurrentAccess(t *testing.T) {
	l := New(1000, 100)
	var wg sync.WaitGroup
	denied := 0
	mu := sync.Mutex{}

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed, _ := l.Allow("concurrent-key")
			if !allowed {
				mu.Lock()
				denied++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// With burst 100, at least 100 should be denied out of 200
	if denied < 90 {
		t.Errorf("expected ~100 denied, got %d", denied)
	}
}

func TestCleanup(t *testing.T) {
	l := New(60, 5)
	l.Allow("stale-key")
	time.Sleep(10 * time.Millisecond)
	l.Cleanup(1 * time.Millisecond) // remove buckets older than 1ms

	l.mu.Lock()
	_, exists := l.buckets["stale-key"]
	l.mu.Unlock()

	if exists {
		t.Error("stale bucket should have been cleaned up")
	}
}
