package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a per-key token bucket rate limiter.
type Limiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     int           // tokens per window
	burst    int           // max tokens
	window   time.Duration // refill window
}

type bucket struct {
	tokens   int
	lastFill time.Time
}

// New creates a rate limiter with the given rate (tokens/min) and burst size.
func New(rate, burst int) *Limiter {
	return &Limiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		window:  time.Minute,
	}
}

// Allow checks if a request for the given key should be allowed.
// Returns (allowed bool, retryAfter seconds).
func (l *Limiter) Allow(key string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, lastFill: now}
		l.buckets[key] = b
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastFill)
	refill := int(elapsed.Seconds()) * l.rate / 60
	if refill > 0 {
		b.tokens += refill
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastFill = now
	}

	if b.tokens <= 0 {
		// Calculate retry-after
		retryAfter := int((time.Minute - elapsed).Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		return false, retryAfter
	}

	b.tokens--
	return true, 0
}

// Cleanup removes stale buckets (call periodically).
func (l *Limiter) Cleanup(maxAge time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for key, b := range l.buckets {
		if now.Sub(b.lastFill) > maxAge {
			delete(l.buckets, key)
		}
	}
}
