package ratelimit

import (
	"sync"
	"time"
)

const maxBuckets = 100000

// Limiter is a per-key token bucket rate limiter.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int           // tokens per window
	burst   int           // max tokens
	window  time.Duration // refill window
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
	return l.AllowWithMultiplier(key, 1.0)
}

// AllowWithMultiplier is like Allow but consumes `mult` extra tokens when
// mult < 1.0, implementing adaptive throttling. mult <= 0 means block.
// mult >= 1.0 consumes a single token (normal).
func (l *Limiter) AllowWithMultiplier(key string, mult float64) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		// Bound map growth: evict oldest if at capacity
		if len(l.buckets) >= maxBuckets {
			// Remove one stale bucket
			for k := range l.buckets {
				delete(l.buckets, k)
				break
			}
		}
		b = &bucket{tokens: l.burst, lastFill: now}
		l.buckets[key] = b
	}

	// Refill tokens based on elapsed time (use fractional seconds for precision)
	elapsed := now.Sub(b.lastFill)
	refill := int(elapsed.Seconds() * float64(l.rate) / 60.0)
	if refill > 0 {
		b.tokens += refill
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.lastFill = now
	}

	// Adaptive block: mult <= 0 means no tokens consumed, request blocked.
	if mult <= 0 {
		retryAfter := int((l.window - elapsed).Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		return false, retryAfter
	}

	// Number of tokens to consume: 1 normally, 2 when throttled.
	consume := 1
	if mult < 1.0 {
		consume = 2
	}

	if b.tokens < consume {
		retryAfter := int((l.window - elapsed).Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		return false, retryAfter
	}

	b.tokens -= consume
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
