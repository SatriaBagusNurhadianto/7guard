package quarantine

import (
	"sync"
	"time"
)

// Entry represents a single quarantined subject.
type Entry struct {
	Key       string
	Reason    string
	Until     time.Time
	CreatedAt time.Time
}

// Quarantine tracks subjects (IPs, sessions) that have been quarantined.
// All methods are safe for concurrent use.
type Quarantine struct {
	mu      sync.RWMutex
	entries map[string]Entry
	now     func() time.Time // injectable clock for testing
}

// New creates a Quarantine store.
func New() *Quarantine {
	return &Quarantine{
		entries: make(map[string]Entry),
		now:     time.Now,
	}
}

// Quarantine marks a subject as quarantined for the given duration.
func (q *Quarantine) Quarantine(key, reason string, duration time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	q.entries[key] = Entry{
		Key:       key,
		Reason:    reason,
		Until:     now.Add(duration),
		CreatedAt: now,
	}
}

// IsQuarantined reports whether a subject is currently quarantined.
func (q *Quarantine) IsQuarantined(key string) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	e, ok := q.entries[key]
	if !ok {
		return false
	}
	return q.now().Before(e.Until)
}

// Release removes a subject from quarantine immediately.
func (q *Quarantine) Release(key string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.entries, key)
}

// Entry returns the quarantine entry for a subject, if any.
func (q *Quarantine) Get(key string) (Entry, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	e, ok := q.entries[key]
	if !ok {
		return Entry{}, false
	}
	return e, true
}

// Cleanup removes expired entries.
func (q *Quarantine) Cleanup() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	removed := 0
	for key, e := range q.entries {
		if !now.Before(e.Until) {
			delete(q.entries, key)
			removed++
		}
	}
	return removed
}

// Size returns the number of tracked entries (including expired, until cleanup).
func (q *Quarantine) Size() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.entries)
}
