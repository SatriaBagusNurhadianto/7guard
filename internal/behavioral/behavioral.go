package behavioral

import (
	"sync"
	"time"
)

// Event represents a single request event for behavioral analysis.
type Event struct {
	RequestID   string
	ClientIP    string
	SessionID   string
	Timestamp   time.Time
	RuleMatches []string
	Severity    string
	Score       int
	Path        string
	Method      string
	UserAgent   string
}

// ChainAlert represents a detected attack chain.
type ChainAlert struct {
	ChainID     string
	Severity    string
	RequestIDs  []string
	DetectedAt  time.Time
	Description string
}

// ChainPattern defines a detectable attack chain.
type ChainPattern struct {
	ID          string
	Description string
	Window      time.Duration
	MinEvents   int
	Severity    string
	MatchFunc   func(events []Event) bool
}

// DefaultChains returns the v1 chain patterns.
func DefaultChains() []ChainPattern {
	return []ChainPattern{
		{
			ID:          "auth-brute-force",
			Description: "5+ failed auth attempts from same IP",
			Window:      60 * time.Second,
			MinEvents:   5,
			Severity:    "high",
			MatchFunc: func(events []Event) bool {
				count := 0
				for _, e := range events {
					if e.Score >= 3 { // auth failure threshold
						count++
					}
				}
				return count >= 5
			},
		},
		{
			ID:          "sqli-then-traversal",
			Description: "SQLi match followed by path traversal from same IP",
			Window:      300 * time.Second,
			MinEvents:   2,
			Severity:    "critical",
			MatchFunc: func(events []Event) bool {
				hasSQLi := false
				hasTraversal := false
				for _, e := range events {
					for _, m := range e.RuleMatches {
						if containsPrefix(m, "sqli") {
							hasSQLi = true
						}
						if containsPrefix(m, "trav") {
							hasTraversal = true
						}
					}
				}
				return hasSQLi && hasTraversal
			},
		},
		{
			ID:          "recon-scan",
			Description: "10+ distinct paths with errors from same IP",
			Window:      120 * time.Second,
			MinEvents:   10,
			Severity:    "medium",
			MatchFunc: func(events []Event) bool {
				paths := make(map[string]bool)
				for _, e := range events {
					if e.Score > 0 {
						paths[e.Path] = true
					}
				}
				return len(paths) >= 10
			},
		},
		{
			ID:          "payload-variation",
			Description: "5+ distinct payloads triggering rules on same endpoint",
			Window:      300 * time.Second,
			MinEvents:   5,
			Severity:    "high",
			MatchFunc: func(events []Event) bool {
				payloads := make(map[string]bool)
				endpoint := ""
				for _, e := range events {
					if endpoint == "" {
						endpoint = e.Path
					}
					if e.Path == endpoint && len(e.RuleMatches) > 0 {
						payloads[e.RequestID] = true
					}
				}
				return len(payloads) >= 5
			},
		},
		{
			ID:          "slow-brute",
			Description: "3+ failed auth spread over 5-30 min (evasion)",
			Window:      1800 * time.Second,
			MinEvents:   3,
			Severity:    "high",
			MatchFunc: func(events []Event) bool {
				count := 0
				for _, e := range events {
					if e.Score >= 3 {
						count++
					}
				}
				if count < 3 {
					return false
				}
				// Check time spread: at least 5 min between first and last
				if len(events) < 2 {
					return false
				}
				span := events[len(events)-1].Timestamp.Sub(events[0].Timestamp)
				return span >= 5*time.Minute
			},
		},
	}
}

// Detector performs behavioral analysis and attack-chain detection.
type Detector struct {
	mu       sync.RWMutex
	chains   []ChainPattern
	windows  map[string]*slidingWindow // key: IP or session
	maxEvents int
}

type slidingWindow struct {
	events []Event
	lastSeen time.Time
}

// New creates a behavioral detector.
func New(chains []ChainPattern) *Detector {
	if chains == nil {
		chains = DefaultChains()
	}
	return &Detector{
		chains:    chains,
		windows:   make(map[string]*slidingWindow),
		maxEvents: 1000,
	}
}

// Record adds an event and checks for attack chains.
func (d *Detector) Record(e Event) []ChainAlert {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := e.ClientIP
	if e.SessionID != "" {
		key = e.SessionID
	}

	w, ok := d.windows[key]
	if !ok {
		w = &slidingWindow{events: []Event{}, lastSeen: e.Timestamp}
		d.windows[key] = w
	}

	w.events = append(w.events, e)
	w.lastSeen = e.Timestamp

	// Evict old events (longest window = 1800s)
	cutoff := e.Timestamp.Add(-1800 * time.Second)
	filtered := w.events[:0]
	for _, ev := range w.events {
		if ev.Timestamp.After(cutoff) {
			filtered = append(filtered, ev)
		}
	}
	w.events = filtered

	// Cap window size
	if len(w.events) > d.maxEvents {
		w.events = w.events[len(w.events)-d.maxEvents:]
	}

	// Check chains
	var alerts []ChainAlert
	for _, chain := range d.chains {
		windowCutoff := e.Timestamp.Add(-chain.Window)
		var windowEvents []Event
		for _, ev := range w.events {
			if ev.Timestamp.After(windowCutoff) {
				windowEvents = append(windowEvents, ev)
			}
		}
		if len(windowEvents) >= chain.MinEvents && chain.MatchFunc(windowEvents) {
			alerts = append(alerts, ChainAlert{
				ChainID:     chain.ID,
				Severity:    chain.Severity,
				RequestIDs:  collectRequestIDs(windowEvents),
				DetectedAt:  e.Timestamp,
				Description: chain.Description,
			})
		}
	}

	return alerts
}

// Cleanup removes stale windows.
func (d *Detector) Cleanup(maxAge time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	for key, w := range d.windows {
		if now.Sub(w.lastSeen) > maxAge {
			delete(d.windows, key)
		}
	}
}

// WindowCount returns the number of active windows (for testing).
func (d *Detector) WindowCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.windows)
}

func collectRequestIDs(events []Event) []string {
	ids := make([]string, 0, len(events))
	for _, e := range events {
		ids = append(ids, e.RequestID)
	}
	return ids
}

func containsPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
