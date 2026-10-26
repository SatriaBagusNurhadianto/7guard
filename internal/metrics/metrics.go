package metrics

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
)

// Block reasons (stable labels).
var BlockReasons = []string{"waf", "adaptive", "quarantine", "rate"}

// Adaptive actions (stable labels).
var AdaptiveActions = []string{"allow", "throttle", "block"}

// Metrics holds production counters for 7Guard. All counters are atomic;
// map-valued counters are protected by mu for structural changes only.
type Metrics struct {
	requestsTotal       atomic.Int64
	quarantinedSubjects atomic.Int64

	mu              sync.Mutex
	blocksTotal     map[string]*atomic.Int64
	adaptiveActions map[string]*atomic.Int64
	ruleMatches     map[string]*atomic.Int64
}

// New creates a Metrics instance with all stable labels pre-seeded at zero.
func New() *Metrics {
	m := &Metrics{
		blocksTotal:     make(map[string]*atomic.Int64),
		adaptiveActions: make(map[string]*atomic.Int64),
		ruleMatches:     make(map[string]*atomic.Int64),
	}
	for _, r := range BlockReasons {
		m.blocksTotal[r] = &atomic.Int64{}
	}
	for _, a := range AdaptiveActions {
		m.adaptiveActions[a] = &atomic.Int64{}
	}
	return m
}

// IncRequests increments the total request counter.
func (m *Metrics) IncRequests() { m.requestsTotal.Add(1) }

// IncBlock increments the block counter for the given reason.
func (m *Metrics) IncBlock(reason string) {
	m.mu.Lock()
	c, ok := m.blocksTotal[reason]
	if !ok {
		c = &atomic.Int64{}
		m.blocksTotal[reason] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

// SetQuarantined sets the current number of quarantined subjects (gauge).
func (m *Metrics) SetQuarantined(n int64) { m.quarantinedSubjects.Store(n) }

// IncAdaptive increments the adaptive-action counter.
func (m *Metrics) IncAdaptive(action string) {
	m.mu.Lock()
	c, ok := m.adaptiveActions[action]
	if !ok {
		c = &atomic.Int64{}
		m.adaptiveActions[action] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

// IncRuleMatch increments the per-rule match counter.
func (m *Metrics) IncRuleMatch(ruleID string) {
	m.mu.Lock()
	c, ok := m.ruleMatches[ruleID]
	if !ok {
		c = &atomic.Int64{}
		m.ruleMatches[ruleID] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

// Snapshot is the stable JSON schema returned by /metrics.
type Snapshot struct {
	RequestsTotal        int64            `json:"requests_total"`
	BlocksTotal          map[string]int64 `json:"blocks_total"`
	QuarantinedSubjects  int64            `json:"quarantined_subjects"`
	AdaptiveActionsTotal map[string]int64 `json:"adaptive_actions_total"`
	RuleMatchesTotal     map[string]int64 `json:"rule_matches_total"`
}

// Snapshot returns a point-in-time copy of all counters.
func (m *Metrics) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()

	blocks := make(map[string]int64, len(m.blocksTotal))
	for k, v := range m.blocksTotal {
		blocks[k] = v.Load()
	}
	adaptive := make(map[string]int64, len(m.adaptiveActions))
	for k, v := range m.adaptiveActions {
		adaptive[k] = v.Load()
	}
	rules := make(map[string]int64, len(m.ruleMatches))
	for k, v := range m.ruleMatches {
		rules[k] = v.Load()
	}
	return Snapshot{
		RequestsTotal:        m.requestsTotal.Load(),
		BlocksTotal:          blocks,
		QuarantinedSubjects:  m.quarantinedSubjects.Load(),
		AdaptiveActionsTotal: adaptive,
		RuleMatchesTotal:     rules,
	}
}

// Handler serves /metrics as JSON.
func (m *Metrics) Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(m.Snapshot())
}
