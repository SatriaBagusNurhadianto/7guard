package metrics

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Block reasons (stable labels).
var BlockReasons = []string{"waf", "adaptive", "quarantine", "rate"}

// Adaptive actions (stable labels).
var AdaptiveActions = []string{"allow", "throttle", "block"}

// Egress deny reasons (stable labels).
var EgressReasons = []string{"allowlist", "dns_rebinding", "redirect", "userinfo", "empty_host", "invalid"}

// Response leak types (stable labels).
var ResponseLeakTypes = []string{"pii", "secret", "error_page"}

// SSRF block reasons (stable labels).
var SSRFBlockReasons = []string{"blocked_range", "metadata", "dns_failure", "redirect_blocked"}

// Metrics holds production counters for 7Guard. All counters are atomic;
// map-valued counters are protected by mu for structural changes only.
type Metrics struct {
	requestsTotal       atomic.Int64
	quarantinedSubjects atomic.Int64

	mu              sync.Mutex
	blocksTotal     map[string]*atomic.Int64
	adaptiveActions map[string]*atomic.Int64
	ruleMatches     map[string]*atomic.Int64
	egressDenied    map[string]*atomic.Int64
	responseLeak    map[string]*atomic.Int64
	ssrfDenied      map[string]*atomic.Int64

	egressAllowed        atomic.Int64
	requestLatencyMicros atomic.Int64
}

// New creates a Metrics instance with all stable labels pre-seeded at zero.
func New() *Metrics {
	m := &Metrics{
		blocksTotal:     make(map[string]*atomic.Int64),
		adaptiveActions: make(map[string]*atomic.Int64),
		ruleMatches:     make(map[string]*atomic.Int64),
		egressDenied:    make(map[string]*atomic.Int64),
		responseLeak:    make(map[string]*atomic.Int64),
		ssrfDenied:      make(map[string]*atomic.Int64),
	}
	for _, r := range BlockReasons {
		m.blocksTotal[r] = &atomic.Int64{}
	}
	for _, a := range AdaptiveActions {
		m.adaptiveActions[a] = &atomic.Int64{}
	}
	for _, r := range EgressReasons {
		m.egressDenied[r] = &atomic.Int64{}
	}
	for _, t := range ResponseLeakTypes {
		m.responseLeak[t] = &atomic.Int64{}
	}
	for _, r := range SSRFBlockReasons {
		m.ssrfDenied[r] = &atomic.Int64{}
	}
	return m
}

// IncRequests increments the total request counter.
func (m *Metrics) IncRequests() { m.requestsTotal.Add(1) }

// IncBlock increments the block counter for the given reason.
func (m *Metrics) IncBlock(reason string) {
	if !contains(BlockReasons, reason) {
		return
	}
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
	if !contains(AdaptiveActions, action) {
		return
	}
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

// IncEgressAllowed increments the egress-allowed counter.
func (m *Metrics) IncEgressAllowed() { m.egressAllowed.Add(1) }

// IncEgressDenied increments the egress-denied counter for the given reason.
func (m *Metrics) IncEgressDenied(reason string) {
	if !contains(EgressReasons, reason) {
		return
	}
	m.mu.Lock()
	c, ok := m.egressDenied[reason]
	if !ok {
		c = &atomic.Int64{}
		m.egressDenied[reason] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

// IncResponseLeak increments the response-leak counter for the given type.
func (m *Metrics) IncResponseLeak(leakType string) {
	if !contains(ResponseLeakTypes, leakType) {
		return
	}
	m.mu.Lock()
	c, ok := m.responseLeak[leakType]
	if !ok {
		c = &atomic.Int64{}
		m.responseLeak[leakType] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

type Snapshot struct {
	RequestsTotal        int64            `json:"requests_total"`
	BlocksTotal          map[string]int64 `json:"blocks_total"`
	QuarantinedSubjects  int64            `json:"quarantined_subjects"`
	AdaptiveActionsTotal map[string]int64 `json:"adaptive_actions_total"`
	RuleMatchesTotal     map[string]int64 `json:"rule_matches_total"`
	EgressAllowedTotal   int64            `json:"egress_allowed_total"`
	EgressDeniedTotal    map[string]int64 `json:"egress_denied_total"`
	ResponseLeakTotal    map[string]int64 `json:"response_leak_total"`
	RequestLatencyMicros int64            `json:"request_latency_micros"`
	SSRFBlockedTotal     map[string]int64 `json:"ssrf_blocked_total"`
}

// IncSSRFBlocked increments the SSRF-blocked counter for the given reason.
func (m *Metrics) IncSSRFBlocked(reason string) {
	if !contains(SSRFBlockReasons, reason) {
		return
	}
	m.mu.Lock()
	c, ok := m.ssrfDenied[reason]
	if !ok {
		c = &atomic.Int64{}
		m.ssrfDenied[reason] = c
	}
	m.mu.Unlock()
	c.Add(1)
}

// RecordLatency records the duration of the most recent request in microseconds.
func (m *Metrics) RecordLatency(d time.Duration) {
	m.requestLatencyMicros.Store(d.Microseconds())
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
	egressDenied := make(map[string]int64, len(m.egressDenied))
	for k, v := range m.egressDenied {
		egressDenied[k] = v.Load()
	}
	e := make(map[string]int64, len(m.responseLeak))
	for k, v := range m.responseLeak {
		e[k] = v.Load()
	}
	ssrf := make(map[string]int64, len(m.ssrfDenied))
	for k, v := range m.ssrfDenied {
		ssrf[k] = v.Load()
	}
	return Snapshot{
		RequestsTotal:        m.requestsTotal.Load(),
		BlocksTotal:          blocks,
		QuarantinedSubjects:  m.quarantinedSubjects.Load(),
		AdaptiveActionsTotal: adaptive,
		RuleMatchesTotal:     rules,
		EgressAllowedTotal:   m.egressAllowed.Load(),
		EgressDeniedTotal:    egressDenied,
		ResponseLeakTotal:    e,
		RequestLatencyMicros: m.requestLatencyMicros.Load(),
		SSRFBlockedTotal:     ssrf,
	}
}

// Handler serves /metrics as JSON.
func (m *Metrics) Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(m.Snapshot())
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
