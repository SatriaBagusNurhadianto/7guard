package adaptive

import (
	"sync"
)

// Action is the decision returned by the adaptive defense.
type Action int

const (
	ActionAllow Action = iota
	ActionThrottle
	ActionBlock
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "allow"
	case ActionThrottle:
		return "throttle"
	case ActionBlock:
		return "block"
	default:
		return "unknown"
	}
}

// Policy defines thresholds for the adaptive defense.
type Policy struct {
	ThrottleThreshold int // score >= this => throttle
	BlockThreshold    int // score >= this => block
}

// DefaultPolicy returns sensible defaults.
func DefaultPolicy() Policy {
	return Policy{
		ThrottleThreshold: 5,
		BlockThreshold:    10,
	}
}

// Adaptive evaluates threat scores and decides an action.
// Thread-safe.
type Adaptive struct {
	mu     sync.RWMutex
	policy Policy
}

// New creates an adaptive defense with the given policy.
func New(policy Policy) *Adaptive {
	if policy.ThrottleThreshold == 0 {
		policy = DefaultPolicy()
	}
	return &Adaptive{policy: policy}
}

// Policy returns the current policy.
func (a *Adaptive) Policy() Policy {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.policy
}

// SetPolicy updates the policy.
func (a *Adaptive) SetPolicy(p Policy) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.policy = p
}

// Evaluate returns the action for a given threat score.
func (a *Adaptive) Evaluate(score int) Action {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if score >= a.policy.BlockThreshold {
		return ActionBlock
	}
	if score >= a.policy.ThrottleThreshold {
		return ActionThrottle
	}
	return ActionAllow
}

// RateMultiplier returns a multiplier (0..1) for the rate limiter
// based on the action. Block => 0, Throttle => 0.5, Allow => 1.0.
func (a *Adaptive) RateMultiplier(action Action) float64 {
	switch action {
	case ActionBlock:
		return 0
	case ActionThrottle:
		return 0.5
	default:
		return 1.0
	}
}
