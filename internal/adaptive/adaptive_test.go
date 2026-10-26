package adaptive

import (
	"testing"
)

func TestAdaptiveEvaluate(t *testing.T) {
	a := New(DefaultPolicy())
	if a.Evaluate(0) != ActionAllow {
		t.Fatal("expected allow for 0")
	}
	if a.Evaluate(5) != ActionThrottle {
		t.Fatal("expected throttle at threshold")
	}
	if a.Evaluate(10) != ActionBlock {
		t.Fatal("expected block at threshold")
	}
	if a.RateMultiplier(ActionBlock) != 0 {
		t.Fatal("block multiplier should be 0")
	}
	if a.RateMultiplier(ActionThrottle) != 0.5 {
		t.Fatal("throttle multiplier should be 0.5")
	}
}

func TestAdaptiveSetPolicy(t *testing.T) {
	a := New(DefaultPolicy())
	a.SetPolicy(Policy{ThrottleThreshold: 2, BlockThreshold: 4})
	if a.Evaluate(3) != ActionThrottle {
		t.Fatal("expected throttle")
	}
	if a.Evaluate(4) != ActionBlock {
		t.Fatal("expected block")
	}
}
