package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestMetricsCountersAndSnapshot(t *testing.T) {
	m := New()
	m.IncRequests()
	m.IncRequests()
	m.IncBlock("waf")
	m.IncBlock("quarantine")
	m.IncAdaptive("allow")
	m.IncAdaptive("throttle")
	m.IncRuleMatch("sqli-or-true")

	snap := m.Snapshot()
	if snap.RequestsTotal != 2 {
		t.Errorf("requests_total = %d, want 2", snap.RequestsTotal)
	}
	if snap.BlocksTotal["waf"] != 1 || snap.BlocksTotal["quarantine"] != 1 {
		t.Errorf("blocks_total = %v", snap.BlocksTotal)
	}
	if snap.AdaptiveActionsTotal["allow"] != 1 || snap.AdaptiveActionsTotal["throttle"] != 1 {
		t.Errorf("adaptive = %v", snap.AdaptiveActionsTotal)
	}
	if snap.RuleMatchesTotal["sqli-or-true"] != 1 {
		t.Errorf("rule_matches = %v", snap.RuleMatchesTotal)
	}
	// stable labels present even at zero
	if _, ok := snap.BlocksTotal["adaptive"]; !ok {
		t.Error("missing adaptive block reason label")
	}
	if _, ok := snap.AdaptiveActionsTotal["block"]; !ok {
		t.Error("missing block adaptive action label")
	}
}

func TestMetricsHandlerJSON(t *testing.T) {
	m := New()
	m.IncRequests()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.Handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var snap Snapshot
	if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.RequestsTotal != 1 {
		t.Errorf("requests_total = %d", snap.RequestsTotal)
	}
}

func TestMetricsSchemaStability(t *testing.T) {
	m := New()
	m.IncRequests()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.Handler(rr, req)
	dec := json.NewDecoder(rr.Body)
	dec.DisallowUnknownFields()
	var snap Snapshot
	if err := dec.Decode(&snap); err != nil {
		t.Fatalf("schema mismatch: %v", err)
	}
}

func TestMetricsConcurrency(t *testing.T) {
	m := New()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.IncRequests()
			m.IncBlock("waf")
			m.IncRuleMatch("r1")
			_ = m.Snapshot()
		}()
	}
	wg.Wait()
	if m.Snapshot().RequestsTotal != 100 {
		t.Errorf("requests_total = %d, want 100", m.Snapshot().RequestsTotal)
	}
}
