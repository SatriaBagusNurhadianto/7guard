package proxy

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func TestPhase7EgressMetricsInMetrics(t *testing.T) {
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.Profile = config.ProfileFull
	cfg.Mode = config.ModeDetect
	cfg.EgressMode = "detect"
	cfg.EgressAllowedHosts = []string{"api.example.com"} // localhost not allowed
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if srv.egress == nil {
		t.Fatal("egress should be wired for full profile")
	}

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req) // triggers upstream dial -> egress check -> denied (detect allows dial, connection refused)

	if srv.metrics == nil {
		t.Fatal("metrics should be wired")
	}
	snap := srv.metrics.Snapshot()
	if _, ok := snap.EgressDeniedTotal["allowlist"]; !ok {
		t.Errorf("egress_denied_total missing allowlist label: %v", snap.EgressDeniedTotal)
	}
	if snap.EgressDeniedTotal["allowlist"] < 1 {
		t.Errorf("egress_denied_total[allowlist] = %d, want >=1", snap.EgressDeniedTotal["allowlist"])
	}

	// /metrics endpoint returns egress fields
	mreq := httptest.NewRequest("GET", "/metrics", nil)
	mrr := httptest.NewRecorder()
	srv.metrics.Handler(mrr, mreq)
	var out map[string]interface{}
	if err := json.Unmarshal(mrr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := out["egress_allowed_total"]; !ok {
		t.Error("missing egress_allowed_total in /metrics")
	}
	if _, ok := out["egress_denied_total"]; !ok {
		t.Error("missing egress_denied_total in /metrics")
	}
}
