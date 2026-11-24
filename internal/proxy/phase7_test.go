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
	// F-26: this server runs egress in detect mode, so the deny verdict is
	// counted as a detection. The old assertion here read >=1 on
	// egress_denied_total and therefore encoded the defect F-26 closes.
	if snap.EgressDetectedTotal["allowlist"] < 1 {
		t.Errorf("egress_detected_total[allowlist] = %d, want >=1", snap.EgressDetectedTotal["allowlist"])
	}
	if snap.EgressDeniedTotal["allowlist"] != 0 {
		t.Errorf("detect mode counted a denial that never happened: egress_denied_total[allowlist] = %d", snap.EgressDeniedTotal["allowlist"])
	}

	// Block mode is the counterpart: the same verdict must be a real denial.
	cfg.Mode = config.ModeBlock
	cfg.EgressMode = "block"
	cfg.Validate()
	blockSrv, err := New(cfg)
	if err != nil {
		t.Fatalf("New (block) failed: %v", err)
	}
	brr := httptest.NewRecorder()
	blockSrv.handleRequest(brr, httptest.NewRequest("GET", "/", nil))
	bsnap := blockSrv.metrics.Snapshot()
	if bsnap.EgressDeniedTotal["allowlist"] < 1 {
		t.Errorf("block mode: egress_denied_total[allowlist] = %d, want >=1", bsnap.EgressDeniedTotal["allowlist"])
	}
	if bsnap.EgressDetectedTotal["allowlist"] != 0 {
		t.Errorf("block mode must not also count a detection: egress_detected_total[allowlist] = %d", bsnap.EgressDetectedTotal["allowlist"])
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
	if _, ok := out["egress_detected_total"]; !ok {
		t.Error("missing egress_detected_total in /metrics")
	}
}
