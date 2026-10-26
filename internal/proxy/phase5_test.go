package proxy

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func TestPhase5MetricsEndpoint(t *testing.T) {
	srv := newTestServer(t, config.ProfileLite, config.ModeDetect)
	// one request to bump counter
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)

	mreq := httptest.NewRequest("GET", "/metrics", nil)
	if srv.metrics == nil {
		t.Fatal("metrics should be wired")
	}
	mrr2 := httptest.NewRecorder()
	srv.metrics.Handler(mrr2, mreq)
	if mrr2.Code != http.StatusOK {
		t.Fatalf("status = %d", mrr2.Code)
	}
	var snap map[string]interface{}
	if err := json.Unmarshal(mrr2.Body.Bytes(), &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"requests_total", "blocks_total", "quarantined_subjects", "adaptive_actions_total", "rule_matches_total"} {
		if _, ok := snap[field]; !ok {
			t.Errorf("missing field %s", field)
		}
	}
	if v, _ := snap["requests_total"].(float64); v < 1 {
		t.Errorf("requests_total = %v, want >=1", snap["requests_total"])
	}
}

func TestPhase5NoSecretsInLog(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	srv := newTestServer(t, config.ProfileLite, config.ModeDetect)
	secret := "SUPERSECRET_TOKEN_VALUE_123"
	req := httptest.NewRequest("GET", "/?id=1%20OR%201=1--", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)

	if strings.Contains(buf.String(), secret) {
		t.Fatalf("secret leaked into log output")
	}
}

func TestPhase5QuarantinedGauge(t *testing.T) {
	srv := newTestServer(t, config.ProfileMax, config.ModeDetect)
	srv.quarantine.Quarantine("1.2.3.4", "test", 10*time.Minute)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if srv.metrics.Snapshot().QuarantinedSubjects != 1 {
		t.Errorf("gauge = %d, want 1", srv.metrics.Snapshot().QuarantinedSubjects)
	}
}

func TestPhase6MetricsAuth(t *testing.T) {
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.Profile = config.ProfileLite
	cfg.Mode = config.ModeDetect
	cfg.MetricsEnabled = true
	cfg.MetricsAuthToken = "secret-token"
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// no token -> 401
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	srv.metricsAuthWrapper(srv.metrics.Handler)(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", rr.Code)
	}

	// wrong token -> 401
	req2 := httptest.NewRequest("GET", "/metrics", nil)
	req2.Header.Set("Authorization", "Bearer wrong")
	rr2 := httptest.NewRecorder()
	srv.metricsAuthWrapper(srv.metrics.Handler)(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 with wrong token, got %d", rr2.Code)
	}

	// correct token -> 200
	req3 := httptest.NewRequest("GET", "/metrics", nil)
	req3.Header.Set("Authorization", "Bearer secret-token")
	rr3 := httptest.NewRecorder()
	srv.metricsAuthWrapper(srv.metrics.Handler)(rr3, req3)
	if rr3.Code != http.StatusOK {
		t.Errorf("expected 200 with correct token, got %d", rr3.Code)
	}
}
