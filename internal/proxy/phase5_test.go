package proxy

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
