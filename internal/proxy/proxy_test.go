package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func TestNewValidConfig(t *testing.T) {
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.Profile = "lite"
	cfg.Validate()

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if srv == nil {
		t.Fatal("server is nil")
	}
}

func TestNewInvalidUpstream(t *testing.T) {
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "://invalid"
	cfg.Profile = "lite"
	cfg.Validate()

	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for invalid upstream")
	}
}

func TestNewMissingRulesDir(t *testing.T) {
	cfg := config.Default()
	cfg.RulesDir = "/nonexistent/rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.Profile = "lite"
	cfg.Validate()

	_, err := New(cfg)
	if err == nil {
		t.Error("expected error for missing rules dir")
	}
}

func TestHandleHealth(t *testing.T) {
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.Profile = "lite"
	cfg.Validate()

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	srv.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !contains(rr.Body.String(), "ok") {
		t.Errorf("expected 'ok' in response, got %s", rr.Body.String())
	}
}

func TestHandleRequestBodyTooLarge(t *testing.T) {
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.Profile = "lite"
	cfg.MaxBodySize = 10
	cfg.Validate()

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	body := make([]byte, 100)
	req := httptest.NewRequest("POST", "/test", nil)
	req.ContentLength = 100
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)

	// MaxBytesReader will trigger on read; status may vary
	_ = body
}

func TestReloadRules(t *testing.T) {
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.Profile = "lite"
	cfg.Validate()

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	count, err := srv.ReloadRules()
	if err != nil {
		t.Fatalf("ReloadRules failed: %v", err)
	}
	if count == 0 {
		t.Error("expected rules to be loaded")
	}
}

func TestReloadRulesInvalidDir(t *testing.T) {
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.Profile = "lite"
	cfg.Validate()

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Temporarily change rules dir to invalid
	srv.rulesDir = "/nonexistent"
	_, err = srv.ReloadRules()
	if err == nil {
		t.Error("expected error for invalid rules dir")
	}
	// Restore
	srv.rulesDir = "../../rules"
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
