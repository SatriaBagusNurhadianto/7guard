package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func newTestServer(t *testing.T, profile string, mode string) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.Profile = profile
	cfg.Mode = mode
	if mode == config.ModeBlock {
		cfg.ConfirmBlock = true
	}
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return srv
}

func TestPhase4QuarantineBlocksWhenEnabled(t *testing.T) {
	srv := newTestServer(t, config.ProfileMax, config.ModeDetect)
	if srv.quarantine == nil {
		t.Fatal("quarantine should be wired for max profile")
	}
	srv.quarantine.Quarantine("1.2.3.4", "test", 10*time.Minute)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for quarantined client, got %d", rr.Code)
	}
}

func TestPhase4QuarantineNoopWhenDisabled(t *testing.T) {
	srv := newTestServer(t, config.ProfileLite, config.ModeDetect)
	if srv.quarantine != nil {
		t.Fatal("quarantine should be nil for lite profile")
	}
	if srv.behavioral != nil {
		t.Fatal("behavioral should be nil for lite profile")
	}
	if srv.adaptive != nil {
		t.Fatal("adaptive should be nil for lite profile")
	}
}

func TestPhase4AdaptiveBlocksWhenEnabled(t *testing.T) {
	srv := newTestServer(t, config.ProfileMax, config.ModeBlock)
	if srv.adaptive == nil {
		t.Fatal("adaptive should be wired for max profile")
	}
	// A SQLi payload that scores >= block threshold (10).
	req := httptest.NewRequest("GET", "/?id=1%20OR%201=1--", nil)
	req.RemoteAddr = "5.6.7.8:9999"
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 from adaptive defense, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestPhase4BehavioralWiredWhenEnabled(t *testing.T) {
	srv := newTestServer(t, config.ProfileMax, config.ModeDetect)
	if srv.behavioral == nil {
		t.Fatal("behavioral should be wired for max profile")
	}
}

func TestPhase4QuarantineCrossPort(t *testing.T) {
	srv := newTestServer(t, config.ProfileMax, config.ModeDetect)
	srv.quarantine.Quarantine("9.9.9.9", "test", 10*time.Minute)

	for _, port := range []string{"9.9.9.9:1111", "9.9.9.9:2222"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = port
		rr := httptest.NewRecorder()
		srv.handleRequest(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("port %s: expected 403, got %d", port, rr.Code)
		}
	}
}

func TestPhase4AdaptiveDetectModeNotBlocked(t *testing.T) {
	srv := newTestServer(t, config.ProfileMax, config.ModeDetect)
	req := httptest.NewRequest("GET", "/?id=1%20OR%201=1--", nil)
	req.RemoteAddr = "7.7.7.7:1234"
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code == http.StatusForbidden {
		t.Errorf("detect mode should not block via adaptive, got 403")
	}
}

func TestPhase4AutoQuarantineOnCriticalChain(t *testing.T) {
	srv := newTestServer(t, config.ProfileMax, config.ModeDetect)
	ip := "9.8.7.6:1234"
	normIP := "9.8.7.6"

	// Request 1: SQLi
	req1 := httptest.NewRequest("GET", "/?id=1%20OR%201=1--", nil)
	req1.RemoteAddr = ip
	rr1 := httptest.NewRecorder()
	srv.handleRequest(rr1, req1)

	// Request 2: path traversal -> should trigger critical chain + auto-quarantine
	req2 := httptest.NewRequest("GET", "/../../etc/passwd", nil)
	req2.RemoteAddr = ip
	rr2 := httptest.NewRecorder()
	srv.handleRequest(rr2, req2)

	if !srv.quarantine.IsQuarantined(normIP) {
		t.Fatal("subject should be auto-quarantined after critical chain")
	}

	// Request 3: same IP (different port) should be blocked
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "9.8.7.6:9999"
	rr3 := httptest.NewRecorder()
	srv.handleRequest(rr3, req3)
	if rr3.Code != http.StatusForbidden {
		t.Errorf("expected 403 for auto-quarantined client, got %d", rr3.Code)
	}
}
