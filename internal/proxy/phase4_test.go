package proxy

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
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
	// D61: quarantine is a block-mode action. In block mode the critical chain
	// creates the entry; the detection record is emitted in both modes.
	srv := newTestServer(t, config.ProfileMax, config.ModeBlock)
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
		t.Fatal("subject should be auto-quarantined after critical chain in block mode")
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

// TestPhase4NoQuarantineInDetectMode is the D61 regression test: in detect mode
// the critical-chain DETECT record must still be emitted, and no quarantine
// entry may be created.
func TestPhase4NoQuarantineInDetectMode(t *testing.T) {
	srv := newTestServer(t, config.ProfileMax, config.ModeDetect)
	ip := "9.8.7.6:1234"
	normIP := "9.8.7.6"

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	for _, target := range []string{"/?id=1%20OR%201=1--", "/../../etc/passwd"} {
		req := httptest.NewRequest("GET", target, nil)
		req.RemoteAddr = ip
		rr := httptest.NewRecorder()
		srv.handleRequest(rr, req)
	}

	if srv.quarantine.Size() != 0 {
		t.Fatalf("detect mode must not quarantine, size=%d", srv.quarantine.Size())
	}
	if srv.quarantine.IsQuarantined(normIP) {
		t.Fatal("detect mode must not quarantine the subject")
	}
	if !strings.Contains(buf.String(), "DETECT") {
		t.Fatal("detect mode must still emit the critical-chain DETECT record")
	}
}

// D66: traversal is content-gated. detect -> DETECT emitted and the request is
// forwarded (not 400); block -> 400 with X-Request-ID.
func TestTraversalDetectModeEmitsAndForwards(t *testing.T) {
	srv := newTestServer(t, config.ProfileMax, config.ModeDetect)
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	req := httptest.NewRequest("GET", "/file%2freadme.txt", nil)
	req.RemoteAddr = "4.4.4.4:1234"
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)

	if rr.Code == http.StatusBadRequest {
		t.Fatalf("detect mode must not block traversal, got 400")
	}
	if !strings.Contains(buf.String(), "waf-traversal-400") {
		t.Fatal("detect mode must emit the traversal DETECT record")
	}
	if rr.Header().Get("X-Request-ID") == "" {
		t.Fatal("traversal response must carry X-Request-ID in detect mode")
	}
}

func TestTraversalBlockMode400(t *testing.T) {
	srv := newTestServer(t, config.ProfileMax, config.ModeBlock)
	req := httptest.NewRequest("GET", "/file%2freadme.txt", nil)
	req.RemoteAddr = "4.4.4.5:1234"
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("block mode must return 400, got %d", rr.Code)
	}
	if rr.Header().Get("X-Request-ID") == "" {
		t.Fatal("traversal 400 must carry X-Request-ID")
	}
}

// F-18: a traversal payload that also matches a content rule must produce ONE
// DETECT record, not two carrying the same request_id. A join that counts
// DETECT *lines* rather than distinct request_ids over-counts detections.
func TestTraversalNoDoubleDetectWhenRuleMatched(t *testing.T) {
	srv := newTestServer(t, config.ProfileLite, config.ModeDetect)
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	req := httptest.NewRequest("GET", "/file%2e%2e%2fetc%2fpasswd", nil)
	req.RemoteAddr = "4.4.4.6:1234"
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)

	if strings.Contains(buf.String(), "waf-traversal-400") {
		t.Fatal("traversal record must be suppressed when a content rule already matched (F-18)")
	}
	if !strings.Contains(buf.String(), "trav-") {
		t.Fatal("the content-rule DETECT record must still be emitted")
	}
}

// V-F10: blocks_total{traversal} counts real blocks. A detect-mode traversal is
// forwarded, so it must not increment the block counter.
func TestTraversalCounterOnlyInBlockMode(t *testing.T) {
	srv := newTestServer(t, config.ProfileMax, config.ModeDetect)
	if srv.metrics == nil {
		t.Fatal("metrics should be wired")
	}
	srv.handleRequest(httptest.NewRecorder(),
		httptest.NewRequest("GET", "/file%2freadme.txt", nil))
	if got := srv.metrics.Snapshot().BlocksTotal["traversal"]; got != 0 {
		t.Fatalf("detect mode must not count a traversal block, got %d", got)
	}

	srv2 := newTestServer(t, config.ProfileMax, config.ModeBlock)
	srv2.handleRequest(httptest.NewRecorder(),
		httptest.NewRequest("GET", "/file%2freadme.txt", nil))
	if got := srv2.metrics.Snapshot().BlocksTotal["traversal"]; got != 1 {
		t.Fatalf("block mode must count the traversal block, got %d", got)
	}
}
