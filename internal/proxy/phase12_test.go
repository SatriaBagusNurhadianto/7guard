package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func buildPhase12(t *testing.T, mode string, handler http.HandlerFunc) (*Server, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(handler)
	cfg := config.Default()
	cfg.Profile = config.ProfileFull
	cfg.RulesDir = "../../rules"
	cfg.Upstream = up.URL
	cfg.SSRFMode = mode
	cfg.EgressMode = "detect"
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv, up
}

func TestPhase12SSRFBlockLoopback(t *testing.T) {
	// upstream is localhost; with block mode, SSRF should block the dial
	srv, up := buildPhase12(t, "block", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	// The dial to localhost should be blocked → 502 or 503
	if rr.Code == 200 {
		t.Errorf("expected non-200 (blocked), got 200")
	}
}

func TestPhase12SSRFDetectMode(t *testing.T) {
	srv, up := buildPhase12(t, "detect", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != 200 {
		t.Errorf("detect mode should allow, got %d", rr.Code)
	}
}
