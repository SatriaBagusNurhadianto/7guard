package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func checkSecHeaders(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := rr.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}

func buildSecHeaders(t *testing.T, mode string, rateLimit int, handler http.HandlerFunc) (*Server, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(handler)
	cfg := config.Default()
	cfg.Profile = config.ProfileFull
	cfg.RulesDir = "../../rules"
	cfg.Upstream = up.URL
	cfg.RequestBodyInspectionMode = mode
	cfg.MaxBodySize = 10 << 20
	cfg.EgressMode = "detect"
	cfg.RateLimit = rateLimit
	cfg.RateBurst = rateLimit
	if cfg.RateBurst < 1 {
		cfg.RateBurst = 1
	}
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv, up
}

func TestSecHeaders200(t *testing.T) {
	srv, up := buildSecHeaders(t, "detect", 600, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	checkSecHeaders(t, rr)
}

func TestSecHeaders400(t *testing.T) {
	srv, up := buildSecHeaders(t, "block", 600, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	defer up.Close()
	req := httptest.NewRequest("POST", "/", strings.NewReader("UNION SELECT 1,2,3"))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != 400 {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	checkSecHeaders(t, rr)
}

func TestSecHeaders413(t *testing.T) {
	srv, up := buildSecHeaders(t, "block", 600, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	defer up.Close()
	big := bytes.Repeat([]byte("A"), 2<<20)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(big))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != 413 {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
	checkSecHeaders(t, rr)
}

func TestSecHeaders429(t *testing.T) {
	srv, up := buildSecHeaders(t, "detect", 1, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	defer up.Close()
	// first request consumes the single allowed token
	req1 := httptest.NewRequest("GET", "/", nil)
	rr1 := httptest.NewRecorder()
	srv.handleRequest(rr1, req1)
	// second request should be rate-limited
	req2 := httptest.NewRequest("GET", "/", nil)
	rr2 := httptest.NewRecorder()
	srv.handleRequest(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr2.Code)
	}
	checkSecHeaders(t, rr2)
}
