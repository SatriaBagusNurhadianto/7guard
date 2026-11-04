package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func buildSecHardening(t *testing.T, mode, jwtSecret string, handler http.HandlerFunc) (*Server, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(handler)
	cfg := config.Default()
	cfg.Profile = config.ProfileFull
	cfg.RulesDir = "../../rules"
	cfg.Upstream = up.URL
	cfg.RequestBodyInspectionMode = mode
	cfg.MaxBodySize = 10 << 20
	cfg.EgressMode = "detect"
	if jwtSecret != "" {
		cfg.JWTSecret = jwtSecret
	}
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv, up
}

func TestSecJWTNoErrorLeak(t *testing.T) {
	srv, up := buildSecHardening(t, "detect", "supersecret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer this.is.not.a.valid.token")
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if body["error"] != "invalid token" {
		t.Errorf("expected generic 'invalid token', got %v", body["error"])
	}
	// ensure no internal error detail leaked
	if strings.Contains(rr.Body.String(), "signature") || strings.Contains(rr.Body.String(), "token contains") {
		t.Errorf("internal JWT error detail leaked: %s", rr.Body.String())
	}
}

func TestSecFailClosedBadGzipBlock(t *testing.T) {
	srv, up := buildSecHardening(t, "block", "", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	defer up.Close()
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte("not a gzip stream")))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Encoding", "gzip")
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 fail-closed, got %d", rr.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if body["error"] != "request body could not be inspected" {
		t.Errorf("expected fail-closed message, got %v", body["error"])
	}
}

func TestSecFailClosedBadGzipDetect(t *testing.T) {
	srv, up := buildSecHardening(t, "detect", "", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	defer up.Close()
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte("not a gzip stream")))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Encoding", "gzip")
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	// detect mode must not fail closed; upstream returns 200
	if rr.Code != 200 {
		t.Fatalf("detect mode should not fail-closed, got %d", rr.Code)
	}
}
