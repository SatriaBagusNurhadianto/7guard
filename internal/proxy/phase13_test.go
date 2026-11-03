package proxy

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func buildPhase13(t *testing.T, mode string, handler http.HandlerFunc) (*Server, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(handler)
	cfg := config.Default()
	cfg.Profile = config.ProfileFull
	cfg.RulesDir = "../../rules"
	cfg.Upstream = up.URL
	cfg.RequestBodyInspectionMode = mode
	cfg.MaxBodySize = 10 << 20
	cfg.EgressMode = "detect"
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv, up
}

func TestPhase13DetectMode(t *testing.T) {
	srv, up := buildPhase13(t, "detect", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	defer up.Close()
	body := strings.NewReader("SELECT * FROM users")
	req := httptest.NewRequest("POST", "/", body)
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != 200 {
		t.Errorf("detect mode should allow, got %d", rr.Code)
	}
}

func TestPhase13BlockMode(t *testing.T) {
	srv, up := buildPhase13(t, "block", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	defer up.Close()
	body := strings.NewReader("UNION SELECT 1,2,3")
	req := httptest.NewRequest("POST", "/", body)
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != 400 {
		t.Errorf("block mode should return 400, got %d", rr.Code)
	}
}

func TestPhase13Oversized(t *testing.T) {
	srv, up := buildPhase13(t, "block", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	defer up.Close()
	big := bytes.Repeat([]byte("A"), 2<<20)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(big))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != 413 {
		t.Errorf("oversized should return 413, got %d", rr.Code)
	}
}

func TestPhase13Compressed(t *testing.T) {
	srv, up := buildPhase13(t, "block", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	defer up.Close()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte("UNION SELECT 1,2,3"))
	gz.Close()
	req := httptest.NewRequest("POST", "/", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Encoding", "gzip")
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != 400 {
		t.Errorf("compressed injection should be blocked, got %d", rr.Code)
	}
}

func TestPhase13BinaryPassthrough(t *testing.T) {
	srv, up := buildPhase13(t, "block", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	defer up.Close()
	body := strings.NewReader("SELECT * FROM users")
	req := httptest.NewRequest("POST", "/", body)
	req.Header.Set("Content-Type", "image/png")
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != 200 {
		t.Errorf("binary should pass through, got %d", rr.Code)
	}
}
