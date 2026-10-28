package proxy

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func buildPhase11(t *testing.T, handler http.HandlerFunc) (*Server, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(handler)
	cfg := config.Default()
	cfg.Profile = config.ProfileFull
	cfg.RulesDir = "../../rules"
	cfg.Upstream = up.URL
	cfg.ResponseInspectionMode = "detect"
	cfg.ResponseInspectionMaxBodyBytes = 1024
	cfg.ResponseInspectionDecompress = true
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv, up
}

func TestPhase11CompressedDetect(t *testing.T) {
	srv, up := buildPhase11(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte("contact: foo@example.com"))
		gz.Close()
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if !strings.Contains(rr.Body.String(), "foo@example.com") {
		// body passed through compressed; decompressed scan happened server-side
	}
	snap := srv.metrics.Snapshot()
	if snap.ResponseLeakTotal["pii"] != 1 {
		t.Errorf("response_leak_total[pii] = %d, want 1", snap.ResponseLeakTotal["pii"])
	}
	_ = io.Discard
	_ = bytes.NewBuffer
}

func TestPhase11CompressedBlock502(t *testing.T) {
	srv, up := buildPhase11(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
		gz.Close()
	})
	// switch to block mode
	srv.cfg.ResponseInspectionMode = "block"
	srv.cfg.ResponseInspectionOnLeak = "block"
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rr.Code)
	}
}

func TestPhase11DecompressDisabled(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte("foo@example.com"))
		gz.Close()
	}))
	cfg := config.Default()
	cfg.Profile = config.ProfileFull
	cfg.RulesDir = "../../rules"
	cfg.Upstream = up.URL
	cfg.ResponseInspectionMode = "detect"
	cfg.ResponseInspectionDecompress = false
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	// decompress disabled -> skipped, no pii metric
	snap := srv.metrics.Snapshot()
	if snap.ResponseLeakTotal["pii"] != 0 {
		t.Errorf("expected 0 pii (skipped), got %d", snap.ResponseLeakTotal["pii"])
	}
}
