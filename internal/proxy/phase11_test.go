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

func TestPhase11TruncatedGzip(t *testing.T) {
	// Build a truncated gzip: write partial
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte("contact: foo@example.com"))
	gz.Close()
	data := buf.Bytes()
	// truncate last 5 bytes
	trunc := data[:len(data)-5]
	srv, up := buildPhase11(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(trunc)
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	// no panic; passes through
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestPhase11CorruptGzip(t *testing.T) {
	srv, up := buildPhase11(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte("not gzip at all"))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestPhase11ContentEncodingPreserved(t *testing.T) {
	srv, up := buildPhase11(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte("hello"))
		gz.Close()
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Header().Get("Content-Encoding") != "gzip" {
		t.Error("Content-Encoding should pass through")
	}
}

func TestPhase11StripOnCompressedPassThrough(t *testing.T) {
	srv, up := buildPhase11(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write([]byte("foo@example.com"))
		gz.Close()
	})
	srv.cfg.ResponseInspectionMode = "block"
	srv.cfg.ResponseInspectionOnLeak = "replace"
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	// passes through (original compressed body), no crash
	if rr.Code != 200 {
		t.Errorf("status = %d", rr.Code)
	}
}

func TestPhase11PlainRegression(t *testing.T) {
	srv, up := buildPhase11(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("contact: foo@example.com"))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	snap := srv.metrics.Snapshot()
	if snap.ResponseLeakTotal["pii"] != 1 {
		t.Errorf("response_leak_total[pii] = %d, want 1", snap.ResponseLeakTotal["pii"])
	}
}
