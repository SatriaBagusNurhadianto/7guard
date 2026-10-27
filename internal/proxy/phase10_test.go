package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

// Helper to build a server with a given upstream handler.
func buildPhase10(t *testing.T, mode, onLeak string, handler http.HandlerFunc) (*Server, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(handler)
	cfg := config.Default()
	cfg.Profile = config.ProfileFull
	cfg.RulesDir = "../../rules"
	cfg.Upstream = up.URL
	cfg.ResponseInspectionMode = mode
	cfg.ResponseInspectionOnLeak = onLeak
	cfg.ResponseInspectionMaxBodyBytes = 1024
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv, up
}

func TestPhase10DetectModeLogsAndMetrics(t *testing.T) {
	srv, up := buildPhase10(t, "detect", "replace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("contact: foo@example.com"))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "foo@example.com") {
		t.Error("detect mode should pass body through")
	}
	snap := srv.metrics.Snapshot()
	if snap.ResponseLeakTotal["pii"] != 1 {
		t.Errorf("response_leak_total[pii] = %d, want 1", snap.ResponseLeakTotal["pii"])
	}
}

func TestPhase10BlockModeStrip(t *testing.T) {
	srv, up := buildPhase10(t, "block", "replace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("secret: AKIAIOSFODNN7EXAMPLE"))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if strings.Contains(rr.Body.String(), "AKIAIOSFODNN7EXAMPLE") {
		t.Error("block mode should strip secret")
	}
	if !strings.Contains(rr.Body.String(), "[REDACTED]") {
		t.Errorf("expected redaction token, got %q", rr.Body.String())
	}
}

func TestPhase10BlockMode502(t *testing.T) {
	srv, up := buildPhase10(t, "block", "block", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("AKIAIOSFODNN7EXAMPLE"))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rr.Code)
	}
}

func TestPhase10ContentTypeGatingBinary(t *testing.T) {
	body := []byte{0x89, 0x50, 0x4e, 0x47} // PNG-ish
	srv, up := buildPhase10(t, "detect", "replace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(body)
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if !bytes.Equal(rr.Body.Bytes(), body) {
		t.Error("binary body should pass through byte-for-byte")
	}
	snap := srv.metrics.Snapshot()
	if snap.ResponseLeakTotal["pii"] != 0 || snap.ResponseLeakTotal["secret"] != 0 {
		t.Error("no leak metric expected for binary")
	}
}

func TestPhase10RedirectPassThrough(t *testing.T) {
	srv, up := buildPhase10(t, "detect", "replace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/elsewhere")
		w.WriteHeader(http.StatusFound)
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rr.Code)
	}
	if rr.Header().Get("Location") != "https://example.com/elsewhere" {
		t.Error("Location header should pass through")
	}
}

func TestPhase10ErrorStatusPreserved(t *testing.T) {
	srv, up := buildPhase10(t, "detect", "replace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("panic: runtime error\ngoroutine 1"))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

func TestPhase10TruncatedNoDataLoss(t *testing.T) {
	// body larger than cap (1024)
	big := strings.Repeat("a", 2000)
	srv, up := buildPhase10(t, "detect", "replace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(big))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Body.Len() != len(big) {
		t.Errorf("body length = %d, want %d (no data loss)", rr.Body.Len(), len(big))
	}
}

func TestPhase10CompressedSkip(t *testing.T) {
	srv, up := buildPhase10(t, "detect", "replace", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte("not really gzip but marked"))
	})
	defer up.Close()
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Header().Get("Content-Encoding") != "gzip" {
		t.Error("Content-Encoding should pass through")
	}
}
