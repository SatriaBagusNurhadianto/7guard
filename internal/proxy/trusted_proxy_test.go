package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func qaNewServer(t *testing.T, trusted []string) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.Profile = config.ProfileLite
	cfg.Mode = config.ModeDetect
	cfg.TrustedProxies = trusted
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return srv
}

func TestQA_TrustedProxy_EmptyNeverTrusts(t *testing.T) {
	srv := qaNewServer(t, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	got := srv.clientIPFromRequest(req)
	if got != "10.0.0.1" {
		t.Fatalf("empty trust list must ignore XFF, got %q want %q", got, "10.0.0.1")
	}
}

func TestQA_TrustedProxy_SpoofedXFFFromUntrustedPeer(t *testing.T) {
	srv := qaNewServer(t, []string{"10.0.0.99"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	got := srv.clientIPFromRequest(req)
	if got != "10.0.0.1" {
		t.Fatalf("spoofed XFF from untrusted peer must be ignored, got %q", got)
	}
}

func TestQA_TrustedProxy_TrustedIPUsesXFF(t *testing.T) {
	srv := qaNewServer(t, []string{"10.0.0.1"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.2")
	got := srv.clientIPFromRequest(req)
	if got != "203.0.113.9" {
		t.Fatalf("trusted proxy must use first XFF IP, got %q", got)
	}
}

func TestQA_TrustedProxy_TrustedCIDRUsesXFF(t *testing.T) {
	srv := qaNewServer(t, []string{"10.0.0.0/24"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.5:9999"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	got := srv.clientIPFromRequest(req)
	if got != "198.51.100.7" {
		t.Fatalf("trusted CIDR must use XFF, got %q", got)
	}
}

func TestQA_TrustedProxy_TrustedUsesRealIPFallback(t *testing.T) {
	srv := qaNewServer(t, []string{"10.0.0.1"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Real-IP", "198.51.100.8")
	got := srv.clientIPFromRequest(req)
	if got != "198.51.100.8" {
		t.Fatalf("trusted proxy with no XFF should use X-Real-IP, got %q", got)
	}
}

func TestQA_TrustedProxy_UntrustedIgnoresRealIP(t *testing.T) {
	srv := qaNewServer(t, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	got := srv.clientIPFromRequest(req)
	if got != "10.0.0.1" {
		t.Fatalf("untrusted peer must ignore X-Real-IP, got %q", got)
	}
}

func TestQA_TrustedProxy_InvalidCIDREntrySkipped(t *testing.T) {
	srv := qaNewServer(t, []string{"not-a-cidr", "10.0.0.1"})
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	got := srv.clientIPFromRequest(req)
	if got != "203.0.113.9" {
		t.Fatalf("valid entry should still work after invalid one, got %q", got)
	}
}

func TestQA_TrustedProxy_NoPortRemoteAddr(t *testing.T) {
	srv := qaNewServer(t, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1"
	got := srv.clientIPFromRequest(req)
	if got != "10.0.0.1" {
		t.Fatalf("no-port RemoteAddr should be returned as-is, got %q", got)
	}
}

func TestQA_MetricsFailClosed_NoToken(t *testing.T) {
	cfg := config.Default()
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.Profile = config.ProfileLite
	cfg.Mode = config.ModeDetect
	cfg.MetricsEnabled = true
	cfg.MetricsAuthToken = ""
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if srv.cfg.MetricsAuthToken != "" {
			srv.metricsAuthWrapper(srv.metrics.Handler)(w, r)
			return
		}
		http.Error(w, "metrics endpoint requires --metrics-auth-token", http.StatusForbidden)
	})
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-token /metrics should be 403, got %d", rr.Code)
	}
}
