package proxy

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func TestEgressFollowupDetectModeLog(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	cfg := config.Default()
	cfg.Profile = config.ProfileFull
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.EgressMode = "detect"
	cfg.EgressAllowedHosts = []string{"api.example.com"}
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req) // triggers egress check -> denied (detect allows dial)
	out := buf.String()
	if !strings.Contains(out, "EGRESS:") {
		t.Fatalf("expected EGRESS: log line, got: %s", out)
	}
	if !strings.Contains(out, `"action":"deny"`) {
		t.Errorf("expected action=deny in log: %s", out)
	}
	if !strings.Contains(out, `"mode":"detect"`) {
		t.Errorf("expected mode=detect in log: %s", out)
	}
}

func TestEgressFollowupCheckRedirectBlocksDeniedHost(t *testing.T) {
	cfg := config.Default()
	cfg.Profile = config.ProfileFull
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.EgressMode = "block"
	cfg.EgressAllowedHosts = []string{"api.example.com"}
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if srv.egress == nil {
		t.Fatal("egress should be wired")
	}
	// Verify CheckRedirect blocks a redirect to a denied host.
	req, _ := http.NewRequest("GET", "https://evil.com/cb", nil)
	via := []*http.Request{req}
	err = srv.egress.CheckRedirect(req, via)
	if err == nil {
		t.Fatal("expected redirect to denied host to be blocked")
	}
}

func TestEgressFollowupNoSecretsInLog(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	secret := "supersecrettoken12345"
	cfg := config.Default()
	cfg.Profile = config.ProfileFull
	cfg.RulesDir = "../../rules"
	cfg.Upstream = "http://localhost:9090"
	cfg.EgressMode = "detect"
	cfg.EgressAllowedHosts = []string{"api.example.com"}
	cfg.Validate()
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if strings.Contains(buf.String(), secret) {
		t.Error("secret leaked into egress log")
	}
}
