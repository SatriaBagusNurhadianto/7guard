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

func newOutcomeServer(t *testing.T, mode string) (*Server, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
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

// F-25: an inspection record must carry what happened, not what was configured.
// The old line printed `action=%s mode=%s` fed with the same value twice, so the
// field named `action` carried no information at all.
func TestRequestInspectRecordCarriesOutcome(t *testing.T) {
	cases := []struct {
		mode, want string
	}{
		{"detect", OutcomeDetected},
		{"block", OutcomeBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			srv, up := newOutcomeServer(t, tc.mode)
			defer up.Close()

			var buf bytes.Buffer
			prev := log.Writer()
			log.SetOutput(&buf)
			defer log.SetOutput(prev)

			req := httptest.NewRequest("POST", "/", strings.NewReader("1 UNION SELECT password FROM users"))
			req.Header.Set("Content-Type", "text/plain")
			rr := httptest.NewRecorder()
			srv.handleRequest(rr, req)

			line := buf.String()
			if !strings.Contains(line, "REQUEST_INSPECT:") {
				t.Fatalf("no REQUEST_INSPECT record emitted; log was %q", line)
			}
			rec := line[strings.Index(line, "REQUEST_INSPECT:"):]
			rec = rec[:strings.IndexByte(rec, '\n')]
			if !strings.Contains(rec, "outcome="+tc.want) {
				t.Errorf("record outcome: want %q present in %q", tc.want, rec)
			}
			if !strings.Contains(rec, "mode="+tc.mode) {
				t.Errorf("record mode: want %q present in %q", tc.mode, rec)
			}
			if strings.Contains(rec, "action=") {
				t.Errorf("record still carries the removed `action` field: %q", rec)
			}
		})
	}
}

// The SSRF dial refusal used to print a hard-coded `action=block` with no
// request id, so an SSRF 502 could not be joined to the request that caused it.
func TestSSRFRecordCarriesRequestIDAndOutcome(t *testing.T) {
	cases := []struct{ mode, want string }{
		{"detect", OutcomeDetected},
		{"block", OutcomeRefused},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
			}))
			defer up.Close()

			cfg := config.Default()
			cfg.Profile = config.ProfileFull
			cfg.RulesDir = "../../rules"
			cfg.Upstream = up.URL // loopback is inside a blocked range
			cfg.SSRFMode = tc.mode
			cfg.EgressMode = tc.mode
			cfg.Validate()
			srv, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}

			var buf bytes.Buffer
			prev := log.Writer()
			log.SetOutput(&buf)
			defer log.SetOutput(prev)

			rr := httptest.NewRecorder()
			srv.handleRequest(rr, httptest.NewRequest("GET", "/", nil))

			logs := buf.String()
			if !strings.Contains(logs, "SSRF:") {
				t.Fatalf("no SSRF record emitted; log was %q", logs)
			}
			rec := logs[strings.Index(logs, "SSRF:"):]
			rec = rec[:strings.IndexByte(rec, '\n')]

			if !strings.Contains(rec, "outcome="+tc.want) {
				t.Errorf("SSRF outcome: want %q in %q", tc.want, rec)
			}
			wantID := rr.Header().Get("X-Request-ID")
			if wantID == "" {
				t.Fatal("response carried no X-Request-ID")
			}
			if !strings.Contains(rec, "request_id="+wantID) {
				t.Errorf("SSRF record is not joinable: want request_id=%s in %q", wantID, rec)
			}
			if strings.Contains(rec, "action=") {
				t.Errorf("SSRF record still carries the removed `action` field: %q", rec)
			}
		})
	}
}
