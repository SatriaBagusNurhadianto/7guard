package proxy

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func refusalDelta(srv *Server, before int64, kind string) int64 {
	return srv.metrics.Snapshot().RefusalsTotal[kind] - before
}

func newRefusalServer(t *testing.T, jwtSecret, bodyMode string, reqBodyMax int64) (*Server, *httptest.Server) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	cfg := config.Default()
	cfg.Profile = config.ProfileFull
	cfg.RulesDir = "../../rules"
	cfg.Upstream = up.URL
	cfg.EgressMode = "detect"
	cfg.RequestBodyInspectionMode = bodyMode
	if reqBodyMax > 0 {
		cfg.RequestBodyMaxBytes = reqBodyMax
	}
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

// The seven in-handler refusal sites must each increment their counter AND emit
// a record carrying the same request id as the response, so the refusal joins
// to its request (the tier 3 contract, applied to refusals).
func TestRefusalRecordsCarryRequestIDAndCounters(t *testing.T) {
	cases := []struct {
		name      string
		kind      string
		jwtSecret string
		bodyMode  string
		maxBody   int64
		request   func() *http.Request
	}{
		{
			name: "framing", kind: "framing",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.TransferEncoding = []string{"chunked"}
				return r
			},
		},
		{
			name: "method-not-allowed", kind: "method_not_allowed",
			request: func() *http.Request {
				return httptest.NewRequest("TRACE", "/", nil)
			},
		},
		{
			name: "jwt-missing", kind: "jwt_missing", jwtSecret: "test-secret",
			request: func() *http.Request { return httptest.NewRequest("GET", "/", nil) },
		},
		{
			name: "jwt-format", kind: "jwt_format", jwtSecret: "test-secret",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Set("Authorization", "Basic abc")
				return r
			},
		},
		{
			name: "jwt-invalid", kind: "jwt_invalid", jwtSecret: "test-secret",
			request: func() *http.Request {
				r := httptest.NewRequest("GET", "/", nil)
				r.Header.Set("Authorization", "Bearer not-a-token")
				return r
			},
		},
		{
			name: "body-too-large", kind: "body_too_large", bodyMode: config.RequestBodyInspectionModeBlock, maxBody: 64, // RequestBodyMaxBytes; MaxBodySize stays at its default
			request: func() *http.Request {
				r := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("A", 200)))
				r.Header.Set("Content-Type", "text/plain")
				return r
			},
		},
		{
			name: "body-read-error", kind: "body_read_error", bodyMode: config.RequestBodyInspectionModeBlock,
			request: func() *http.Request {
				r := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("A", 8)))
				r.Header.Set("Content-Type", "text/plain")
				r.Body = errReadCloser{}
				return r
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, up := newRefusalServer(t, tc.jwtSecret, tc.bodyMode, tc.maxBody)
			defer up.Close()

			logs := captureLogs(t)
			before := srv.metrics.Snapshot().RefusalsTotal[tc.kind]
			rr := httptest.NewRecorder()
			srv.handleRequest(rr, tc.request())
			if got := refusalDelta(srv, before, tc.kind); got != 1 {
				t.Errorf("refusals_total[%s] delta = %d, want 1", tc.kind, got)
			}

			wantID := rr.Header().Get("X-Request-ID")
			if wantID == "" {
				t.Fatalf("response carried no X-Request-ID, so the record cannot join")
			}
			if rec := logs.String(); !strings.Contains(rec, "REFUSED: request_id="+wantID+" kind="+tc.kind) {
				t.Errorf("no joinable REFUSED record for kind=%s with request_id=%s; logs were:\n%s", tc.kind, wantID, rec)
			}
		})
	}
}

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("synthetic body read failure") }
func (errReadCloser) Close() error             { return nil }

// The four aux sites (/health, /metrics wrapper, disabled /metrics) sit outside
// handleRequest, so no request row can exist for them: they are counted only and
// must NOT be given an id that would look joinable. Both /metrics
// configurations are mutually exclusive, so this runs two real route tables.
func TestAuxRefusalsAreCountedWithoutAJoinableID(t *testing.T) {
	makeServer := func(t *testing.T, token string) (*Server, *httptest.Server) {
		t.Helper()
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}))
		cfg := config.Default()
		cfg.Profile = config.ProfileFull
		cfg.RulesDir = "../../rules"
		cfg.Upstream = up.URL
		cfg.EgressMode = "detect"
		if token != "" {
			cfg.MetricsAuthToken = token
		}
		cfg.Validate()
		srv, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return srv, httptest.NewServer(srv.routes())
	}

	noToken, noTokenUp := makeServer(t, "")
	defer noTokenUp.Close()
	withToken, withTokenUp := makeServer(t, "s3cret")
	defer withTokenUp.Close()

	call := func(t *testing.T, url, method, bearer string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	assertAux := func(t *testing.T, kind string, srv *Server, before int64, resp *http.Response) {
		t.Helper()
		if got := refusalDelta(srv, before, kind); got != 1 {
			t.Errorf("refusals_total[%s] delta = %d, want 1", kind, got)
		}
		if id := resp.Header.Get("X-Request-ID"); id != "" {
			t.Errorf("aux refusal %s carried X-Request-ID=%q; no request row exists to join to", kind, id)
		}
	}

	// Instance 1 (no token): the fail-closed handler is registered.
	b1 := noToken.metrics.Snapshot().RefusalsTotal["metrics_disabled"]
	resp := call(t, noTokenUp.URL+"/metrics", "GET", "")
	assertAux(t, "metrics_disabled", noToken, b1, resp)
	_ = resp.Body.Close()
	// The wrapper is absent on this instance, so its reason must not move.
	if v := noToken.metrics.Snapshot().RefusalsTotal["metrics_auth"]; v != 0 {
		t.Errorf("metrics_auth fired on the no-token instance: %d", v)
	}

	// Instance 2 (token set): the wrapper is registered instead.
	b2 := withToken.metrics.Snapshot().RefusalsTotal["metrics_auth"]
	resp = call(t, withTokenUp.URL+"/metrics", "GET", "wrong")
	assertAux(t, "metrics_auth", withToken, b2, resp)
	_ = resp.Body.Close()

	b3 := withToken.metrics.Snapshot().RefusalsTotal["metrics_method"]
	resp = call(t, withTokenUp.URL+"/metrics", "POST", "s3cret")
	assertAux(t, "metrics_method", withToken, b3, resp)
	_ = resp.Body.Close()

	b4 := withToken.metrics.Snapshot().RefusalsTotal["health_method"]
	resp = call(t, withTokenUp.URL+"/health", "TRACE", "")
	assertAux(t, "health_method", withToken, b4, resp)
	_ = resp.Body.Close()

	// Mutual exclusivity: the token instance never registers the disabled handler.
	if v := withToken.metrics.Snapshot().RefusalsTotal["metrics_disabled"]; v != 0 {
		t.Errorf("metrics_disabled fired on the token instance: %d", v)
	}
}
