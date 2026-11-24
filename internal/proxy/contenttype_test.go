package proxy

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

// F-29: the three matcher forms, stated explicitly.
func TestContentTypeMatcherForms(t *testing.T) {
	patterns := config.DefaultInspectionContentTypes
	cases := []struct {
		pattern, mediaType string
		want               bool
	}{
		// exact form
		{"image/svg+xml", "image/svg+xml", true},
		{"image/svg+xml", "image/png", false},
		// whole-subtype wildcard
		{"text/*", "text/html", true},
		{"text/*", "text/plain; charset=utf-8", true}, // parameters are stripped before matching
		{"text/*", "application/json", false},
		// structured-syntax suffix form
		{"application/*+json", "application/json", false}, // no suffix present
		{"application/*+json", "application/vnd.api+json", true},
		{"application/*+xml", "application/atom+xml", true},
		{"application/*+xml", "application/xml", false},
		// a bare "*" in the type half is not a form we claim; it must not match anything accidentally
		{"*/json", "application/json", false},
	}
	for _, tc := range cases {
		if got := contentTypeAllowed([]string{tc.pattern}, tc.mediaType); got != tc.want {
			t.Errorf("contentTypeAllowed(%q, %q) = %v, want %v", tc.pattern, tc.mediaType, got, tc.want)
		}
	}

	// The shipped default rule itself: SVG must be in it, by name.
	foundSVG := false
	for _, p := range patterns {
		if contentTypeAllowed([]string{p}, "image/svg+xml") {
			foundSVG = true
		}
	}
	if !foundSVG {
		t.Errorf("default inspection rule does not cover image/svg+xml: %v", patterns)
	}
}

// Both dimensions must consult the SAME rule. Before F-29 the request path read
// the response list and additionally OR-ed in "request list empty", so a
// configured response-only allowlist silently changed what uploads were scanned.
func TestRequestAndResponseShareOneRule(t *testing.T) {
	srv, up := newRefusalServer(t, "", config.RequestBodyInspectionModeDetect, 0)
	defer up.Close()
	got := srv.inspectionContentTypes()
	if len(got) == 0 {
		t.Fatal("no content-type rule resolved")
	}
	if !contentTypeAllowed(got, "image/svg+xml") {
		t.Errorf("shared rule does not inspect image/svg+xml: %v", got)
	}
}

// SVG is scriptable XML, so excluding it would silently stop uploads being
// scanned. Asserted on the wire for the request dimension.
func TestSVGUploadIsInspectedOnRequest(t *testing.T) {
	srv, up := newRefusalServer(t, "", config.RequestBodyInspectionModeDetect, 0)
	defer up.Close()

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	body := `<svg xmlns="http://www.w3.org/2000/svg"><script>1 UNION SELECT password FROM users</script></svg>`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "image/svg+xml")
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)

	if !strings.Contains(buf.String(), "REQUEST_INSPECT") || !strings.Contains(buf.String(), "sqli-union-select") {
		t.Errorf("image/svg+xml upload was not inspected; log was:\n%s", buf.String())
	}
}

// Same assertion for the response dimension: a leak inside an SVG response must
// be seen by the scanner. Scanning is asserted from the record; redaction is
// asserted separately under forced block, because OnLeak applies there.
func TestSVGResponseIsInspected(t *testing.T) {
	run := func(t *testing.T, mode string) (string, []byte) {
		t.Helper()
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/svg+xml")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><text>admin@example.com</text></svg>`))
		}))
		defer up.Close()

		cfg := config.Default()
		cfg.Profile = config.ProfileFull
		cfg.RulesDir = "../../rules"
		cfg.Upstream = up.URL
		cfg.EgressMode = config.EgressModeDetect
		cfg.SSRFMode = config.SSRFModeDetect
		cfg.ResponseInspectionMode = mode
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
		body, err := io.ReadAll(rr.Result().Body)
		if err != nil {
			t.Fatal(err)
		}
		return buf.String(), body
	}

	t.Run("detect-scans", func(t *testing.T) {
		logs, _ := run(t, config.ResponseInspectionModeDetect)
		if !strings.Contains(logs, "RESPONSE_LEAK") || !strings.Contains(logs, "content_type=image/svg+xml") {
			t.Errorf("image/svg+xml response was never scanned; log was:\n%s", logs)
		}
	})

	t.Run("block-redacts", func(t *testing.T) {
		logs, body := run(t, config.ResponseInspectionModeBlock)
		if !strings.Contains(logs, "types=[pii]") {
			t.Errorf("no leak detection recorded for image/svg+xml; log was:\n%s", logs)
		}
		if strings.Contains(string(body), "admin@example.com") {
			t.Errorf("image/svg+xml leak delivered intact under block (%d B)", len(body))
		}
	})
}
