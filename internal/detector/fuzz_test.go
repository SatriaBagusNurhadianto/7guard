package detector

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/rules"
)

func FuzzNormalize(f *testing.F) {
	seeds := []string{
		"",
		"hello",
		"%27%20OR%201%3D1",
		"\xc0\xae\xc0\xaf",
		"\xe0\x80\xae",
		"\x00\x00",
		"UNION SELECT",
		strings.Repeat("a", 10000),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// Must not panic; output must be a string (trivially).
		_ = singleDecode(s)
	})
}

func FuzzDetect(f *testing.F) {
	rs, err := rules.LoadRules("../../rules")
	if err != nil {
		f.Fatal(err)
	}
	d := New(rs)
	seeds := []string{
		"1 UNION SELECT username,password FROM users",
		"1' OR 1=1 --",
		"<script>alert(1)</script>",
		"../../../etc/passwd",
		"",
		"\x00",
		"%00",
		strings.Repeat("a", 5000),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, _ := url.Parse("http://example.com/")
		req := &http.Request{
			Method: "GET",
			URL:    u,
			Header: http.Header{},
			Body:   io.NopCloser(bytes.NewBufferString(s)),
		}
		req.URL.RawQuery = s
		req.URL.Path = "/" + s
		// Normalize path to avoid invalid URLs causing downstream issues; ignore parse errors.
		matches := d.Detect(req)
		for _, m := range matches {
			if m.Rule.ID == "" {
				t.Errorf("match with empty rule ID")
			}
			if m.Location != "path" && m.Location != "query" && m.Location != "body" {
				t.Errorf("invalid location %q", m.Location)
			}
		}
	})
}
