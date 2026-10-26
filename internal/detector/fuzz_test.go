package detector

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
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
		_ = singleDecode(s)
	})
}

func FuzzSingleDecode(f *testing.F) {
	f.Add("%27%20OR%201%3D1")
	f.Add("normal input")
	f.Add("")
	f.Add("%c0%ae%c0%af")
	f.Add("'; DROP TABLE users; --")
	f.Fuzz(func(t *testing.T, s string) {
		out := singleDecode(s)
		_ = out
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

func FuzzDetectString(f *testing.F) {
	rs, err := rules.LoadRules("../../rules")
	if err != nil {
		f.Skip("rules not available")
	}
	d := New(rs)
	f.Add("SELECT * FROM users")
	f.Add("<script>alert(1)</script>")
	f.Add("../../etc/passwd")
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		matches := d.DetectString(input)
		_ = matches
	})
}

func FuzzDetectRequest(f *testing.F) {
	rs, err := rules.LoadRules("../../rules")
	if err != nil {
		f.Skip("rules not available")
	}
	d := New(rs)
	f.Add("/search", "q=hello", "body")
	f.Add("/", "", "")
	f.Fuzz(func(t *testing.T, path, query, body string) {
		u, err := url.Parse("http://example.com" + path + "?" + query)
		if err != nil {
			return
		}
		req := httptest.NewRequest("POST", u.String(), strings.NewReader(body))
		matches := d.Detect(req)
		_ = matches
	})
}
