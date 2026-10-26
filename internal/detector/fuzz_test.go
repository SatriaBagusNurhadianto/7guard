package detector

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/rules"
)

// FuzzSingleDecode ensures singleDecode never panics on arbitrary input.
func FuzzSingleDecode(f *testing.F) {
	f.Add("%27%20OR%201%3D1")
	f.Add("normal input")
	f.Add("")
	f.Add("%c0%ae%c0%af")
	f.Add("'; DROP TABLE users; --")
	f.Fuzz(func(t *testing.T, s string) {
		// Must not panic.
		out := singleDecode(s)
		_ = out
	})
}

// FuzzDetectString ensures DetectString never panics on arbitrary input.
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
		// Invariant: matches must be a valid slice (no nil deref).
		_ = matches
	})
}

// FuzzDetectRequest ensures Detect handles arbitrary request paths/queries/bodies.
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
