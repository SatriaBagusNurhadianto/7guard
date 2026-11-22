package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/config"
)

func TestPathTraversalContains(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/foo/../etc/passwd", true},
		{"/foo/..", true},
		{"/..", true},
		{"/a\\b\\..\\c", true},
		{"/%2e%2e/etc/passwd", true},
		{"/%2E%2E/etc", true},
		{"/%2f%2e%2e", true},
		{"/%5c..", true},
		{"/%c0%ae%2e/etc", true},
		{"/a%00b", true},
		{"/%252e%252e/etc", true}, // double-encoded
		{"/normal/path", false},
		{"/files/my..doc", false},
		{"/search?q=..", false}, // query not in path
	}
	for _, c := range cases {
		got := containsPathTraversal(c.path)
		if got != c.want {
			t.Errorf("containsPathTraversal(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestPathTraversalBlocked(t *testing.T) {
	// D66: traversal is content-gated, not transport-safety. detect -> the request
	// is forwarded (not refused); block -> 400. The payload is an encoded
	// separator, the class that actually reaches this gate: literal `..` is
	// cleanPath-redirected by net/http's ServeMux before handleRequest
	// (SEC-R4-03), and on Maximum a dot-dot payload that trips a content rule is
	// 403'd at :816 before it gets here.
	t.Run("detect forwards", func(t *testing.T) {
		srv := newTestServer(t, config.ProfileLite, config.ModeDetect)
		req := httptest.NewRequest("GET", "/file%2freadme.txt", nil)
		rr := httptest.NewRecorder()
		srv.handleRequest(rr, req)
		if rr.Code == http.StatusBadRequest {
			t.Fatalf("detect mode must not refuse traversal, got 400")
		}
	})
	t.Run("block refuses", func(t *testing.T) {
		srv := newTestServer(t, config.ProfileLite, config.ModeBlock)
		req := httptest.NewRequest("GET", "/file%2freadme.txt", nil)
		rr := httptest.NewRecorder()
		srv.handleRequest(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("block mode must return 400 for traversal, got %d", rr.Code)
		}
	})
}
