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
	srv := newTestServer(t, config.ProfileLite, config.ModeDetect)
	req := httptest.NewRequest("GET", "/foo/../etc/passwd", nil)
	rr := httptest.NewRecorder()
	srv.handleRequest(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for traversal path, got %d", rr.Code)
	}
}
