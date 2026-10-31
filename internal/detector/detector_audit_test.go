package detector

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBodyCapRestoresFullBody verifies that a body larger than the 1MB scan
// cap is still forwarded to upstream in full (not truncated) while detection
// still scans the first 1MB.
func TestBodyCapRestoresFullBody(t *testing.T) {
	rs := loadTestRules(t)
	d := New(rs)

	// Build a body: an attack marker in the first KB + 2MB of padding.
	padding := bytes.Repeat([]byte("A"), 2<<20)
	body := append([]byte(`{"q":"1 UNION SELECT * FROM users"}`), padding...)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if len(b) != len(body) {
			t.Errorf("upstream received %d bytes, want %d (body truncated?)", len(b), len(body))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	req := httptest.NewRequest("POST", "/api/search", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	matches := d.Detect(req)
	if len(matches) == 0 {
		t.Error("expected SQLi match in body prefix")
	}

	// After Detect, r.Body should still be fully readable.
	got, _ := io.ReadAll(req.Body)
	if len(got) != len(body) {
		t.Errorf("restored body len = %d, want %d", len(got), len(body))
	}
	if !bytes.Equal(got, body) {
		t.Error("restored body differs from original")
	}
}
