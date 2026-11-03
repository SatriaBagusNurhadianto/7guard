package detector

import (
	"testing"
)

func TestNFKCHomoglyphFullwidth(t *testing.T) {
	// Fullwidth "admin" (ａｄｍｉｎ) should normalize to "admin" and trigger detection.
	d := New(loadTestRules(t))
	matches := d.DetectString("\uff41\uff44\uff4d\uff49\uff4e' OR 1=1--")
	if len(matches) == 0 {
		t.Error("expected SQLi match after NFKC normalization of fullwidth input")
	}
}

func TestNFKCNoFalsePositiveOnPlainUnicode(t *testing.T) {
	d := New(loadTestRules(t))
	// A benign non-ASCII string should not produce spurious matches.
	matches := d.DetectString("café résumé naïve")
	if len(matches) > 0 {
		t.Errorf("false positive on benign unicode input: %s", matches[0].Rule.ID)
	}
}

func TestNFKCIdempotent(t *testing.T) {
	// Normalizing already-ASCII input should be a no-op.
	d := New(loadTestRules(t))
	in := "1 UNION SELECT * FROM users"
	m1 := d.DetectString(in)
	m2 := d.DetectString(in)
	if len(m1) != len(m2) {
		t.Errorf("NFKC not idempotent: %d vs %d matches", len(m1), len(m2))
	}
}

func TestNFKCFullwidthPercentReDecode(t *testing.T) {
	d := New(loadTestRules(t))
	// Fullwidth % (％) + "3cscript" should decode to "<script" and trigger XSS.
	matches := d.DetectString("\uff053cscript")
	if len(matches) == 0 {
		t.Error("expected XSS match after NFKC + re-decode of fullwidth percent")
	}
}

func TestNFKCEvasionVariants(t *testing.T) {
	d := New(loadTestRules(t))
	cases := []struct {
		name string
		in   string
	}{
		{"fullwidth percent uppercase hex", "\uff053Cscript"},
		{"fullwidth percent double-encoded UTF-8", "%ef%bc%853cscript"},
		{"fullwidth percent double-encoded outer", "%25ef%25bc%25853cscript"},
		{"fullwidth less-than direct", "\uff1cscript"},
		{"fullwidth greater-than in payload", "img src=x onerror=alert(1)\uff1e"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := d.DetectString(c.in); len(got) == 0 {
				t.Errorf("expected detection for %q, got none", c.in)
			}
		})
	}
}
