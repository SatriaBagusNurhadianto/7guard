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
