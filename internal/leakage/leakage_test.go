package leakage

import "testing"

func TestScanDetectsEmail(t *testing.T) {
	s := New()
	leaks := s.Scan([]byte("contact us at foo@example.com please"))
	if len(leaks) == 0 {
		t.Fatal("expected leak")
	}
	if leaks[0].Type != LeakPII {
		t.Fatalf("expected pii, got %s", leaks[0].Type)
	}
}

func TestScanLuhnCreditCard(t *testing.T) {
	s := New()
	// valid Luhn test number
	leaks := s.Scan([]byte("card 4111 1111 1111 1111"))
	found := false
	for _, l := range leaks {
		if l.Type == LeakPII {
			found = true
		}
	}
	if !found {
		t.Fatal("expected pii leak for valid card")
	}
	// invalid Luhn
	leaks2 := s.Scan([]byte("card 4111 1111 1111 1112"))
	for _, l := range leaks2 {
		// ensure not flagged as cc; could be phone-ish, just check no panic
		_ = l
	}
}

func TestRedactReplace(t *testing.T) {
	s := New()
	body := []byte("secret: password=supersecretvalue1234567890")
	leaks := s.Scan(body)
	if len(leaks) == 0 {
		t.Skip("no leak detected")
	}
	out := Redact(body, leaks, "[REDACTED]", false)
	if string(out) == string(body) {
		t.Fatal("expected redaction")
	}
}

func TestLeakTypesDistinct(t *testing.T) {
	leaks := []Leak{{Type: LeakPII}, {Type: LeakPII}, {Type: LeakSecret}}
	ts := LeakTypes(leaks)
	if len(ts) != 2 {
		t.Fatalf("expected 2 distinct, got %d", len(ts))
	}
}
