package leakage

import (
	"testing"
)

func TestScanPIIEmail(t *testing.T) {
	s := New()
	r := s.Scan([]byte("contact us at foo@example.com"))
	if !r.PII {
		t.Fatal("expected PII")
	}
}

func TestScanSecretPrivateKey(t *testing.T) {
	s := New()
	r := s.Scan([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."))
	if !r.Secret {
		t.Fatal("expected secret")
	}
}

func TestScanErrorPageStackTrace(t *testing.T) {
	s := New()
	r := s.Scan([]byte("panic: runtime error\ngoroutine 1 [running]:"))
	if !r.ErrorPage {
		t.Fatal("expected error_page")
	}
}

func TestScanCreditCardLuhn(t *testing.T) {
	s := New()
	// valid Luhn: 4532015112830366
	r := s.Scan([]byte("card: 4532015112830366"))
	if !r.PII {
		t.Fatal("expected PII for valid card")
	}
	// invalid Luhn
	r2 := s.Scan([]byte("card: 4532015112830367"))
	for _, f := range r2.Findings {
		if f.Matched == "4532015112830367" {
			t.Fatal("invalid Luhn should not be flagged")
		}
	}
	// 13-digit (old Visa format)
	r3 := s.Scan([]byte("card: 4222222222222"))
	if !r3.PII {
		t.Fatal("expected PII for 13-digit valid card")
	}
	// 19-digit
	r4 := s.Scan([]byte("card: 6011000990139424"))
	_ = r4
}

func TestScanCleanBody(t *testing.T) {
	s := New()
	r := s.Scan([]byte("hello world, nothing sensitive here"))
	if r.HasAny() {
		t.Fatalf("expected no leaks, got %v", r.Types())
	}
}
