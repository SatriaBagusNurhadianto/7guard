package detector

import (
	"net/http/httptest"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/rules"
)

func BenchmarkDetectSQLi(b *testing.B) {
	rs := loadBenchRules(b)
	d := New(rs)
	req := httptest.NewRequest("GET", "/search?q=1+UNION+SELECT+password+FROM+users", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(req)
	}
}

func BenchmarkDetectXSS(b *testing.B) {
	rs := loadBenchRules(b)
	d := New(rs)
	req := httptest.NewRequest("GET", "/search?q=<script>alert(1)</script>", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(req)
	}
}

func BenchmarkDetectTraversal(b *testing.B) {
	rs := loadBenchRules(b)
	d := New(rs)
	req := httptest.NewRequest("GET", "/files?path=../../../etc/passwd", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(req)
	}
}

func BenchmarkDetectBenign(b *testing.B) {
	rs := loadBenchRules(b)
	d := New(rs)
	req := httptest.NewRequest("GET", "/search?q=hello+world+how+are+you", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Detect(req)
	}
}

func BenchmarkDetectString(b *testing.B) {
	rs := loadBenchRules(b)
	d := New(rs)
	input := "1 UNION SELECT username,password FROM users WHERE 1=1 --"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.DetectString(input)
	}
}

func loadBenchRules(b *testing.B) []rules.Rule {
	b.Helper()
	rs, err := rules.LoadRules("../../rules")
	if err != nil {
		b.Fatalf("loading rules: %v", err)
	}
	return rs
}
