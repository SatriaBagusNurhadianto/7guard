package detector

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/SatriaBagusNurhadianto/7guard/internal/rules"
)

func loadTestRules(t *testing.T) []rules.Rule {
	t.Helper()
	rs, err := rules.LoadRules("../../rules")
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}
	if len(rs) == 0 {
		t.Fatal("no rules loaded")
	}
	return rs
}

func TestDetectSQLiAttack(t *testing.T) {
	rs := loadTestRules(t)
	d := New(rs)

	attacks := []string{
		"1 UNION SELECT username,password FROM users",
		"1' OR 1=1 --",
		"1; DROP TABLE users; --",
		"1' OR 'a'='a",
		"admin'--",
		"1 UNION ALL SELECT 1,2,3",
		"1; INSERT INTO users VALUES ('hacker','pass')",
		"1; DELETE FROM users WHERE 1=1",
		"1; UPDATE users SET password='hacked' WHERE 1=1",
		"1' AND SLEEP(5) --",
		"1' AND BENCHMARK(1000000,SHA1('test')) --",
		"1'; WAITFOR DELAY '0:0:5' --",
		"1'; EXEC xp_cmdshell('dir') --",
		"1' UNION SELECT table_name FROM information_schema.tables --",
	}

	for _, attack := range attacks {
		matches := d.DetectString(attack)
		if len(matches) == 0 {
			t.Errorf("expected match for attack: %q, got none", attack)
		}
	}
}

func TestDetectBenign(t *testing.T) {
	rs := loadTestRules(t)
	d := New(rs)

	benign := []string{
		"search=hello+world",
		"product=laptop+computer",
		"name=O'Brien",
		"query=how+to+use+SQL+in+Go",
		"page=1&limit=20",
		"category=electronics",
		"sort=price_asc",
		"filter=active",
	}

	for _, input := range benign {
		matches := d.DetectString(input)
		if len(matches) > 0 {
			t.Errorf("false positive for benign input %q: matched %s", input, matches[0].Rule.ID)
		}
	}
}

func TestSingleDecode(t *testing.T) {
	// Double-encoded input is decoded (defense against double-encoding bypasses).
	doubleEncoded := "%2527%2520OR%25201%253D1" // %27%20OR%201%3D1 double-encoded
	decoded := singleDecode(doubleEncoded)
	// Should be fully decoded for scanning
	if decoded != "' OR 1=1" {
		t.Errorf("expected fully decoded, got %q", decoded)
	}
}

func TestDetectHTTPRequest(t *testing.T) {
	rs := loadTestRules(t)
	d := New(rs)

	req := httptest.NewRequest("GET", "/search?q=1+UNION+SELECT+password+FROM+users", nil)
	matches := d.Detect(req)
	if len(matches) == 0 {
		t.Error("expected SQLi match in query param")
	}

	// Benign request
	req2 := httptest.NewRequest("GET", "/search?q=hello+world", nil)
	matches2 := d.Detect(req2)
	if len(matches2) > 0 {
		t.Errorf("false positive on benign request: %s", matches2[0].Rule.ID)
	}
}

func TestBodyDetection(t *testing.T) {
	rs := loadTestRules(t)
	d := New(rs)

	body := strings.NewReader(`{"query": "1 UNION SELECT * FROM users"}`)
	req := httptest.NewRequest("POST", "/api/search", body)
	req.Header.Set("Content-Type", "application/json")
	matches := d.Detect(req)
	if len(matches) == 0 {
		t.Error("expected SQLi match in request body")
	}
}

func TestConcurrentDetection(t *testing.T) {
	rs := loadTestRules(t)
	d := New(rs)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			input := "1 UNION SELECT password FROM users"
			if idx%2 == 0 {
				input = "hello world search query"
			}
			matches := d.DetectString(input)
			if idx%2 == 0 {
				if len(matches) > 0 {
					t.Errorf("false positive on benign input in goroutine %d", idx)
				}
			} else {
				if len(matches) == 0 {
					t.Errorf("missed attack in goroutine %d", idx)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestOverlongUTF8Normalization(t *testing.T) {
	// %c0%ae decodes to overlong '.' which should be normalized
	input := "%c0%ae%c0%ae/etc/passwd"
	decoded := singleDecode(input)
	if strings.Contains(decoded, "\xc0\xae") {
		t.Errorf("overlong UTF-8 not normalized: %q", decoded)
	}
}
