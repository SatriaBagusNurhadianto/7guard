package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRules(t *testing.T) {
	rs, err := LoadRules("../../rules")
	if err != nil {
		t.Fatalf("loading rules: %v", err)
	}
	if len(rs) < 10 {
		t.Errorf("expected at least 10 rules, got %d", len(rs))
	}

	for _, r := range rs {
		if err := r.Validate(); err != nil {
			t.Errorf("invalid rule %s: %v", r.ID, err)
		}
	}
}

func TestLoadRulesMissingDir(t *testing.T) {
	_, err := LoadRules("/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing dir")
	}
}

func TestRuleValidate(t *testing.T) {
	r := Rule{ID: "test", Category: "sqli", Pattern: "test", Locations: []string{"query"}}
	if err := r.Validate(); err != nil {
		t.Errorf("valid rule rejected: %v", err)
	}

	// Missing ID
	r2 := Rule{Category: "sqli", Pattern: "test", Locations: []string{"query"}}
	if err := r2.Validate(); err == nil {
		t.Error("rule without ID accepted")
	}

	// Missing locations
	r3 := Rule{ID: "test", Category: "sqli", Pattern: "test"}
	if err := r3.Validate(); err == nil {
		t.Error("rule without locations accepted")
	}
}

func TestLoadRulesTempDir(t *testing.T) {
	dir := t.TempDir()
	content := `- id: test-rule
  category: test
  severity: low
  pattern: "foo"
  locations: [query]
  description: "test"
`
	os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(content), 0644)
	rs, err := LoadRules(dir)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if len(rs) != 1 {
		t.Errorf("expected 1 rule, got %d", len(rs))
	}
	if rs[0].ID != "test-rule" {
		t.Errorf("wrong ID: %s", rs[0].ID)
	}
}
