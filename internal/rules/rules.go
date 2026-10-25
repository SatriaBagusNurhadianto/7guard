package rules

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Severity levels for rules
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Rule represents a single detection rule loaded from YAML.
type Rule struct {
	ID          string   `yaml:"id"`
	Category    string   `yaml:"category"`
	Severity    string   `yaml:"severity"`
	Pattern     string   `yaml:"pattern"`
	Locations   []string `yaml:"locations"`
	Description string   `yaml:"description"`
}

// Validate checks that a rule has all required fields.
func (r *Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule missing id")
	}
	if r.Category == "" {
		return fmt.Errorf("rule %s missing category", r.ID)
	}
	if r.Pattern == "" {
		return fmt.Errorf("rule %s missing pattern", r.ID)
	}
	if len(r.Locations) == 0 {
		return fmt.Errorf("rule %s missing locations", r.ID)
	}
	return nil
}

// LoadRules reads all YAML rule files from a directory.
func LoadRules(dir string) ([]Rule, error) {
	var rules []Rule

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading rules dir %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path) // #nosec G304 -- path is from controlled rules directory, not user input
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}

		// Support both single rule and list of rules
		var single Rule
		if err := yaml.Unmarshal(data, &single); err == nil && single.ID != "" {
			if err := single.Validate(); err != nil {
				return nil, err
			}
			rules = append(rules, single)
			continue
		}

		var list []Rule
		if err := yaml.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		for i := range list {
			if err := list[i].Validate(); err != nil {
				return nil, err
			}
			rules = append(rules, list[i])
		}
	}

	return rules, nil
}
