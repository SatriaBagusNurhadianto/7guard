package detector

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"

	"github.com/SatriaBagusNurhadianto/7guard/internal/rules"
)

// Match represents a single rule match against a request.
type Match struct {
	Rule     rules.Rule
	Location string
	Matched  string
}

// Detector runs a set of rules against an HTTP request.
type Detector struct {
	rules    []rules.Rule
	compiled map[string]*regexp.Regexp
}

// New creates a Detector with the given rules.
func New(rs []rules.Rule) *Detector {
	d := &Detector{
		rules:    rs,
		compiled: make(map[string]*regexp.Regexp),
	}
	for _, r := range rs {
		re, err := regexp.Compile("(?i)" + r.Pattern)
		if err != nil {
			continue
		}
		d.compiled[r.ID] = re
	}
	return d
}

// Detect runs all rules against the request and returns matches.
func (d *Detector) Detect(r *http.Request) []Match {
	var matches []Match

	locations := map[string]string{
		"path":  singleDecode(r.URL.Path),
		"query": singleDecode(r.URL.RawQuery),
	}

	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		locations["body"] = singleDecode(string(bodyBytes))
	}

	for _, rule := range d.rules {
		re, ok := d.compiled[rule.ID]
		if !ok {
			continue
		}
		for _, loc := range rule.Locations {
			input, ok := locations[loc]
			if !ok {
				continue
			}
			if m := re.FindString(input); m != "" {
				matches = append(matches, Match{
					Rule:     rule,
					Location: loc,
					Matched:  m,
				})
			}
		}
	}

	return matches
}

// DetectString runs all rules against a single string input.
func (d *Detector) DetectString(input string) []Match {
	var matches []Match
	decoded := singleDecode(input)

	for _, rule := range d.rules {
		re, ok := d.compiled[rule.ID]
		if !ok {
			continue
		}
		if m := re.FindString(decoded); m != "" {
			matches = append(matches, Match{
				Rule:     rule,
				Location: "input",
				Matched:  m,
			})
		}
	}

	return matches
}

// singleDecode decodes URL-encoded input exactly once, then strips SQL comments
// to defeat comment-obfuscation bypasses (e.g., UNI/**/ON SEL/**/ECT).
func singleDecode(s string) string {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		decoded = s
	}
	return stripSQLComments(decoded)
}

// stripSQLComments removes /* ... */ comment sequences (used for obfuscation bypass).
// Does NOT strip -- comments (those are caught by dedicated rules).
func stripSQLComments(s string) string {
	// Remove /* ... */ (non-greedy)
	for {
		start := -1
		end := -1
		for i := 0; i < len(s)-1; i++ {
			if s[i] == '/' && s[i+1] == '*' {
				start = i
				break
			}
		}
		if start == -1 {
			break
		}
		for i := start + 2; i < len(s)-1; i++ {
			if s[i] == '*' && s[i+1] == '/' {
				end = i + 2
				break
			}
		}
		if end == -1 {
			// Unclosed comment: strip to end
			s = s[:start]
			break
		}
		s = s[:start] + s[end:]
	}
	return s
}
