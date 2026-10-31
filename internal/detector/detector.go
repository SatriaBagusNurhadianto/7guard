package detector

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

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
// Rules with invalid regex patterns are skipped with a warning.
func New(rs []rules.Rule) *Detector {
	d := &Detector{
		rules:    rs,
		compiled: make(map[string]*regexp.Regexp),
	}
	for _, r := range rs {
		re, err := regexp.Compile("(?i)" + r.Pattern)
		if err != nil {
			log.Printf("detector: invalid regex for rule %s: %v", r.ID, err)
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
		"path":  safeDecode(r.URL.Path),
		"query": safeDecode(r.URL.RawQuery),
	}

	// Scan headers
	var headerVals []string
	for k, v := range r.Header {
		headerVals = append(headerVals, k)
		headerVals = append(headerVals, v...)
	}
	if len(headerVals) > 0 {
		locations["header"] = safeDecode(strings.Join(headerVals, " "))
	}

	// Scan cookies
	var cookieVals []string
	for _, c := range r.Cookies() {
		cookieVals = append(cookieVals, c.Name, c.Value)
	}
	if len(cookieVals) > 0 {
		locations["cookie"] = safeDecode(strings.Join(cookieVals, " "))
	}

	if r.Body != nil {
		// Read at most 1MB+1 to detect oversized bodies without OOM.
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if err != nil {
			log.Printf("detector: error reading body: %v", err)
		}
		// Restore body for upstream: scanned bytes + any unread remainder.
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), r.Body))
		// Scan up to 1MB of body
		scanBytes := bodyBytes
		if len(scanBytes) > 1<<20 {
			scanBytes = scanBytes[:1<<20]
		}
		locations["body"] = safeDecode(string(scanBytes))
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
	decoded := safeDecode(input)

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

// safeDecode decodes URL-encoded input, normalizes overlong UTF-8,
// then strips SQL comments to defeat bypasses.
// Unlike url.QueryUnescape, this does not fail on invalid % sequences —
// it skips them and continues decoding the rest.
func safeDecode(s string) string {
	decoded := resilientUnescape(s)
	decoded = stripOverlongUTF8(decoded)
	return stripSQLComments(decoded)
}

// resilientUnescape decodes %XX sequences, skipping invalid ones instead of
// failing the entire decode.
func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func resilientUnescape(s string) string {
	// Try standard decode first (handles + -> space)
	if decoded, err := url.QueryUnescape(s); err == nil {
		return decoded
	}
	// Fallback: manual decode, skipping invalid % sequences
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '+' {
			b.WriteByte(' ')
			i++
			continue
		}
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// stripOverlongUTF8 replaces overlong UTF-8 encodings with their canonical ASCII.
func stripOverlongUTF8(s string) string {
	replacements := map[string]string{
		"\xc0\xae": ".",  // overlong '.'
		"\xc0\xaf": "/",  // overlong '/'
		"\xc0\xa0": " ",  // overlong space
		"\xc1\x9c": "\\", // overlong backslash
	}
	for old, new := range replacements {
		s = strings.ReplaceAll(s, old, new)
	}

	replacements3 := map[string]string{
		"\xe0\x80\xae": ".", // overlong '.'
		"\xe0\x80\xaf": "/", // overlong '/'
	}
	for old, new := range replacements3 {
		s = strings.ReplaceAll(s, old, new)
	}

	return s
}

// stripSQLComments removes /* ... */ comment sequences (used for obfuscation bypass).
// Comments are replaced with a space (not removed) to prevent UNION/**/SELECT bypass.
// Unclosed comments (/* without */) are replaced with a space.
// Single-pass O(n) implementation.
func stripSQLComments(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		if i < len(s)-1 && s[i] == '/' && s[i+1] == '*' {
			// Find closing */
			end := -1
			for j := i + 2; j < len(s)-1; j++ {
				if s[j] == '*' && s[j+1] == '/' {
					end = j + 2
					break
				}
			}
			if end == -1 {
				// Unclosed comment: replace /* with space, keep rest
				b.WriteByte(' ')
				i += 2
				continue
			}
			// Replace comment with space
			b.WriteByte(' ')
			i = end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// singleDecode is an alias for safeDecode (kept for test compatibility).
func singleDecode(s string) string {
	return safeDecode(s)
}
