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
		"path":   singleDecode(r.URL.Path),
		"query":  singleDecode(r.URL.RawQuery),
		"header": singleDecode(headersString(r)),
		"cookie": singleDecode(cookiesString(r)),
	}

	if r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
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

func headersString(r *http.Request) string {
	var b strings.Builder
	for k, vals := range r.Header {
		b.WriteString(k)
		b.WriteString(": ")
		for _, v := range vals {
			b.WriteString(v)
			b.WriteString(" ")
		}
	}
	return b.String()
}

func cookiesString(r *http.Request) string {
	var b strings.Builder
	for _, c := range r.Cookies() {
		b.WriteString(c.Name)
		b.WriteString("=")
		b.WriteString(c.Value)
		b.WriteString(" ")
	}
	return b.String()
}

// singleDecode decodes URL-encoded input exactly once, normalizes overlong UTF-8,
// then strips SQL comments to defeat bypasses.
func singleDecode(s string) string {
	decoded := lenientUnescape(s)
	decoded = stripOverlongUTF8(decoded)
	return stripSQLComments(decoded)
}

// lenientUnescape decodes valid %XX sequences even if some are malformed.
func lenientUnescape(s string) string {
	decoded, err := url.QueryUnescape(s)
	if err == nil {
		return decoded
	}
	var b strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '%' && i+2 < len(s) {
			hi := unhex(s[i+1])
			lo := unhex(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo)) // #nosec G115 -- hi,lo are 0-15, result fits in byte
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

// stripOverlongUTF8 replaces overlong UTF-8 encodings with their canonical ASCII.
func stripOverlongUTF8(s string) string {
	replacements := map[string]string{
		"\xc0\xae": ".",
		"\xc0\xaf": "/",
		"\xc0\xa0": " ",
		"\xc1\x9c": "\\",
	}
	for old, new := range replacements {
		s = strings.ReplaceAll(s, old, new)
	}

	replacements3 := map[string]string{
		"\xe0\x80\xae": ".",
		"\xe0\x80\xaf": "/",
	}
	for old, new := range replacements3 {
		s = strings.ReplaceAll(s, old, new)
	}

	return s
}

// stripSQLComments removes /* ... */ comment sequences (used for obfuscation bypass).
// Replaces comments with a space (not empty) to prevent token concatenation.
// Unclosed /* is replaced with a space (does not strip trailing content).
// O(n) single pass.
func stripSQLComments(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	n := len(s)
	for i < n {
		if i+1 < n && s[i] == '/' && s[i+1] == '*' {
			j := i + 2
			for j+1 < n {
				if s[j] == '*' && s[j+1] == '/' {
					break
				}
				j++
			}
			if j+1 < n {
				b.WriteByte(' ')
				i = j + 2
			} else {
				b.WriteByte(' ')
				i += 2
			}
		} else {
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}
