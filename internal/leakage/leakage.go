package leakage

import (
	"regexp"
	"strings"
)

// LeakType constants.
const (
	LeakPII       = "pii"
	LeakSecret    = "secret"
	LeakErrorPage = "error_page"
)

// Leak represents a single detected leak in a response body.
type Leak struct {
	Type     string // pii | secret | error_page
	Location int    // byte offset of the match start
	End      int    // byte offset of the match end (exclusive)
}

// Scanner detects data leakage in response bodies.
// All regexes are compiled once at construction and are safe for
// concurrent use; the scanner does not mutate shared state.
type Scanner struct {
	emailRe        *regexp.Regexp
	phoneRe        *regexp.Regexp
	ssnRe          *regexp.Regexp
	ccRe           *regexp.Regexp
	bearerRe       *regexp.Regexp
	apiKeyRe       *regexp.Regexp
	privKeyRe      *regexp.Regexp
	stackTraceRe   *regexp.Regexp
	sqlErrRe       *regexp.Regexp
	internalPathRe *regexp.Regexp
}

// New creates a Scanner with all patterns compiled once.
func New() *Scanner {
	return &Scanner{
		emailRe:        regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`),
		phoneRe:        regexp.MustCompile(`(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`),
		ssnRe:          regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		ccRe:           regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
		bearerRe:       regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]{8,}`),
		apiKeyRe:       regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret|token|password)\s*[:=]\s*["']?[A-Za-z0-9._~+/=-]{16,}["']?`),
		privKeyRe:      regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
		stackTraceRe:   regexp.MustCompile(`(?i)(panic:|traceback \(most recent call last\)|at [A-Za-z0-9_./$]+\.[A-Za-z]+:\d+|stack trace|goroutine \d+ \[)`),
		sqlErrRe:       regexp.MustCompile(`(?i)(sql syntax|mysql_fetch|ORA-\d{4,5}|pg_query|syntax error at or near|unclosed quotation mark|sqlite3?\.)`),
		internalPathRe: regexp.MustCompile(`(?i)(?:/home/|/var/www/|/etc/|/usr/local/|/root/|/opt/|[A-Za-z]:\\(?:Users|Windows|Program Files)\\)`),
	}
}

// Scan scans body for leaks. Returns a list of leaks (one per match location).
// Credit-card candidates are validated with Luhn before being flagged.
func (s *Scanner) Scan(body []byte) []Leak {
	var leaks []Leak
	text := string(body)

	// PII: email
	for _, m := range s.emailRe.FindAllStringIndex(text, -1) {
		leaks = append(leaks, Leak{Type: LeakPII, Location: m[0], End: m[1]})
	}
	// PII: phone
	for _, m := range s.phoneRe.FindAllStringIndex(text, -1) {
		leaks = append(leaks, Leak{Type: LeakPII, Location: m[0], End: m[1]})
	}
	// PII: SSN
	for _, m := range s.ssnRe.FindAllStringIndex(text, -1) {
		leaks = append(leaks, Leak{Type: LeakPII, Location: m[0], End: m[1]})
	}
	// PII: credit card (Luhn-validated)
	for _, m := range s.ccRe.FindAllStringIndex(text, -1) {
		cand := text[m[0]:m[1]]
		digits := onlyDigits(cand)
		if len(digits) >= 13 && len(digits) <= 19 && luhn(digits) {
			leaks = append(leaks, Leak{Type: LeakPII, Location: m[0], End: m[1]})
		}
	}
	// Secrets
	for _, m := range s.bearerRe.FindAllStringIndex(text, -1) {
		leaks = append(leaks, Leak{Type: LeakSecret, Location: m[0], End: m[1]})
	}
	for _, m := range s.apiKeyRe.FindAllStringIndex(text, -1) {
		leaks = append(leaks, Leak{Type: LeakSecret, Location: m[0], End: m[1]})
	}
	for _, m := range s.privKeyRe.FindAllStringIndex(text, -1) {
		leaks = append(leaks, Leak{Type: LeakSecret, Location: m[0], End: m[1]})
	}
	// Error pages
	for _, m := range s.stackTraceRe.FindAllStringIndex(text, -1) {
		leaks = append(leaks, Leak{Type: LeakErrorPage, Location: m[0], End: m[1]})
	}
	for _, m := range s.sqlErrRe.FindAllStringIndex(text, -1) {
		leaks = append(leaks, Leak{Type: LeakErrorPage, Location: m[0], End: m[1]})
	}
	for _, m := range s.internalPathRe.FindAllStringIndex(text, -1) {
		leaks = append(leaks, Leak{Type: LeakErrorPage, Location: m[0], End: m[1]})
	}

	return leaks
}

// LeakTypes returns the distinct leak types present in leaks.
func LeakTypes(leaks []Leak) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range leaks {
		if !seen[l.Type] {
			seen[l.Type] = true
			out = append(out, l.Type)
		}
	}
	return out
}

// Redact returns a copy of body with the leaked spans removed (strip) or
// replaced with token (replace). leaks must come from Scanner.Scan.
func Redact(body []byte, leaks []Leak, token string, strip bool) []byte {
	if len(leaks) == 0 {
		out := make([]byte, len(body))
		copy(out, body)
		return out
	}
	// Merge overlapping ranges.
	type rng struct{ s, e int }
	var ranges []rng
	for _, l := range leaks {
		ranges = append(ranges, rng{l.Location, l.End})
	}
	// sort by start
	// simple insertion sort
	for i := 1; i < len(ranges); i++ {
		j := i
		for j > 0 && ranges[j-1].s > ranges[j].s {
			ranges[j-1], ranges[j] = ranges[j], ranges[j-1]
			j--
		}
	}
	merged := []rng{ranges[0]}
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		if r.s <= last.e {
			if r.e > last.e {
				last.e = r.e
			}
		} else {
			merged = append(merged, r)
		}
	}
	var out []byte
	pos := 0
	for _, r := range merged {
		if r.s > pos {
			out = append(out, body[pos:r.s]...)
		}
		if !strip {
			out = append(out, []byte(token)...)
		}
		pos = r.e
		if pos > len(body) {
			pos = len(body)
		}
	}
	if pos < len(body) {
		out = append(out, body[pos:]...)
	}
	return out
}
func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func luhn(digits string) bool {
	if len(digits) < 2 {
		return false
	}
	sum := 0
	parity := len(digits) % 2
	for i, c := range digits {
		d := int(c - '0')
		if i%2 == parity {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}
