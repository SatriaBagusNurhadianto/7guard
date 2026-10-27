package leakage

import (
	"regexp"
	"strings"
)

// Finding describes one detected leak.
type Finding struct {
	Type    string // pii | secret | error_page
	Matched string // matched text (not for logging)
	Offset  int
}

// Report summarizes which leak types were found in a body.
type Report struct {
	PII       bool
	Secret    bool
	ErrorPage bool
	Findings  []Finding
}

// HasAny reports whether any leak was found.
func (r Report) HasAny() bool {
	return r.PII || r.Secret || r.ErrorPage
}

// Types returns the distinct leak types found.
func (r Report) Types() []string {
	var out []string
	if r.PII {
		out = append(out, "pii")
	}
	if r.Secret {
		out = append(out, "secret")
	}
	if r.ErrorPage {
		out = append(out, "error_page")
	}
	return out
}

var (
	reEmail = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)

	rePhone = regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`)

	reSSN = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

	reCreditCard = regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{4}\b`)

	reAPIKey = regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9_\-]{16,}`)

	reBearer = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}`)

	rePrivateKey = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)

	reAWSKey = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)

	reStackTrace = regexp.MustCompile(`(?i)(stack\s*trace|traceback|at\s+[\w./\-]+\.(?:go|java|py|js|ts|rb|php):\d+|panic:|goroutine \d+ \[)`)

	reSQLError = regexp.MustCompile(`(?i)(sql\s*(?:syntax|error)|mysql_(?:fetch|query)|ORA-\d{4,5}|pg_query|sqlite3?\.|unclosed quotation mark)`)

	reInternalPath = regexp.MustCompile(`(?i)(/home/[a-z_]+|/var/www/|/etc/passwd|C:\\Users\\|/proc/self)`)
)

// Scanner holds compiled patterns (stateless, safe for concurrent use).
type Scanner struct{}

// New creates a Scanner.
func New() *Scanner { return &Scanner{} }

// Scan inspects body and returns a Report.
func (s *Scanner) Scan(body []byte) Report {
	text := string(body)
	var report Report
	var findings []Finding

	// PII: email
	for _, m := range reEmail.FindAllStringIndex(text, -1) {
		report.PII = true
		findings = append(findings, Finding{Type: "pii", Matched: text[m[0]:m[1]], Offset: m[0]})
	}
	// PII: phone
	for _, m := range rePhone.FindAllStringIndex(text, -1) {
		report.PII = true
		findings = append(findings, Finding{Type: "pii", Matched: text[m[0]:m[1]], Offset: m[0]})
	}
	// PII: SSN
	for _, m := range reSSN.FindAllStringIndex(text, -1) {
		report.PII = true
		findings = append(findings, Finding{Type: "pii", Matched: text[m[0]:m[1]], Offset: m[0]})
	}
	// PII: credit card (Luhn-validated)
	for _, m := range reCreditCard.FindAllStringIndex(text, -1) {
		num := digitsOnly(text[m[0]:m[1]])
		if len(num) >= 13 && len(num) <= 19 && luhn(num) {
			report.PII = true
			findings = append(findings, Finding{Type: "pii", Matched: text[m[0]:m[1]], Offset: m[0]})
		}
	}

	// Secrets
	for _, re := range []*regexp.Regexp{reAPIKey, reBearer, rePrivateKey, reAWSKey} {
		for _, m := range re.FindAllStringIndex(text, -1) {
			report.Secret = true
			findings = append(findings, Finding{Type: "secret", Matched: text[m[0]:m[1]], Offset: m[0]})
		}
	}

	// Error page
	for _, re := range []*regexp.Regexp{reStackTrace, reSQLError, reInternalPath} {
		for _, m := range re.FindAllStringIndex(text, -1) {
			report.ErrorPage = true
			findings = append(findings, Finding{Type: "error_page", Matched: text[m[0]:m[1]], Offset: m[0]})
		}
	}

	report.Findings = findings
	return report
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func luhn(num string) bool {
	sum := 0
	parity := len(num) % 2
	for i, c := range num {
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
