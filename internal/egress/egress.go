package egress

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Reason constants for deny decisions (used in metrics/logs).
const (
	ReasonAllowed       = "allowed"
	ReasonAllowlist     = "allowlist"
	ReasonDNSRebinding  = "dns_rebinding"
	ReasonRedirect      = "redirect"
	ReasonUserinfo      = "userinfo"
	ReasonEmptyHost     = "empty_host"
	ReasonInvalidConfig = "invalid_config"
)

// EgressMode constants.
const (
	EgressModeDetect = "detect"
	EgressModeBlock  = "block"
)

type Allowlist struct {
	hostnames []string // exact hostnames (lowercased, trailing dot trimmed)
	wildcards []string // suffix patterns like "*.example.com" (stored as ".example.com")
	cidrs     []*net.IPNet
	ips       []net.IP

	// Mode: detect or block. Default block if empty.
	Mode string

	// OnDecision is an optional callback invoked for each egress decision.
	OnDecision func(allowed bool, reason string)
}

// NewAllowlist parses a list of allowlist entries. Returns an error on malformed input.
func NewAllowlist(entries []string) (*Allowlist, error) {
	a := &Allowlist{}
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		// Wildcard suffix
		if strings.HasPrefix(e, "*.") {
			suffix := strings.ToLower(strings.TrimPrefix(e, "*"))
			// suffix now ".example.com"
			a.wildcards = append(a.wildcards, suffix)
			continue
		}
		// CIDR
		if strings.Contains(e, "/") {
			_, cidr, err := net.ParseCIDR(e)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", e, err)
			}
			a.cidrs = append(a.cidrs, cidr)
			continue
		}
		// IP
		if ip := net.ParseIP(e); ip != nil {
			a.ips = append(a.ips, ip)
			continue
		}
		// Hostname
		host := normalizeHost(e)
		if host == "" {
			return nil, fmt.Errorf("invalid host entry %q", e)
		}
		a.hostnames = append(a.hostnames, host)
	}
	a.Mode = EgressModeDetect
	return a, nil
}

// normalizeHost lowercases and trims a trailing dot.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ".")
	return h
}

// Check evaluates whether a target host is allowed.
// Returns (allowed bool, reason string).
// Phase 1: hostname allowlist (against original hostname).
// Phase 2: IP/CIDR allowlist (against resolved IPs, caller supplies resolved).
// For a simple hostname check without resolution, only phase 1 applies.
func (a *Allowlist) CheckHostname(host string) bool {
	if a == nil {
		return false
	}
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	// exact hostname
	for _, allowed := range a.hostnames {
		if allowed == h {
			return true
		}
	}
	// wildcard suffix
	for _, suffix := range a.wildcards {
		if strings.HasSuffix(h, suffix) && len(h) > len(suffix) {
			return true
		}
	}
	return false
}

// CheckIP evaluates whether a resolved IP is allowed by IP/CIDR entries.
func (a *Allowlist) CheckIP(ip net.IP) bool {
	if a == nil {
		return false
	}
	// normalize IPv4-mapped IPv6 to its IPv4 form
	normalized := ip
	if v4 := ip.To4(); v4 != nil {
		normalized = v4
	}
	for _, allowed := range a.ips {
		if allowed.Equal(normalized) {
			return true
		}
	}
	for _, cidr := range a.cidrs {
		if cidr.Contains(normalized) {
			return true
		}
	}
	return false
}

// Check evaluates a URL's host against the allowlist using two-phase matching
// without DNS resolution (hostname phase only + literal IP phase).
// For full resolve-validate-dial, use DialContext.
func (a *Allowlist) Check(rawURL string) (bool, string) {
	if a == nil {
		return false, ReasonAllowlist
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, ReasonInvalidConfig
	}
	// userinfo check
	if u.User != nil {
		return false, ReasonUserinfo
	}
	host := u.Hostname()
	if host == "" {
		return false, ReasonEmptyHost
	}
	// Phase 1: hostname allowlist
	if a.CheckHostname(host) {
		return true, ReasonAllowed
	}
	// If host is a literal IP, phase 2 directly
	if ip := net.ParseIP(host); ip != nil {
		if a.CheckIP(ip) {
			return true, ReasonAllowed
		}
		return false, ReasonAllowlist
	}
	// hostname not in allowlist and not a literal IP → not allowed
	// (resolution happens at dial time; here we deny unknown hostnames)
	return false, ReasonAllowlist
}

// DialContext returns a dial function that enforces the allowlist with
// resolve-validate-dial. The resolver is injectable for testing.
func (a *Allowlist) DialContext(resolve func(host string) ([]net.IP, error)) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			host = address
			port = ""
		}
		if host == "" {
			if a.OnDecision != nil {
				a.OnDecision(false, ReasonEmptyHost)
			}
			if a.mode() != EgressModeDetect {
				return nil, fmt.Errorf("egress: empty host")
			}
			// detect mode: fall through not possible without host; deny connection
			return nil, fmt.Errorf("egress: empty host")
		}
		// userinfo guard
		if strings.Contains(host, "@") {
			if a.OnDecision != nil {
				a.OnDecision(false, ReasonUserinfo)
			}
			if a.mode() != EgressModeDetect {
				return nil, fmt.Errorf("egress: userinfo not allowed")
			}
			return nil, fmt.Errorf("egress: userinfo not allowed")
		}
		norm := normalizeHost(host)

		// Phase 1: hostname allowlist (pre-resolution)
		hostnameAllowed := a.CheckHostname(norm)

		// Resolve
		var ips []net.IP
		if ip := net.ParseIP(norm); ip != nil {
			ips = []net.IP{ip}
		} else {
			if resolve == nil {
				ips, err = net.LookupIP(norm)
				if err != nil {
					return nil, fmt.Errorf("egress: resolve %s: %w", norm, err)
				}
			} else {
				ips, err = resolve(norm)
				if err != nil {
					return nil, fmt.Errorf("egress: resolve %s: %w", norm, err)
				}
			}
		}

		// Validate resolved IPs; track final decision without calling OnDecision yet.
		denied := false
		denyReason := ReasonAllowlist
		for _, ip := range ips {
			if !hostnameAllowed {
				if !a.CheckIP(ip) {
					denied = true
					denyReason = ReasonAllowlist
					break
				}
			} else {
				// hostname allowed: guard against rebinding to private/loopback
				// unless explicitly allowlisted by IP/CIDR
				if ip.IsLoopback() || ip.IsPrivate() {
					if !a.CheckIP(ip) {
						denied = true
						denyReason = ReasonDNSRebinding
						break
					}
				}
			}
		}

		// Final decision
		if denied {
			if a.OnDecision != nil {
				a.OnDecision(false, denyReason)
			}
			if a.mode() != EgressModeDetect {
				return nil, fmt.Errorf("egress: denied (%s): %s", denyReason, norm)
			}
			// detect mode: fall through to dial
		} else {
			// allowed by policy; OnDecision(true) called after successful dial
		}

		// Dial the first resolved IP (or original host if no resolution)
		dialAddr := address
		if len(ips) > 0 {
			if port != "" {
				dialAddr = net.JoinHostPort(ips[0].String(), port)
			} else {
				dialAddr = ips[0].String()
			}
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, network, dialAddr)
		if err != nil {
			return nil, err
		}
		if !denied {
			if a.OnDecision != nil {
				a.OnDecision(true, ReasonAllowed)
			}
		}
		return conn, nil
	}
}

// CheckRedirect implements http.Client.CheckRedirect signature.
// Note: 7Guard's ReverseProxy forwards redirects to the client rather than
// following them, so this guard only matters for internal http.Client calls.
func (a *Allowlist) CheckRedirect(req *http.Request, via []*http.Request) error {
	if !a.ValidateRedirect(req.URL.String()) {
		if a.OnDecision != nil {
			a.OnDecision(false, ReasonRedirect)
		}
		if a.mode() != EgressModeDetect {
			return fmt.Errorf("egress: redirect denied: %s", req.URL.Host)
		}
	}
	return nil
}

// ValidateRedirect checks if a redirect target URL is allowed.
func (a *Allowlist) ValidateRedirect(targetURL string) bool {
	allowed, _ := a.Check(targetURL)
	return allowed
}

// mode returns the effective mode (default detect).
func (a *Allowlist) mode() string {
	if a == nil || a.Mode == "" {
		return EgressModeDetect
	}
	return a.Mode
}
