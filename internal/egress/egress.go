package egress

import (
	"context"
	"fmt"
	"net"
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

// Allowlist holds the parsed egress allowlist.
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
	// normalize IPv4-mapped IPv6
	if v4 := ip.To4(); v4 != nil && ip.To16() != nil && ip.IsLoopback() == false {
		// keep as-is for matching; To4 handles mapped
	}
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
			return nil, fmt.Errorf("egress: empty host")
		}
		// userinfo already stripped by caller; but guard anyway
		if strings.Contains(host, "@") {
			if a.OnDecision != nil {
				a.OnDecision(false, ReasonUserinfo)
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
				var err error
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

		// Validate resolved IPs
		for _, ip := range ips {
			// DNS rebinding check: if hostname was allowlisted, still verify resolved IP
			// is not in a denied state. For hostname allowlist, we allow if hostname matched;
			// but if an IP/CIDR entry exists, the resolved IP must also be allowed OR the
			// hostname must have been allowed. To prevent rebinding, require that when the
			// hostname is NOT in the hostname allowlist, the resolved IP must be in the
			// IP allowlist.
			if !hostnameAllowed {
				if !a.CheckIP(ip) {
					if a.OnDecision != nil {
						a.OnDecision(false, ReasonDNSRebinding)
					}
					if a.Mode != "detect" {
						return nil, fmt.Errorf("egress: denied (dns_rebinding or not allowlisted): %s -> %s", norm, ip)
					}
				}
			} else {
				// hostname allowed: still guard against rebinding to private/loopback
				// unless explicitly allowlisted by IP/CIDR
				if ip.IsLoopback() || ip.IsPrivate() {
					if !a.CheckIP(ip) {
						if a.OnDecision != nil {
							a.OnDecision(false, ReasonDNSRebinding)
						}
						if a.Mode != "detect" {
							return nil, fmt.Errorf("egress: denied (dns_rebinding to private): %s -> %s", norm, ip)
						}
					}
				}
			}
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
		conn, err := net.Dial(network, dialAddr)
		if err != nil {
			return nil, err
		}
		if a.OnDecision != nil {
			a.OnDecision(true, ReasonAllowed)
		}
		return conn, nil
	}
}

// CheckRedirect validates redirect targets.
func (a *Allowlist) CheckRedirect(req, via []*interface{}) error {
	// placeholder signature; real impl below
	return nil
}

// ValidateRedirect checks if a redirect target URL is allowed.
func (a *Allowlist) ValidateRedirect(targetURL string) bool {
	allowed, _ := a.Check(targetURL)
	return allowed
}
