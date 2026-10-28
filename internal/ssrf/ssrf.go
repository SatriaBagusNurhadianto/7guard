package ssrf

import (
	"fmt"
	"net"
	"strings"
)

// ErrBlocked is returned when a target is blocked by SSRF protection.
var ErrBlocked = fmt.Errorf("blocked by SSRF protection")

// blockedRanges contains the default blocked CIDRs.
var blockedRanges = []string{
	"127.0.0.0/8",
	"::1/128",
	"::ffff:127.0.0.0/104",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"fe80::/10",
	"100.64.0.0/10",
	"fc00::/7",
	"169.254.169.254/32",
	"fd00:ec2::254/128",
	"100.100.100.200/32",
}

// metadataHosts contains blocked metadata hostnames.
var metadataHosts = map[string]bool{
	"metadata.google.internal": true,
}

// blockedNets is the parsed list of blocked networks.
var blockedNets []*net.IPNet

func init() {
	for _, cidr := range blockedRanges {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedNets = append(blockedNets, n)
		}
	}
}

// NormalizeIP unwraps IPv4-mapped IPv6 addresses.
func NormalizeIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil && ip.To16() != nil && !ip.Equal(v4) {
		return v4
	}
	return ip
}

// IsBlocked reports whether the given IP is in a blocked range.
func IsBlocked(ip net.IP) bool {
	ip = NormalizeIP(ip)
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsMetadataHost reports whether the hostname is a known metadata endpoint.
func IsMetadataHost(host string) bool {
	return metadataHosts[strings.ToLower(strings.TrimSpace(host))]
}

// AddBlockedRanges registers additional CIDRs to block.
func AddBlockedRanges(ranges []string) {
	for _, cidr := range ranges {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			blockedNets = append(blockedNets, n)
		}
	}
}
// Check resolves the host and validates the resolved IP against blocked ranges.
func Check(host string) (net.IP, error) {
	return CheckEx(host, true)
}

// CheckEx is like Check but allows toggling metadata blocking.
func CheckEx(host string, blockMetadata bool) (net.IP, error) {
	if blockMetadata && IsMetadataHost(host) {
		return nil, ErrBlocked
	}
	// If host is an IP literal, validate directly.
	if ip := net.ParseIP(host); ip != nil {
		if IsBlocked(ip) {
			return nil, ErrBlocked
		}
		return ip, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("%w: dns resolution failed: %v", ErrBlocked, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no addresses", ErrBlocked)
	}
	for _, ip := range ips {
		if IsBlocked(ip) {
			return nil, ErrBlocked
		}
	}
	return ips[0], nil
}
