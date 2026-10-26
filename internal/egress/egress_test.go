package egress

import (
	"context"
	"net"
	"testing"
)

func TestNewAllowlistValid(t *testing.T) {
	a, err := NewAllowlist([]string{
		"api.example.com",
		"*.example.com",
		"10.0.0.0/8",
		"192.168.1.1",
		"2001:db8::/32",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a == nil {
		t.Fatal("nil allowlist")
	}
}

func TestNewAllowlistInvalidCIDR(t *testing.T) {
	_, err := NewAllowlist([]string{"not-a-cidr/99"})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestNewAllowlistInvalidHost(t *testing.T) {
	_, err := NewAllowlist([]string{" "})
	// empty entries are skipped, so no error; just ensure no panic
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckHostnameExact(t *testing.T) {
	a, _ := NewAllowlist([]string{"api.example.com"})
	if !a.CheckHostname("api.example.com") {
		t.Error("expected allow")
	}
	if a.CheckHostname("evil.com") {
		t.Error("expected deny")
	}
}

func TestCheckHostnameCaseInsensitive(t *testing.T) {
	a, _ := NewAllowlist([]string{"api.example.com"})
	if !a.CheckHostname("API.Example.COM") {
		t.Error("expected allow (case-insensitive)")
	}
}

func TestCheckHostnameTrailingDot(t *testing.T) {
	a, _ := NewAllowlist([]string{"api.example.com"})
	if !a.CheckHostname("api.example.com.") {
		t.Error("expected allow (trailing dot trimmed)")
	}
}

func TestCheckHostnameWildcard(t *testing.T) {
	a, _ := NewAllowlist([]string{"*.example.com"})
	if !a.CheckHostname("foo.example.com") {
		t.Error("expected allow for subdomain")
	}
	if !a.CheckHostname("bar.foo.example.com") {
		t.Error("expected allow for nested subdomain")
	}
	if a.CheckHostname("example.com") {
		t.Error("expected deny for bare domain (wildcard should not match parent)")
	}
}

func TestCheckIPExact(t *testing.T) {
	a, _ := NewAllowlist([]string{"192.168.1.1"})
	if !a.CheckIP(net.ParseIP("192.168.1.1")) {
		t.Error("expected allow")
	}
	if a.CheckIP(net.ParseIP("10.0.0.1")) {
		t.Error("expected deny")
	}
}

func TestCheckIPCIDR(t *testing.T) {
	a, _ := NewAllowlist([]string{"10.0.0.0/8"})
	if !a.CheckIP(net.ParseIP("10.5.5.5")) {
		t.Error("expected allow (in CIDR)")
	}
	if a.CheckIP(net.ParseIP("192.168.1.1")) {
		t.Error("expected deny (not in CIDR)")
	}
}

func TestCheckIPCIDRv6(t *testing.T) {
	a, _ := NewAllowlist([]string{"2001:db8::/32"})
	if !a.CheckIP(net.ParseIP("2001:db8::1")) {
		t.Error("expected allow (in IPv6 CIDR)")
	}
	if a.CheckIP(net.ParseIP("2001:db9::1")) {
		t.Error("expected deny (not in CIDR)")
	}
}

func TestCheckIPMappedV6(t *testing.T) {
	a, _ := NewAllowlist([]string{"127.0.0.1"})
	ip := net.ParseIP("::ffff:127.0.0.1")
	if !a.CheckIP(ip) {
		t.Error("expected allow (IPv4-mapped IPv6 normalized to IPv4)")
	}
}

func TestCheckURLAllowed(t *testing.T) {
	a, _ := NewAllowlist([]string{"api.example.com"})
	ok, reason := a.Check("https://api.example.com/path")
	if !ok || reason != ReasonAllowed {
		t.Errorf("expected allow, got %v %s", ok, reason)
	}
}

func TestCheckURLDenied(t *testing.T) {
	a, _ := NewAllowlist([]string{"api.example.com"})
	ok, reason := a.Check("https://evil.com/path")
	if ok {
		t.Error("expected deny")
	}
	if reason != ReasonAllowlist {
		t.Errorf("expected reason %s, got %s", ReasonAllowlist, reason)
	}
}

func TestCheckURLUserinfo(t *testing.T) {
	a, _ := NewAllowlist([]string{"api.example.com"})
	ok, reason := a.Check("https://api.example.com@evil.com/path")
	if ok {
		t.Error("expected deny")
	}
	if reason != ReasonUserinfo {
		t.Errorf("expected reason %s, got %s", ReasonUserinfo, reason)
	}
}

func TestCheckURLEmptyHost(t *testing.T) {
	a, _ := NewAllowlist([]string{"api.example.com"})
	ok, reason := a.Check("https:///path")
	if ok {
		t.Error("expected deny")
	}
	if reason != ReasonEmptyHost {
		t.Errorf("expected reason %s, got %s", ReasonEmptyHost, reason)
	}
}

func TestCheckURLLiteralIPAllowed(t *testing.T) {
	a, _ := NewAllowlist([]string{"10.0.0.0/8"})
	ok, reason := a.Check("http://10.1.2.3/path")
	if !ok || reason != ReasonAllowed {
		t.Errorf("expected allow, got %v %s", ok, reason)
	}
}

func TestCheckURLLiteralIPDenied(t *testing.T) {
	a, _ := NewAllowlist([]string{"10.0.0.0/8"})
	ok, _ := a.Check("http://192.168.1.1/path")
	if ok {
		t.Error("expected deny")
	}
}

func TestCheckNilAllowlist(t *testing.T) {
	var a *Allowlist
	ok, _ := a.Check("https://example.com")
	if ok {
		t.Error("nil allowlist should deny")
	}
	if a.CheckHostname("example.com") {
		t.Error("nil allowlist hostname should deny")
	}
	if a.CheckIP(net.ParseIP("1.2.3.4")) {
		t.Error("nil allowlist IP should deny")
	}
}

func TestValidateRedirect(t *testing.T) {
	a, _ := NewAllowlist([]string{"api.example.com"})
	if !a.ValidateRedirect("https://api.example.com/cb") {
		t.Error("expected allow")
	}
	if a.ValidateRedirect("https://evil.com/cb") {
		t.Error("expected deny")
	}
}

func TestTwoPhaseHostnameVsIP(t *testing.T) {
	// hostname entry should not match an IP, and vice versa
	a, _ := NewAllowlist([]string{"api.example.com", "10.0.0.0/8"})
	// hostname matches
	ok, _ := a.Check("https://api.example.com/x")
	if !ok {
		t.Error("hostname entry should allow api.example.com")
	}
	// IP in CIDR matches
	ok, _ = a.Check("http://10.5.5.5/x")
	if !ok {
		t.Error("CIDR entry should allow 10.5.5.5")
	}
	// hostname not in list and not IP → deny
	ok, _ = a.Check("https://other.com/x")
	if ok {
		t.Error("unknown hostname should deny")
	}
}

func TestDialContextBlockModeDenied(t *testing.T) {
	al, _ := NewAllowlist([]string{"allowed.example.com"})
	al.Mode = EgressModeBlock
	dial := al.DialContext(func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	})
	_, err := dial(context.Background(), "tcp", "evil.example.com:80")
	if err == nil {
		t.Fatal("expected deny in block mode")
	}
}

func TestDialContextDetectModeAllows(t *testing.T) {
	al, _ := NewAllowlist([]string{"allowed.example.com"})
	al.Mode = EgressModeDetect
	var decisions []bool
	al.OnDecision = func(allowed bool, reason string) { decisions = append(decisions, allowed) }
	dial := al.DialContext(func(host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	})
	// denied by policy but detect mode allows dial; dial will fail (no server) but OnDecision fired once as denied
	_, _ = dial(context.Background(), "tcp", "evil.example.com:80")
	if len(decisions) != 1 {
		t.Fatalf("expected exactly one OnDecision call, got %d", len(decisions))
	}
	if decisions[0] {
		t.Fatal("expected denied decision recorded")
	}
}

func TestDialContextDefaultDeny(t *testing.T) {
	al, _ := NewAllowlist([]string{})
	al.Mode = EgressModeBlock
	dial := al.DialContext(nil)
	_, err := dial(context.Background(), "tcp", "anything.example.com:80")
	if err == nil {
		t.Fatal("expected default-deny in block mode with empty allowlist")
	}
}

func TestDialContextDNSRebinding(t *testing.T) {
	al, _ := NewAllowlist([]string{"allowed.example.com"})
	al.Mode = EgressModeBlock
	dial := al.DialContext(func(host string) ([]net.IP, error) {
		// hostname allowlisted but resolves to loopback -> rebinding
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	})
	_, err := dial(context.Background(), "tcp", "allowed.example.com:80")
	if err == nil {
		t.Fatal("expected deny on dns rebinding to loopback")
	}
}

func TestDialContextEmptyHost(t *testing.T) {
	al, _ := NewAllowlist([]string{"allowed.example.com"})
	al.Mode = EgressModeBlock
	dial := al.DialContext(nil)
	_, err := dial(context.Background(), "tcp", ":80")
	if err == nil {
		t.Fatal("expected deny on empty host")
	}
}
