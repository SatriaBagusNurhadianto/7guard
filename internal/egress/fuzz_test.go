package egress

import (
	"net"
	"net/url"
	"testing"
)

// FuzzNormalizeHost ensures normalizeHost never panics.
func FuzzNormalizeHost(f *testing.F) {
	f.Add("API.Example.COM.")
	f.Add("")
	f.Add("::ffff:127.0.0.1")
	f.Fuzz(func(t *testing.T, s string) {
		_ = normalizeHost(s)
	})
}

// FuzzNewAllowlist ensures parsing never panics.
func FuzzNewAllowlist(f *testing.F) {
	f.Add("*.example.com")
	f.Add("10.0.0.0/8")
	f.Add("192.168.1.1")
	f.Add("bad entry")
	f.Fuzz(func(t *testing.T, s string) {
		a, err := NewAllowlist([]string{s})
		if err == nil && a != nil {
			_ = a.CheckHostname(s)
		}
	})
}

// FuzzCheck ensures Check never panics.
func FuzzCheck(f *testing.F) {
	f.Add("https://api.example.com/path")
	f.Add("http://evil.com@allowed.com/")
	f.Add("https:///path")
	f.Fuzz(func(t *testing.T, s string) {
		a, _ := NewAllowlist([]string{"api.example.com", "10.0.0.0/8"})
		_, _ = a.Check(s)
	})
}

// FuzzCheckIP ensures CheckIP handles arbitrary IPs.
func FuzzCheckIP(f *testing.F) {
	f.Add("127.0.0.1")
	f.Add("::ffff:127.0.0.1")
	f.Add("not-an-ip")
	f.Fuzz(func(t *testing.T, s string) {
		a, _ := NewAllowlist([]string{"10.0.0.0/8"})
		ip := net.ParseIP(s)
		if ip != nil {
			_ = a.CheckIP(ip)
		}
	})
}

// FuzzURLParse ensures url.Parse + Check don't panic.
func FuzzURLParse(f *testing.F) {
	f.Add("http://a@b/c")
	f.Fuzz(func(t *testing.T, s string) {
		u, err := url.Parse(s)
		if err != nil {
			return
		}
		a, _ := NewAllowlist([]string{"example.com"})
		_, _ = a.Check(u.String())
	})
}
