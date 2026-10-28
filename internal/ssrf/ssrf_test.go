package ssrf

import (
	"net"
	"testing"
)

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"::ffff:127.0.0.1", "127.0.0.1"},
		{"127.0.0.1", "127.0.0.1"},
		{"::1", "::1"},
	}
	for _, c := range cases {
		got := NormalizeIP(net.ParseIP(c.in))
		if got.String() != c.want {
			t.Errorf("NormalizeIP(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestIsBlocked(t *testing.T) {
	blocked := []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "fc00::1", "100.100.100.200"}
	for _, ip := range blocked {
		if !IsBlocked(net.ParseIP(ip)) {
			t.Errorf("expected blocked: %s", ip)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"}
	for _, ip := range allowed {
		if IsBlocked(net.ParseIP(ip)) {
			t.Errorf("expected allowed: %s", ip)
		}
	}
}

func TestIsMetadataHost(t *testing.T) {
	if !IsMetadataHost("metadata.google.internal") {
		t.Error("expected metadata.google.internal blocked")
	}
	if IsMetadataHost("example.com") {
		t.Error("expected example.com not blocked")
	}
}

func TestCheckIP(t *testing.T) {
	if _, err := Check("127.0.0.1"); err == nil {
		t.Error("expected error for 127.0.0.1")
	}
	ip, err := Check("8.8.8.8")
	if err != nil || ip == nil {
		t.Errorf("expected success for 8.8.8.8, got %v", err)
	}
}