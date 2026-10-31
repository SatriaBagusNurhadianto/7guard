package ssrf

import (
	"net"
	"testing"
)

func TestAuditNewBlockedRanges(t *testing.T) {
	cases := []string{
		"0.0.0.0", // 0.0.0.0/8
		"0.255.255.255",
		"::",        // ::/128
		"224.0.0.1", // multicast 224.0.0.0/4
		"239.255.255.255",
		"240.0.0.1",       // reserved 240.0.0.0/4
		"255.255.255.255", // broadcast
	}
	for _, ip := range cases {
		if !IsBlocked(net.ParseIP(ip)) {
			t.Errorf("expected blocked (new range): %s", ip)
		}
	}
	// sanity: public IPs still allowed
	for _, ip := range []string{"8.8.8.8", "1.1.1.1"} {
		if IsBlocked(net.ParseIP(ip)) {
			t.Errorf("expected allowed: %s", ip)
		}
	}
}

func TestAuditAddBlockedRangesConcurrency(t *testing.T) {
	// Exercise the new RWMutex under concurrent Add + IsBlocked.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			AddBlockedRanges([]string{"192.0.2.0/24"})
		}
		close(done)
	}()
	for i := 0; i < 200; i++ {
		_ = IsBlocked(net.ParseIP("192.0.2.5"))
	}
	<-done
	if !IsBlocked(net.ParseIP("192.0.2.5")) {
		t.Error("expected 192.0.2.5 blocked after AddBlockedRanges")
	}
}
