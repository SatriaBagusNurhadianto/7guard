package quarantine

import (
	"testing"
	"time"
)

func TestQuarantineLifecycle(t *testing.T) {
	q := New()
	q.now = func() time.Time { return time.Unix(1000, 0) }

	if q.IsQuarantined("ip1") {
		t.Fatal("should not be quarantined initially")
	}
	q.Quarantine("ip1", "test", 10*time.Minute)
	if !q.IsQuarantined("ip1") {
		t.Fatal("should be quarantined")
	}
	if e, ok := q.Get("ip1"); !ok || e.Reason != "test" {
		t.Fatalf("entry missing/wrong: %+v", e)
	}

	// advance clock past expiry
	q.now = func() time.Time { return time.Unix(1000, 0).Add(11 * time.Minute) }
	if q.IsQuarantined("ip1") {
		t.Fatal("should have expired")
	}
	if removed := q.Cleanup(); removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}
	if q.Size() != 0 {
		t.Fatalf("expected size 0, got %d", q.Size())
	}
}

func TestQuarantineRelease(t *testing.T) {
	q := New()
	q.Quarantine("ip2", "r", time.Hour)
	q.Release("ip2")
	if q.IsQuarantined("ip2") {
		t.Fatal("should be released")
	}
}
