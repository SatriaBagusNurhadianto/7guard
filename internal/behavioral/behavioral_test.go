package behavioral

import (
	"testing"
	"time"
)

func TestNewDefaultChains(t *testing.T) {
	d := New(nil)
	if len(d.chains) != 5 {
		t.Errorf("expected 5 default chains, got %d", len(d.chains))
	}
}

func TestRecordNoAlert(t *testing.T) {
	d := New(nil)
	alerts := d.Record(Event{
		RequestID: "r1",
		ClientIP:  "1.2.3.4",
		Timestamp: time.Now(),
		Score:     1,
	})
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts, got %d", len(alerts))
	}
}

func TestAuthBruteForce(t *testing.T) {
	d := New(nil)
	now := time.Now()

	var alerts []ChainAlert
	for i := 0; i < 5; i++ {
		a := d.Record(Event{
			RequestID: "r" + string(rune('0'+i)),
			ClientIP:  "1.2.3.4",
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Score:     3,
		})
		alerts = append(alerts, a...)
	}

	if len(alerts) == 0 {
		t.Error("expected auth-brute-force alert after 5 failed auths")
	}
	found := false
	for _, a := range alerts {
		if a.ChainID == "auth-brute-force" {
			found = true
		}
	}
	if !found {
		t.Error("auth-brute-force chain not detected")
	}
}

func TestSQLiThenTraversal(t *testing.T) {
	d := New(nil)
	now := time.Now()

	d.Record(Event{
		RequestID:   "r1",
		ClientIP:    "1.2.3.4",
		Timestamp:   now,
		RuleMatches: []string{"sqli-union-select"},
		Score:       5,
	})
	alerts := d.Record(Event{
		RequestID:   "r2",
		ClientIP:    "1.2.3.4",
		Timestamp:   now.Add(10 * time.Second),
		RuleMatches: []string{"trav-basic-dotdot-slash"},
		Score:       5,
	})

	found := false
	for _, a := range alerts {
		if a.ChainID == "sqli-then-traversal" {
			found = true
		}
	}
	if !found {
		t.Error("sqli-then-traversal chain not detected")
	}
}

func TestReconScan(t *testing.T) {
	d := New(nil)
	now := time.Now()

	var alerts []ChainAlert
	for i := 0; i < 10; i++ {
		a := d.Record(Event{
			RequestID: "r" + string(rune('0'+i)),
			ClientIP:  "1.2.3.4",
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Path:      "/path" + string(rune('0'+i)),
			Score:     1,
		})
		alerts = append(alerts, a...)
	}

	found := false
	for _, a := range alerts {
		if a.ChainID == "recon-scan" {
			found = true
		}
	}
	if !found {
		t.Error("recon-scan chain not detected")
	}
}

func TestCleanup(t *testing.T) {
	d := New(nil)
	d.Record(Event{
		RequestID: "r1",
		ClientIP:  "1.2.3.4",
		Timestamp: time.Now().Add(-10 * time.Minute),
	})

	if d.WindowCount() != 1 {
		t.Errorf("expected 1 window, got %d", d.WindowCount())
	}

	d.Cleanup(1 * time.Minute)
	if d.WindowCount() != 0 {
		t.Errorf("expected 0 windows after cleanup, got %d", d.WindowCount())
	}
}

func TestSessionKey(t *testing.T) {
	d := New(nil)
	now := time.Now()

	// Same session ID should share window
	d.Record(Event{
		RequestID: "r1",
		ClientIP:  "1.2.3.4",
		SessionID: "sess-abc",
		Timestamp: now,
		Score:     3,
	})
	d.Record(Event{
		RequestID: "r2",
		ClientIP:  "5.6.7.8",  // different IP
		SessionID: "sess-abc", // same session
		Timestamp: now.Add(time.Second),
		Score:     3,
	})

	// Should be 1 window (session-based)
	if d.WindowCount() != 1 {
		t.Errorf("expected 1 window for same session, got %d", d.WindowCount())
	}
}

func TestSeverityEscalation(t *testing.T) {
	d := New(nil)
	now := time.Now()

	var alert *ChainAlert
	for i := 0; i < 5; i++ {
		a := d.Record(Event{
			RequestID: "r" + string(rune('0'+i)),
			ClientIP:  "1.2.3.4",
			Timestamp: now.Add(time.Duration(i) * time.Second),
			Score:     3,
		})
		for j := range a {
			alert = &a[j]
		}
	}

	if alert == nil {
		t.Fatal("no alert generated")
	}
	if alert.Severity != "high" {
		t.Errorf("expected high severity, got %s", alert.Severity)
	}
}
