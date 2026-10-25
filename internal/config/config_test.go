package config

import (
	"testing"
)

func TestValidateProfile(t *testing.T) {
	for _, p := range ValidProfiles() {
		cfg := Default()
		cfg.Profile = p
		if err := cfg.Validate(); err != nil {
			t.Errorf("valid profile %s rejected: %v", p, err)
		}
	}

	cfg := Default()
	cfg.Profile = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Error("invalid profile accepted")
	}
}

func TestValidateMode(t *testing.T) {
	cfg := Default()
	cfg.Mode = "detect"
	if err := cfg.Validate(); err != nil {
		t.Errorf("detect mode rejected: %v", err)
	}

	cfg = Default()
	cfg.Mode = "block"
	if err := cfg.Validate(); err == nil {
		t.Error("block mode without confirm-block accepted")
	}

	cfg = Default()
	cfg.Mode = "block"
	cfg.ConfirmBlock = true
	if err := cfg.Validate(); err != nil {
		t.Errorf("block mode with confirm-block rejected: %v", err)
	}
}

func TestProfileGating(t *testing.T) {
	cfg := Default()
	cfg.Profile = "lite"
	cfg.Validate()

	// Lite should have basic features
	if !cfg.HasFeature("waf_basic") {
		t.Error("lite missing waf_basic")
	}
	if !cfg.HasFeature("rate_limit") {
		t.Error("lite missing rate_limit")
	}

	// Lite should NOT have advanced features
	if cfg.HasFeature("behavioral_analysis") {
		t.Error("lite has behavioral_analysis (should be advanced+)")
	}
	if cfg.HasFeature("quarantine") {
		t.Error("lite has quarantine (should be max only)")
	}

	// Full profile
	cfg2 := Default()
	cfg2.Profile = "full"
	cfg2.Validate()
	if !cfg2.HasFeature("bola_idor") {
		t.Error("full missing bola_idor")
	}
	if cfg2.HasFeature("behavioral_analysis") {
		t.Error("full has behavioral_analysis (should be advanced+)")
	}

	// RejectFeatureOverride
	if err := cfg.RejectFeatureOverride("behavioral_analysis"); err == nil {
		t.Error("expected error for unavailable feature override")
	}
}

func TestMaxBodySize(t *testing.T) {
	cfg := Default()
	cfg.MaxBodySize = 0
	if err := cfg.Validate(); err == nil {
		t.Error("zero max-body-size accepted")
	}

	cfg = Default()
	cfg.MaxBodySize = -1
	if err := cfg.Validate(); err == nil {
		t.Error("negative max-body-size accepted")
	}
}
