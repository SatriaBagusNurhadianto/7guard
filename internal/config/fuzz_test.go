package config

import (
	"testing"
)

// FuzzValidate ensures Validate never panics on arbitrary config values.
func FuzzValidate(f *testing.F) {
	f.Add("lite", "detect", "")
	f.Add("max", "block", "secret")
	f.Add("invalid", "nope", "x")
	f.Fuzz(func(t *testing.T, profile, mode, token string) {
		cfg := Default()
		cfg.Profile = profile
		cfg.Mode = mode
		cfg.MetricsAuthToken = token
		cfg.ConfirmBlock = (mode == "block")
		// Should not panic; error is acceptable.
		_ = cfg.Validate()
	})
}

// FuzzNewAllowlistViaConfig ensures config validation of egress hosts never panics.
func FuzzEgressHosts(f *testing.F) {
	f.Add("*.example.com")
	f.Add("not-a-cidr/99")
	f.Fuzz(func(t *testing.T, host string) {
		cfg := Default()
		cfg.EgressAllowedHosts = []string{host}
		_ = cfg.Validate()
	})
}
