package config

import (
	"fmt"
	"strings"

	"github.com/SatriaBagusNurhadianto/7guard/internal/egress"
)

// Profile constants
const (
	ProfileLite     = "lite"
	ProfileFull     = "full"
	ProfileAdvanced = "advanced"
	ProfileMax      = "max"
)

// Mode constants
const (
	ModeDetect = "detect"
	ModeBlock  = "block"
)

// EgressMode constants
const (
	EgressModeDetect = "detect"
	EgressModeBlock  = "block"
)

// Config holds all runtime configuration for 7Guard.
type Config struct {
	Profile      string
	Mode         string
	ConfirmBlock bool
	ListenAddr   string
	Upstream     string
	MaxBodySize  int64
	RulesDir     string
	RateLimit    int // requests per minute
	RateBurst    int // burst size
	TLSCertFile  string
	TLSKeyFile   string
	JWTSecret    string

	// Egress control
	EgressMode         string
	EgressAllowedHosts []string

	// SSRF protection
	SSRFMode          string
	SSRFAllowedHosts  []string
	SSRFBlockedRanges []string
	SSRFBlockMetadata bool

	// Response body inspection (data-leakage detection)
	ResponseInspectionMode         string
	ResponseInspectionMaxBodyBytes int64
	ResponseInspectionContentTypes []string
	ResponseInspectionOnLeak       string
	ResponseInspectionReplaceToken string
	ResponseInspectionDecompress   bool

	// Feature flags (set by profile)
	Features map[string]bool

	// Observability (infrastructure, not profile-gated)
	MetricsEnabled   bool
	MetricsAuthToken string

	// Quarantine cleanup interval (seconds; 0 = default 60)
	QuarantineCleanupInterval int
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Profile:                        ProfileLite,
		Mode:                           ModeDetect,
		ListenAddr:                     ":8080",
		Upstream:                       "http://localhost:9090",
		MaxBodySize:                    1 << 20, // 1 MB
		RulesDir:                       "./rules",
		RateLimit:                      0, // set by profile
		RateBurst:                      0, // set by profile
		Features:                       map[string]bool{},
		MetricsEnabled:                 true,
		EgressMode:                     EgressModeDetect,
		SSRFMode:                       EgressModeDetect,
		SSRFBlockMetadata:              true,
		ResponseInspectionMode:         "detect",
		ResponseInspectionMaxBodyBytes: 1 << 20,
		ResponseInspectionOnLeak:       "replace",
		ResponseInspectionReplaceToken: "[REDACTED]",
		ResponseInspectionDecompress:   true,
	}
}

// ValidProfiles returns all valid profile names.
func ValidProfiles() []string {
	return []string{ProfileLite, ProfileFull, ProfileAdvanced, ProfileMax}
}

// ValidModes returns all valid mode names.
func ValidModes() []string {
	return []string{ModeDetect, ModeBlock}
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	// Validate profile
	validProfile := false
	for _, p := range ValidProfiles() {
		if c.Profile == p {
			validProfile = true
			break
		}
	}
	if !validProfile {
		return fmt.Errorf("invalid profile %q, must be one of: %s", c.Profile, strings.Join(ValidProfiles(), ", "))
	}

	// Validate mode
	validMode := false
	for _, m := range ValidModes() {
		if c.Mode == m {
			validMode = true
			break
		}
	}
	if !validMode {
		return fmt.Errorf("invalid mode %q, must be one of: %s", c.Mode, strings.Join(ValidModes(), ", "))
	}

	// Block mode requires explicit confirmation
	if c.Mode == ModeBlock && !c.ConfirmBlock {
		return fmt.Errorf("block mode requires --confirm-block flag (safety: prevents accidental blocking)")
	}

	// Validate max body size
	if c.MaxBodySize <= 0 {
		return fmt.Errorf("max-body-size must be positive, got %d", c.MaxBodySize)
	}

	// Validate egress mode
	if c.EgressMode != "" && c.EgressMode != EgressModeDetect && c.EgressMode != EgressModeBlock {
		return fmt.Errorf("invalid egress mode %q, must be detect or block", c.EgressMode)
	}
	if c.SSRFMode != "" && c.SSRFMode != EgressModeDetect && c.SSRFMode != EgressModeBlock && c.SSRFMode != "off" {
		return fmt.Errorf("invalid ssrf mode %q, must be off, detect, or block", c.SSRFMode)
	}
	if c.EgressMode == "" {
		c.EgressMode = EgressModeDetect
	}
	if c.SSRFMode == "" {
		c.SSRFMode = EgressModeDetect
	}

	// Validate egress allowlist (fail-closed on malformed entries)
	if len(c.EgressAllowedHosts) > 0 {
		if _, err := egress.NewAllowlist(c.EgressAllowedHosts); err != nil {
			return fmt.Errorf("invalid egress allowed hosts: %w", err)
		}
	}

	// Validate response inspection mode
	if c.ResponseInspectionMode != "" && c.ResponseInspectionMode != EgressModeDetect && c.ResponseInspectionMode != EgressModeBlock {
		return fmt.Errorf("invalid response inspection mode %q, must be detect or block", c.ResponseInspectionMode)
	}
	if c.ResponseInspectionMode == "" {
		c.ResponseInspectionMode = EgressModeDetect
	}
	if c.ResponseInspectionMaxBodyBytes <= 0 {
		return fmt.Errorf("response-inspection-max-body-bytes must be positive, got %d", c.ResponseInspectionMaxBodyBytes)
	}
	if c.ResponseInspectionOnLeak == "" {
		c.ResponseInspectionOnLeak = "replace"
	}
	if c.ResponseInspectionOnLeak != "strip" && c.ResponseInspectionOnLeak != "replace" && c.ResponseInspectionOnLeak != "block" {
		return fmt.Errorf("invalid response-inspection on-leak %q, must be strip/replace/block", c.ResponseInspectionOnLeak)
	}
	if c.ResponseInspectionReplaceToken == "" {
		c.ResponseInspectionReplaceToken = "[REDACTED]"
	}

	// Load profile features
	c.loadProfileFeatures()

	return nil
}

// loadProfileFeatures sets feature flags based on the selected profile.
func (c *Config) loadProfileFeatures() {
	// Per-profile rate limits
	switch c.Profile {
	case ProfileLite:
		if c.RateLimit == 0 {
			c.RateLimit = 60
		}
		if c.RateBurst == 0 {
			c.RateBurst = 10
		}
	case ProfileFull:
		if c.RateLimit == 0 {
			c.RateLimit = 120
		}
		if c.RateBurst == 0 {
			c.RateBurst = 20
		}
	case ProfileAdvanced:
		if c.RateLimit == 0 {
			c.RateLimit = 300
		}
		if c.RateBurst == 0 {
			c.RateBurst = 50
		}
	case ProfileMax:
		if c.RateLimit == 0 {
			c.RateLimit = 600
		}
		if c.RateBurst == 0 {
			c.RateBurst = 100
		}
	}

	// All profiles get Lite features
	c.Features["waf_basic"] = true
	c.Features["rate_limit"] = true
	c.Features["ip_filter"] = true
	c.Features["jwt_security"] = true
	c.Features["bounded_logging"] = true

	if c.Profile == ProfileFull || c.Profile == ProfileAdvanced || c.Profile == ProfileMax {
		c.Features["waf_advanced"] = true
		c.Features["bola_idor"] = true
		c.Features["async_alerting"] = true
		c.Features["egress_control"] = true
		c.Features["behavioral_signals"] = true
		c.Features["response_inspection"] = true
		c.Features["ssrf_basic"] = true
	}

	if c.Profile == ProfileAdvanced || c.Profile == ProfileMax {
		c.Features["behavioral_analysis"] = true
		c.Features["attack_chain"] = true
		c.Features["session_analysis"] = true
		c.Features["adaptive_rate_limit"] = true
		// Experimental: excluded from release-blocking criteria
		c.Features["experimental"] = true
	}

	if c.Profile == ProfileMax {
		c.Features["multi_dim_correlation"] = true
		c.Features["quarantine"] = true
		c.Features["adaptive_defense"] = true
		c.Features["forensic_context"] = true
	}
}

// HasFeature checks if a feature is enabled for the current profile.
// Defense-in-depth: rejects if feature is not in the feature map at all.
func (c *Config) HasFeature(name string) bool {
	enabled, exists := c.Features[name]
	if !exists {
		return false
	}
	return enabled
}

// RejectFeatureOverride prevents manually enabling features not in the profile.
// Returns error if a feature flag is set that shouldn't be available.
func (c *Config) RejectFeatureOverride(feature string) error {
	if !c.HasFeature(feature) {
		return fmt.Errorf("feature %q is not available in profile %q", feature, c.Profile)
	}
	return nil
}
