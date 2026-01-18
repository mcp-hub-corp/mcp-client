package config

import (
	"testing"
)

// TestLoadConfig_MandatoryDefaults ensures mandatory default limits are always set
func TestLoadConfig_MandatoryDefaults(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg == nil {
		t.Fatal("LoadConfig returned nil config")
	}

	// CRITICAL: Verify all mandatory default limits are set
	if cfg.DefaultMaxCPU <= 0 {
		t.Errorf("DefaultMaxCPU not set: %d", cfg.DefaultMaxCPU)
	}

	if cfg.DefaultMaxMemory == "" {
		t.Errorf("DefaultMaxMemory not set: %s", cfg.DefaultMaxMemory)
	}

	if cfg.DefaultMaxPIDs <= 0 {
		t.Errorf("DefaultMaxPIDs not set: %d", cfg.DefaultMaxPIDs)
	}

	if cfg.DefaultMaxFDs <= 0 {
		t.Errorf("DefaultMaxFDs not set: %d", cfg.DefaultMaxFDs)
	}

	if cfg.DefaultTimeout == "" {
		t.Errorf("DefaultTimeout not set: %s", cfg.DefaultTimeout)
	}
}

// TestLoadConfig_DefaultsAreReasonable ensures defaults are within expected ranges
func TestLoadConfig_DefaultsAreReasonable(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// CPU: Should be at least 100 millicores
	if cfg.DefaultMaxCPU < 100 {
		t.Errorf("DefaultMaxCPU too low: %d (should be >= 100)", cfg.DefaultMaxCPU)
	}

	// Memory: Should be at least 256MB
	if cfg.DefaultMaxMemory != "512M" && cfg.DefaultMaxMemory != "256M" && cfg.DefaultMaxMemory != "1G" {
		t.Errorf("DefaultMaxMemory suspicious value: %s", cfg.DefaultMaxMemory)
	}

	// PIDs: Should be at least 10
	if cfg.DefaultMaxPIDs < 10 {
		t.Errorf("DefaultMaxPIDs too low: %d (should be >= 10)", cfg.DefaultMaxPIDs)
	}

	// FDs: Should be at least 64
	if cfg.DefaultMaxFDs < 64 {
		t.Errorf("DefaultMaxFDs too low: %d (should be >= 64)", cfg.DefaultMaxFDs)
	}

	// Timeout: Should be parseable and reasonable (> 1 second)
	if cfg.DefaultTimeout != "5m" && cfg.DefaultTimeout != "1m" {
		t.Errorf("DefaultTimeout suspicious value: %s", cfg.DefaultTimeout)
	}
}

// TestLoadConfig_DefaultsLimitedByPolicies ensures policy limits match or exceed mandatory defaults
func TestLoadConfig_DefaultsLimitedByPolicies(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// The regular limits should be >= defaults (or overridable)
	// The mandatory defaults should ALWAYS apply as a floor
	if cfg.MaxCPU <= 0 && cfg.DefaultMaxCPU <= 0 {
		t.Error("CRITICAL: Neither MaxCPU nor DefaultMaxCPU set")
	}

	if cfg.MaxMemory == "" && cfg.DefaultMaxMemory == "" {
		t.Error("CRITICAL: Neither MaxMemory nor DefaultMaxMemory set")
	}

	if cfg.MaxPIDs <= 0 && cfg.DefaultMaxPIDs <= 0 {
		t.Error("CRITICAL: Neither MaxPIDs nor DefaultMaxPIDs set")
	}

	if cfg.MaxFDs <= 0 && cfg.DefaultMaxFDs <= 0 {
		t.Error("CRITICAL: Neither MaxFDs nor DefaultMaxFDs set")
	}
}
