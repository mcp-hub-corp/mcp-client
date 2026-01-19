package policy

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCertLevelPolicy(t *testing.T) {
	tests := []struct {
		name         string
		minCertLevel int
		enforceMode  string
		expectedMin  int
		expectedMode string
	}{
		{"default_no_enforcement", 0, DisabledMode, 0, DisabledMode},
		{"level_1_strict", 1, StrictMode, 1, StrictMode},
		{"level_2_warn", 2, WarnMode, 2, WarnMode},
		{"level_3_strict", 3, StrictMode, 3, StrictMode},
		{"invalid_mode_defaults_disabled", 1, "invalid", 1, DisabledMode},
		{"clamp_negative_level", -1, StrictMode, 0, StrictMode},
		{"clamp_over_max_level", 5, StrictMode, 3, StrictMode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := NewCertLevelPolicy(tt.minCertLevel, tt.enforceMode)
			assert.Equal(t, tt.expectedMin, policy.MinCertLevel)
			assert.Equal(t, tt.expectedMode, policy.EnforceMode)
		})
	}
}

func TestNewCertLevelPolicyWithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	policy := NewCertLevelPolicyWithLogger(2, StrictMode, logger)

	assert.Equal(t, 2, policy.MinCertLevel)
	assert.Equal(t, StrictMode, policy.EnforceMode)
	assert.NotNil(t, policy.logger)
}

func TestCertLevelPolicy_ValidateDisabledMode(t *testing.T) {
	policy := NewCertLevelPolicy(2, DisabledMode)

	// Should allow any cert level in disabled mode
	assert.NoError(t, policy.Validate(0))
	assert.NoError(t, policy.Validate(1))
	assert.NoError(t, policy.Validate(2))
	assert.NoError(t, policy.Validate(3))
}

func TestCertLevelPolicy_ValidateNoMinimum(t *testing.T) {
	policy := NewCertLevelPolicy(0, StrictMode)

	// With minimum 0, should allow all levels
	assert.NoError(t, policy.Validate(0))
	assert.NoError(t, policy.Validate(1))
	assert.NoError(t, policy.Validate(2))
	assert.NoError(t, policy.Validate(3))
}

func TestCertLevelPolicy_ValidateStrictMode(t *testing.T) {
	tests := []struct {
		name         string
		minCertLevel int
		certLevel    int
		shouldError  bool
	}{
		{"cert_level_meets_minimum", 2, 2, false},
		{"cert_level_exceeds_minimum", 1, 3, false},
		{"cert_level_below_minimum", 2, 1, true},
		{"cert_level_zero_below_minimum", 1, 0, true},
		{"cert_level_boundary", 2, 2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := NewCertLevelPolicy(tt.minCertLevel, StrictMode)
			err := policy.Validate(tt.certLevel)

			if tt.shouldError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "certification level")
				assert.Contains(t, err.Error(), "below minimum")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCertLevelPolicy_ValidateWarnMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	policy := NewCertLevelPolicyWithLogger(2, WarnMode, logger)

	// Warn mode should allow execution even when cert level is below minimum
	// but would log a warning (we can't easily verify logging in this test)
	tests := []struct {
		certLevel int
	}{
		{0},
		{1},
		{2},
		{3},
	}

	for _, tt := range tests {
		t.Run("warn_mode_allows_all_levels", func(t *testing.T) {
			err := policy.Validate(tt.certLevel)
			assert.NoError(t, err, "warn mode should not return error")
		})
	}
}

func TestCertLevelPolicy_ValidateClamping(t *testing.T) {
	policy := NewCertLevelPolicy(2, StrictMode)

	// Negative cert level should be clamped to 0
	err := policy.Validate(-5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "below minimum")

	// Over-max cert level should be clamped to 3
	err = policy.Validate(100)
	assert.NoError(t, err) // 3 >= 2
}

func TestCertLevelPolicy_IsEnforced(t *testing.T) {
	tests := []struct {
		mode       string
		isEnforced bool
	}{
		{DisabledMode, false},
		{StrictMode, true},
		{WarnMode, true},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			policy := NewCertLevelPolicy(1, tt.mode)
			assert.Equal(t, tt.isEnforced, policy.IsEnforced())
		})
	}
}

func TestCertLevelPolicy_GetMinCertLevel(t *testing.T) {
	policy := NewCertLevelPolicy(2, StrictMode)
	assert.Equal(t, 2, policy.GetMinCertLevel())
}

func TestCertLevelPolicy_GetEnforceMode(t *testing.T) {
	policy := NewCertLevelPolicy(1, WarnMode)
	assert.Equal(t, WarnMode, policy.GetEnforceMode())
}

func TestCertLevelPolicy_ValidateWithLogging(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	policy := NewCertLevelPolicyWithLogger(2, StrictMode, logger)

	// Should log and then validate
	err := policy.ValidateWithLogging(1, "test/package")
	assert.Error(t, err)

	err = policy.ValidateWithLogging(2, "test/package")
	assert.NoError(t, err)
}

func TestCertLevelNames(t *testing.T) {
	assert.Equal(t, "Integrity Verified", CertLevelNames[0])
	assert.Equal(t, "Static Verified", CertLevelNames[1])
	assert.Equal(t, "Security Certified", CertLevelNames[2])
	assert.Equal(t, "Runtime Certified", CertLevelNames[3])
}

func TestCertLevelPolicy_AllModes(t *testing.T) {
	// Test strict mode blocking
	strictPolicy := NewCertLevelPolicy(2, StrictMode)
	assert.Error(t, strictPolicy.Validate(1))

	// Test warn mode allowing
	warnPolicy := NewCertLevelPolicy(2, WarnMode)
	assert.NoError(t, warnPolicy.Validate(1))

	// Test disabled mode allowing
	disabledPolicy := NewCertLevelPolicy(2, DisabledMode)
	assert.NoError(t, disabledPolicy.Validate(1))
}

func TestCertLevelPolicy_ErrorMessages(t *testing.T) {
	policy := NewCertLevelPolicy(2, StrictMode)

	err := policy.Validate(1)
	require.Error(t, err)

	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "certification level 1")
	assert.Contains(t, errorMsg, "Static Verified")
	assert.Contains(t, errorMsg, "minimum required level 2")
	assert.Contains(t, errorMsg, "Security Certified")
}

func TestCertLevelPolicy_IntegrationWithOriginPolicy(t *testing.T) {
	// Test that cert level policy and origin policy can work together
	certLevelPolicy := NewCertLevelPolicy(1, StrictMode)
	originPolicy := NewOriginPolicy([]string{"official", "verified"})

	// Origin policy check
	originErr := originPolicy.Validate("official")
	assert.NoError(t, originErr)

	// Cert level policy check
	certErr := certLevelPolicy.Validate(1)
	assert.NoError(t, certErr)

	// Both should work independently
	originErr = originPolicy.Validate("community")
	assert.Error(t, originErr)

	certErr = certLevelPolicy.Validate(0)
	assert.Error(t, certErr)
}

func TestCertLevelPolicy_BoundaryValues(t *testing.T) {
	tests := []struct {
		name    string
		minLevel int
		testLevel int
		expectError bool
	}{
		{"min_0_test_0", 0, 0, false},
		{"min_0_test_3", 0, 3, false},
		{"min_1_test_0", 1, 0, true},
		{"min_1_test_1", 1, 1, false},
		{"min_3_test_2", 3, 2, true},
		{"min_3_test_3", 3, 3, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := NewCertLevelPolicy(tt.minLevel, StrictMode)
			err := policy.Validate(tt.testLevel)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
