package policy

import (
	"fmt"
	"log/slog"
)

// CertLevelPolicy represents policy enforcement for certification levels
type CertLevelPolicy struct {
	MinCertLevel int    // 0-3 (0: Integrity Verified, 1: Static Verified, 2: Security Certified, 3: Runtime Certified)
	EnforceMode  string // strict, warn, disabled
	logger       *slog.Logger
}

// CertLevelModes
const (
	// Strict mode: block execution if cert_level is below minimum
	StrictMode = "strict"

	// Warn mode: allow execution but log warning
	WarnMode = "warn"

	// Disabled mode: no enforcement (allow everything)
	DisabledMode = "disabled"
)

// CertLevelNames maps certification levels to human-readable names
var CertLevelNames = map[int]string{
	0: "Integrity Verified",
	1: "Static Verified",
	2: "Security Certified",
	3: "Runtime Certified",
}

// NewCertLevelPolicy creates a new certification level policy
func NewCertLevelPolicy(minCertLevel int, enforceMode string) *CertLevelPolicy {
	logger := slog.Default()
	return NewCertLevelPolicyWithLogger(minCertLevel, enforceMode, logger)
}

// NewCertLevelPolicyWithLogger creates a new certification level policy with custom logger
func NewCertLevelPolicyWithLogger(minCertLevel int, enforceMode string, logger *slog.Logger) *CertLevelPolicy {
	// Normalize enforce mode
	if enforceMode != StrictMode && enforceMode != WarnMode && enforceMode != DisabledMode {
		enforceMode = DisabledMode // Default to disabled for invalid modes
	}

	// Clamp min_cert_level to valid range (0-3)
	if minCertLevel < 0 {
		minCertLevel = 0
	}
	if minCertLevel > 3 {
		minCertLevel = 3
	}

	return &CertLevelPolicy{
		MinCertLevel: minCertLevel,
		EnforceMode:  enforceMode,
		logger:       logger,
	}
}

// Validate checks if the given certification level meets the policy requirements
// Returns nil if allowed, error if blocked (in strict mode)
func (p *CertLevelPolicy) Validate(certLevel int) error {
	// If enforcement is disabled, always allow
	if p.EnforceMode == DisabledMode {
		return nil
	}

	// If minimum is not set (0), allow everything
	if p.MinCertLevel == 0 {
		return nil
	}

	// Clamp cert_level to valid range
	if certLevel < 0 {
		certLevel = 0
	}
	if certLevel > 3 {
		certLevel = 3
	}

	// Check if cert level meets minimum requirement
	if certLevel >= p.MinCertLevel {
		return nil
	}

	// Cert level is below minimum
	minName := CertLevelNames[p.MinCertLevel]
	currentName := CertLevelNames[certLevel]

	message := fmt.Sprintf(
		"certification level %d (%s) is below minimum required level %d (%s)",
		certLevel, currentName, p.MinCertLevel, minName,
	)

	if p.EnforceMode == WarnMode {
		p.logger.Warn(message,
			slog.Int("certification_level", certLevel),
			slog.Int("minimum_required", p.MinCertLevel),
			slog.String("enforce_mode", "warn"),
		)
		return nil // Allow execution in warn mode
	}

	// Strict mode: block execution
	return fmt.Errorf(message)
}

// ValidateWithLogging validates and logs the decision
func (p *CertLevelPolicy) ValidateWithLogging(certLevel int, packageID string) error {
	// Log the validation attempt
	minName := CertLevelNames[p.MinCertLevel]
	currentName := CertLevelNames[certLevel]

	p.logger.Debug("validating certification level",
		slog.String("package", packageID),
		slog.Int("certification_level", certLevel),
		slog.String("level_name", currentName),
		slog.Int("minimum_required", p.MinCertLevel),
		slog.String("minimum_name", minName),
		slog.String("enforce_mode", p.EnforceMode),
	)

	return p.Validate(certLevel)
}

// IsEnforced returns true if the policy is actively enforced (not disabled)
func (p *CertLevelPolicy) IsEnforced() bool {
	return p.EnforceMode != DisabledMode
}

// GetMinCertLevel returns the minimum certification level required
func (p *CertLevelPolicy) GetMinCertLevel() int {
	return p.MinCertLevel
}

// GetEnforceMode returns the enforcement mode
func (p *CertLevelPolicy) GetEnforceMode() string {
	return p.EnforceMode
}
