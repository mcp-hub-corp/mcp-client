package policy

import (
	"fmt"
	"strings"
)

// OriginPolicy represents policy enforcement for MCP origin types
type OriginPolicy struct {
	AllowedOrigins []string // Empty list = allow all origins
}

// NewOriginPolicy creates a new origin policy with the specified allowed origins
func NewOriginPolicy(allowedOrigins []string) *OriginPolicy {
	return &OriginPolicy{
		AllowedOrigins: allowedOrigins,
	}
}

// Validate checks if the given origin is allowed by the policy
// Returns nil if allowed, error if blocked
func (p *OriginPolicy) Validate(origin string) error {
	// Empty allowlist means allow all origins
	if len(p.AllowedOrigins) == 0 {
		return nil
	}

	// Normalize origin for comparison (case-insensitive)
	normalizedOrigin := strings.ToLower(strings.TrimSpace(origin))

	// Check if origin is in allowlist
	for _, allowed := range p.AllowedOrigins {
		normalizedAllowed := strings.ToLower(strings.TrimSpace(allowed))
		if normalizedOrigin == normalizedAllowed {
			return nil
		}
	}

	// Origin not in allowlist
	return fmt.Errorf("origin %q is not allowed by policy (allowed origins: %v)", origin, p.AllowedOrigins)
}

// IsEmpty returns true if the policy has no restrictions (allows all origins)
func (p *OriginPolicy) IsEmpty() bool {
	return len(p.AllowedOrigins) == 0
}
