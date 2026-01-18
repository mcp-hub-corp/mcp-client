package policy

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/security-mcp/mcp-client/internal/config"
	"github.com/security-mcp/mcp-client/internal/manifest"
)

// Policy represents local security policy and execution limits
type Policy struct {
	MaxCPU           int           // millicores
	MaxMemory        string        // e.g. "512M"
	MaxPIDs          int           // max process count
	MaxFDs           int           // max file descriptors
	DefaultTimeout   time.Duration // default execution timeout
	AllowSubprocess  bool          // allow subprocess creation
	NetworkAllowlist []string      // allowed domains/IPs
	EnvAllowlist     []string      // allowed env vars (if empty, all allowed)
	logger           *slog.Logger
}

// ExecutionLimits represents the final limits to apply to execution
type ExecutionLimits struct {
	MaxCPU    int           // millicores
	MaxMemory string        // e.g. "512M"
	MaxPIDs   int           // max process count
	MaxFDs    int           // max file descriptors
	Timeout   time.Duration // execution timeout
}

// NewPolicy creates a new policy from config
func NewPolicy(cfg *config.Config) *Policy {
	logger := slog.Default()

	return &Policy{
		MaxCPU:          cfg.MaxCPU,
		MaxMemory:       cfg.MaxMemory,
		MaxPIDs:         cfg.MaxPIDs,
		MaxFDs:          cfg.MaxFDs,
		DefaultTimeout:  cfg.Timeout,
		AllowSubprocess: false, // default deny
		logger:          logger,
	}
}

// NewPolicyWithLogger creates a new policy from config with custom logger
func NewPolicyWithLogger(cfg *config.Config, logger *slog.Logger) *Policy {
	return &Policy{
		MaxCPU:          cfg.MaxCPU,
		MaxMemory:       cfg.MaxMemory,
		MaxPIDs:         cfg.MaxPIDs,
		MaxFDs:          cfg.MaxFDs,
		DefaultTimeout:  cfg.Timeout,
		AllowSubprocess: false, // default deny
		logger:          logger,
	}
}

// ApplyManifestPermissions merges policy with manifest permissions
func (p *Policy) ApplyManifestPermissions(m *manifest.Manifest) error {
	if m == nil {
		return fmt.Errorf("manifest cannot be nil")
	}

	// Check subprocess permission
	if m.Permissions.Subprocess && !p.AllowSubprocess {
		p.logger.Warn("manifest requests subprocess but policy denies",
			slog.String("package", m.Package.ID))
		// Note: We still allow it for this phase, just log it
		// In production, this might be a failure point based on policy
	}

	// Store network allowlist from manifest
	if len(m.Permissions.Network) > 0 {
		p.NetworkAllowlist = m.Permissions.Network
		p.logger.Debug("applied manifest network allowlist",
			slog.Int("count", len(m.Permissions.Network)))
	}

	// Store env allowlist from manifest (if specified)
	if len(m.Permissions.Environment) > 0 {
		p.EnvAllowlist = m.Permissions.Environment
		p.logger.Debug("applied manifest environment allowlist",
			slog.Int("count", len(m.Permissions.Environment)))
	}

	return nil
}

// ApplyLimits merges policy limits with manifest limits (stricter wins)
func (p *Policy) ApplyLimits(m *manifest.Manifest) *ExecutionLimits {
	if m == nil {
		m = &manifest.Manifest{}
	}

	limits := &ExecutionLimits{
		MaxCPU:    p.MaxCPU,
		MaxMemory: p.MaxMemory,
		MaxPIDs:   p.MaxPIDs,
		MaxFDs:    p.MaxFDs,
		Timeout:   p.DefaultTimeout,
	}

	// Apply manifest limits if more restrictive
	if m.Limits.MaxCPU > 0 && m.Limits.MaxCPU < limits.MaxCPU {
		limits.MaxCPU = m.Limits.MaxCPU
		p.logger.Debug("manifest limit is stricter", slog.String("limit", "max_cpu"))
	}

	if m.Limits.MaxMemory != "" && isMoreRestrictiveMemory(m.Limits.MaxMemory, limits.MaxMemory) {
		limits.MaxMemory = m.Limits.MaxMemory
		p.logger.Debug("manifest limit is stricter", slog.String("limit", "max_memory"))
	}

	if m.Limits.MaxPIDs > 0 && m.Limits.MaxPIDs < limits.MaxPIDs {
		limits.MaxPIDs = m.Limits.MaxPIDs
		p.logger.Debug("manifest limit is stricter", slog.String("limit", "max_pids"))
	}

	if m.Limits.MaxFDs > 0 && m.Limits.MaxFDs < limits.MaxFDs {
		limits.MaxFDs = m.Limits.MaxFDs
		p.logger.Debug("manifest limit is stricter", slog.String("limit", "max_fds"))
	}

	if m.Limits.Timeout != "" {
		// Parse timeout and compare
		if parsedTimeout, err := time.ParseDuration(m.Limits.Timeout); err == nil {
			if parsedTimeout > 0 && parsedTimeout < limits.Timeout {
				limits.Timeout = parsedTimeout
				p.logger.Debug("manifest limit is stricter", slog.String("limit", "timeout"))
			}
		}
	}

	return limits
}

// ValidateEnv filters environment variables based on manifest allowlist
func (p *Policy) ValidateEnv(env map[string]string) map[string]string {
	if len(p.EnvAllowlist) == 0 {
		// If no allowlist, pass through all env vars
		return env
	}

	filtered := make(map[string]string)
	for _, key := range p.EnvAllowlist {
		if val, ok := env[key]; ok {
			filtered[key] = val
		}
	}

	return filtered
}

// ValidateNetwork checks if a network connection is allowed
func (p *Policy) ValidateNetwork(host string) bool {
	if len(p.NetworkAllowlist) == 0 {
		// Default deny if no allowlist specified
		return false
	}

	host = strings.ToLower(host)
	for _, allowed := range p.NetworkAllowlist {
		allowed = strings.ToLower(allowed)

		// Exact match
		if host == allowed {
			return true
		}

		// Subdomain match (e.g., *.example.com matches sub.example.com but not example.com)
		if strings.HasPrefix(allowed, "*.") {
			domain := allowed[2:] // Remove "*."
			// Must have at least one subdomain prefix
			if strings.HasSuffix(host, "."+domain) {
				return true
			}
		}

		// IP range or CIDR matching could be added here in the future
	}

	return false
}

// isMoreRestrictiveMemory compares memory limits and returns true if new is more restrictive
func isMoreRestrictiveMemory(newLimit, currentLimit string) bool {
	newVal := parseMemoryString(newLimit)
	currentVal := parseMemoryString(currentLimit)

	if newVal <= 0 || currentVal <= 0 {
		return false // Invalid format, don't override
	}

	return newVal < currentVal
}

// parseMemoryString parses memory strings like "512M", "1G" into bytes
func parseMemoryString(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	var multiplier int64 = 1
	switch {
	case strings.HasSuffix(s, "G"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "M"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "K"):
		multiplier = 1024
		s = strings.TrimSuffix(s, "K")
	}

	var val int64
	_, _ = fmt.Sscanf(s, "%d", &val) //nolint:errcheck // parse errors result in zero value
	return val * multiplier
}
