package sandbox

import "time"

// Sandbox defines the interface for process isolation and resource limiting
type Sandbox interface {
	// Apply applies sandbox restrictions to a process
	Apply(pid int) error

	// SetLimits configures resource limits
	SetLimits(limits ResourceLimits) error

	// Cleanup removes sandbox resources
	Cleanup() error
}

// ResourceLimits defines resource constraints for MCP processes
type ResourceLimits struct {
	MaxCPU    int           // millicores (1000 = 1 core)
	MaxMemory string        // e.g., "512M"
	MaxPIDs   int           // max number of processes
	MaxFDs    int           // max number of file descriptors
	Timeout   time.Duration // execution timeout
}

// NewSandbox creates a platform-specific sandbox
// TODO: Implement platform-specific versions in phases 5-7
func NewSandbox() (Sandbox, error) {
	return nil, nil
}
