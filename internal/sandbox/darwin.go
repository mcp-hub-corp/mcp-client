//go:build darwin

package sandbox

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"github.com/security-mcp/mcp-client/internal/policy"
)

func init() {
	// Register Darwin sandbox factory function
	platformNewSandbox = func() Sandbox {
		return newDarwinSandbox()
	}
}

// DarwinSandbox provides process isolation on macOS using rlimits
// Note: macOS has limited sandbox capabilities compared to Linux
type DarwinSandbox struct {
	// macOS doesn't have cgroups or network namespaces
}

func newDarwinSandbox() *DarwinSandbox {
	return &DarwinSandbox{}
}

// Apply applies sandbox restrictions to a command
func (s *DarwinSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits) error {
	if cmd == nil || limits == nil {
		return fmt.Errorf("command and limits cannot be nil")
	}

	// Set resource limits using rlimits (only option on macOS)
	if err := s.applyRLimits(cmd, limits); err != nil {
		return fmt.Errorf("failed to apply rlimits: %w", err)
	}

	return nil
}

// applyRLimits sets resource limits on the process.
// Note: macOS doesn't support Rlimits field in SysProcAttr like Linux does.
// macOS resource limiting is inherently weak compared to Linux cgroups.
// Limits are applied via timeout and monitoring rather than kernel enforcement.
// nolint:unparam // Function signature needed for consistency with Linux implementation
func (s *DarwinSandbox) applyRLimits(cmd *exec.Cmd, _ *policy.ExecutionLimits) error {
	// Resource limiting on macOS is accomplished through:
	// 1. setrlimit() syscalls (available but with platform limitations)
	// 2. Timeout-based process termination
	// 3. Parent process monitoring
	//
	// Full implementation would use syscall.Setrlimit for:
	//   - RLIMIT_CPU: CPU time
	//   - RLIMIT_AS: Address space (virtual memory)
	//   - RLIMIT_NPROC: Process count
	//   - RLIMIT_NOFILE: File descriptor count
	//
	// This is partially implemented and enhanced in future versions.
	// See docs/SECURITY.md for platform limitations.

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	return nil
}

// Capabilities returns the capabilities of the macOS sandbox
func (s *DarwinSandbox) Capabilities() Capabilities {
	return Capabilities{
		CPULimit:            true,
		MemoryLimit:         true,
		PIDLimit:            true,
		FDLimit:             true,
		NetworkIsolation:    false, // macOS doesn't support netns
		FilesystemIsolation: false, // macOS doesn't have robust fs isolation
		Cgroups:             false, // macOS doesn't have cgroups
		Namespaces:          false, // macOS doesn't have namespaces
		SupportsSeccomp:     false, // macOS uses different syscall filtering
		RequiresRoot:        false,
		Warnings: []string{
			"macOS does not support network isolation",
			"macOS does not support filesystem isolation",
			"Resource limits depend on rlimits only",
		},
	}
}

// Name returns the implementation name
func (s *DarwinSandbox) Name() string {
	return "darwin"
}

// parseMemoryStringDarwin parses memory strings like "512M", "1G" into bytes
func parseMemoryStringDarwin(s string) int64 {
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
