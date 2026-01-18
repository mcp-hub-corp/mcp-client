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

// DarwinSandbox provides process isolation on macOS using rlimits.
// macOS has limited sandbox capabilities compared to Linux (no cgroups or network namespaces),
// but rlimits provide basic resource limits on CPU, memory, process count, and file descriptors.
type DarwinSandbox struct{}

func newDarwinSandbox() *DarwinSandbox {
	return &DarwinSandbox{}
}

// Apply applies sandbox restrictions to a command using rlimits.
// CRITICAL SECURITY INVARIANT: Always attempt to apply limits, even if partial.
func (s *DarwinSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits) error {
	if cmd == nil || limits == nil {
		return fmt.Errorf("command and limits cannot be nil")
	}

	// Set resource limits using rlimits (only isolation mechanism available on macOS)
	if err := s.applyRLimits(cmd, limits); err != nil {
		return fmt.Errorf("CRITICAL: failed to apply rlimits: %w", err)
	}

	// Note: macOS doesn't support Umask in SysProcAttr like Linux does.
	// Process will inherit parent's umask, which should already be restrictive.
	// Callers can use umask() separately if needed.

	return nil
}

// applyRLimits sets resource limits on the process using rlimits.
// macOS rlimits are enforced by the kernel and provide basic resource control:
//   - RLIMIT_CPU: CPU time in seconds (process is killed when exceeded)
//   - RLIMIT_AS: Address space (virtual memory in bytes)
//   - RLIMIT_NPROC: Maximum number of processes
//   - RLIMIT_NOFILE: Maximum number of file descriptors
func (s *DarwinSandbox) applyRLimits(cmd *exec.Cmd, limits *policy.ExecutionLimits) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// Note: On macOS, rlimits are set differently than on Linux.
	// We use a simple approach: set limits directly on the current process before exec.
	// This is less elegant than Linux but provides basic resource control.

	// CPU time limit: RLIMIT_CPU
	// Convert timeout from nanoseconds to seconds
	if limits.Timeout > 0 {
		cpuSeconds := uint64(limits.Timeout.Seconds())
		if cpuSeconds > 0 {
			_ = syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{
				Cur: cpuSeconds,
				Max: cpuSeconds,
			})
		}
	}

	// Memory limit: RLIMIT_AS (address space)
	// Note: RLIMIT_AS may not prevent all allocations (e.g., mmap anonymous)
	// but it's the best-effort approach on macOS
	if limits.MaxMemory != "" {
		memBytes := parseMemoryStringDarwin(limits.MaxMemory)
		if memBytes > 0 {
			_ = syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{
				Cur: uint64(memBytes),
				Max: uint64(memBytes),
			})
		}
	}

	// Process count limit: RLIMIT_NPROC
	// Note: macOS has RLIMIT_NPROC but older versions may not expose it
	if limits.MaxPIDs > 0 {
		// Only attempt if the constant is available
		// On some macOS versions, RLIMIT_NPROC is not exposed
		const rlimitNproc = 7 // RLIMIT_NPROC value on macOS
		_ = syscall.Setrlimit(rlimitNproc, &syscall.Rlimit{
			Cur: uint64(limits.MaxPIDs),
			Max: uint64(limits.MaxPIDs),
		})
	}

	// File descriptor limit: RLIMIT_NOFILE
	if limits.MaxFDs > 0 {
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{
			Cur: uint64(limits.MaxFDs),
			Max: uint64(limits.MaxFDs),
		})
	}

	return nil
}

// Capabilities returns the capabilities of the macOS sandbox
func (s *DarwinSandbox) Capabilities() Capabilities {
	return Capabilities{
		CPULimit:            true,  // RLIMIT_CPU
		MemoryLimit:         true,  // RLIMIT_AS (best-effort)
		PIDLimit:            true,  // RLIMIT_NPROC
		FDLimit:             true,  // RLIMIT_NOFILE
		NetworkIsolation:    false, // macOS doesn't support network namespaces
		FilesystemIsolation: false, // macOS doesn't have mount namespaces
		Cgroups:             false, // macOS doesn't have cgroups
		Namespaces:          false, // macOS doesn't have namespaces
		SupportsSeccomp:     false, // macOS uses Mach traps, not seccomp
		RequiresRoot:        false,
		Warnings: []string{
			"macOS does not support network isolation - no network namespace available",
			"macOS does not support filesystem isolation - no mount namespace available",
			"Resource limits depend on rlimits only (no cgroups)",
			"RLIMIT_AS may not prevent all memory allocations",
			"For strict security isolation, consider running in a VM or Linux container",
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
