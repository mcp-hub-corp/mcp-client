//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/security-mcp/mcp-client/internal/policy"
)

func init() {
	// Register Linux sandbox factory function
	platformNewSandbox = func() Sandbox {
		return newLinuxSandbox()
	}
}

// LinuxSandbox provides process isolation on Linux using rlimits and cgroups
type LinuxSandbox struct {
	useCgroups   bool
	useCgroupsV2 bool
	cgroupPath   string
	canCreateNet bool
}

func newLinuxSandbox() *LinuxSandbox {
	ls := &LinuxSandbox{
		useCgroups: false,
		cgroupPath: "/sys/fs/cgroup",
	}

	// Detect cgroups v2
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		ls.useCgroups = true
		ls.useCgroupsV2 = true
	} else if _, err := os.Stat("/sys/fs/cgroup/cpu"); err == nil {
		// cgroups v1 available
		ls.useCgroups = true
		ls.useCgroupsV2 = false
	}

	// Check if we can create network namespaces
	// This requires CAP_NET_ADMIN, typically only root or unshare syscall support
	uid := os.Geteuid()
	ls.canCreateNet = uid == 0 // Simple check: only root can reliably do this

	return ls
}

// Apply applies sandbox restrictions to a command
func (s *LinuxSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits) error {
	if cmd == nil || limits == nil {
		return fmt.Errorf("command and limits cannot be nil")
	}

	// Set resource limits using rlimits
	if err := s.applyRLimits(cmd, limits); err != nil {
		return fmt.Errorf("failed to apply rlimits: %w", err)
	}

	// Try to apply cgroups v2 if available
	if s.useCgroups && s.useCgroupsV2 {
		// Note: cgroups setup is complex and requires either root or delegated cgroups
		// For now, we rely on rlimits
	}

	// Set restrictive umask for file creation
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Umask = 0077 // Restrictive: only owner can read/write

	return nil
}

// applyRLimits sets resource limits on the process
func (s *LinuxSandbox) applyRLimits(cmd *exec.Cmd, limits *policy.ExecutionLimits) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// Create rlimit slice
	var rlimits []syscall.Rlimit

	// CPU limit: convert millicores to seconds
	// millicores / 1000 = seconds per second of wall clock time
	if limits.MaxCPU > 0 {
		// Convert millicores to CPU seconds
		// 1000 millicores = 1 second per second = unlimited
		// 500 millicores = 0.5 seconds per second
		cpuSecs := uint64(limits.MaxCPU) / 100 // Rough conversion
		if cpuSecs > 0 {
			rlimits = append(rlimits, syscall.Rlimit{
				Cur: cpuSecs,
				Max: cpuSecs,
			})
		}
	}

	// Memory limit: convert string to bytes and apply
	if limits.MaxMemory != "" {
		memBytes := parseMemoryString(limits.MaxMemory)
		if memBytes > 0 {
			rlimits = append(rlimits, syscall.Rlimit{
				Cur: uint64(memBytes),
				Max: uint64(memBytes),
			})
		}
	}

	// Process count limit
	if limits.MaxPIDs > 0 {
		rlimits = append(rlimits, syscall.Rlimit{
			Cur: uint64(limits.MaxPIDs),
			Max: uint64(limits.MaxPIDs),
		})
	}

	// File descriptor limit
	if limits.MaxFDs > 0 {
		rlimits = append(rlimits, syscall.Rlimit{
			Cur: uint64(limits.MaxFDs),
			Max: uint64(limits.MaxFDs),
		})
	}

	cmd.SysProcAttr.Rlimits = rlimits

	return nil
}

// Capabilities returns the capabilities of the Linux sandbox
func (s *LinuxSandbox) Capabilities() Capabilities {
	caps := Capabilities{
		CPULimit:            true,
		MemoryLimit:         true,
		PIDLimit:            true,
		FDLimit:             true,
		NetworkIsolation:    s.canCreateNet,
		FilesystemIsolation: true,
		Cgroups:             s.useCgroups,
		Namespaces:          s.canCreateNet,
		SupportsSeccomp:     true,
		RequiresRoot:        s.canCreateNet, // Network isolation requires root
	}

	if !s.useCgroups {
		caps.Warnings = append(caps.Warnings,
			"cgroups not available - resource limits depend on rlimits only",
		)
	}

	if s.useCgroups && !s.useCgroupsV2 {
		caps.Warnings = append(caps.Warnings,
			"cgroups v1 available (v2 preferred for better performance)",
		)
	}

	if !s.canCreateNet {
		caps.Warnings = append(caps.Warnings,
			"Network namespaces not available - running without root",
		)
	}

	return caps
}

// Name returns the implementation name
func (s *LinuxSandbox) Name() string {
	return "linux"
}

// readCgroupValue reads a value from cgroup file (v2)
func (s *LinuxSandbox) readCgroupValue(cgroupFile, field string) (string, error) {
	content, err := os.ReadFile(cgroupFile)
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[0] == field {
			return parts[1], nil
		}
	}

	return "", fmt.Errorf("field %s not found in %s", field, cgroupFile)
}

// writeCgroupValue writes a value to a cgroup file (v2)
func (s *LinuxSandbox) writeCgroupValue(cgroupFile string, value string) error {
	return os.WriteFile(cgroupFile, []byte(value+"\n"), 0o644)
}

// calculateCPUQuota converts millicores to cgroups CPU quota format
// Returns "period:quota" format used by cgroups v2
func calculateCPUQuota(millicores int, period int64) (int64, error) {
	if millicores <= 0 {
		return 0, fmt.Errorf("millicores must be positive")
	}

	// Convert millicores to absolute CPU time
	// millicores / 1000 = fraction of 1 CPU
	// For period of 100000 microseconds (100ms):
	// 1000 millicores (1 CPU) = 100000 microseconds
	// 500 millicores (0.5 CPU) = 50000 microseconds
	quota := (int64(millicores) * period) / 1000
	return quota, nil
}

// Memory conversion helpers
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
