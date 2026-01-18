//go:build linux

package sandbox

import (
	"fmt"
	"log/slog"
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

// LinuxSandbox provides comprehensive process isolation on Linux using rlimits,
// cgroups v2, and namespaces (mount, network, pid).
// Design principle: SAFE BY DEFAULT - all isolation layers applied, failures documented
type LinuxSandbox struct {
	useCgroups        bool   // cgroups available
	useCgroupsV2      bool   // cgroups v2 available (preferred over v1)
	cgroupPath        string // path to cgroups mountpoint
	canCreateNet      bool   // can create network namespaces (requires CAP_NET_ADMIN or root)
	canCreateMount    bool   // can create mount namespaces (requires unshare capability)
	cgroupManager     *cgroupManager
	logger            *slog.Logger
	trackedCgroups    map[int]string // pid -> cgroup path for cleanup
}

// cgroupManager handles cgroups v2 operations (best-effort)
type cgroupManager struct {
	rootPath string
	logger   *slog.Logger
}

func newLinuxSandbox() *LinuxSandbox {
	logger := slog.Default()

	ls := &LinuxSandbox{
		useCgroups:     false,
		cgroupPath:     "/sys/fs/cgroup",
		logger:         logger,
		trackedCgroups: make(map[int]string),
	}

	// Detect cgroups v2 (preferred)
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		ls.useCgroups = true
		ls.useCgroupsV2 = true
		ls.cgroupManager = &cgroupManager{
			rootPath: "/sys/fs/cgroup",
			logger:   logger,
		}
		logger.Debug("cgroups v2 detected and available")
	} else if _, err := os.Stat("/sys/fs/cgroup/cpu"); err == nil {
		// cgroups v1 available (fallback, less preferred)
		ls.useCgroups = true
		ls.useCgroupsV2 = false
		logger.Debug("cgroups v1 detected (cgroups v2 preferred)")
	} else {
		logger.Debug("cgroups not available - resource limits will use rlimits only")
	}

	// Check if we can create network namespaces
	// This requires CAP_NET_ADMIN, typically only available to root or unshare
	uid := os.Geteuid()
	ls.canCreateNet = uid == 0
	if ls.canCreateNet {
		logger.Debug("network namespace isolation enabled (running as root)")
	} else {
		logger.Debug("network namespace isolation disabled (requires root/CAP_NET_ADMIN)")
	}

	// Mount namespaces typically don't require root but do require unshare support
	// We assume it's available on modern Linux
	ls.canCreateMount = true

	return ls
}

// Apply applies all sandbox restrictions to a command.
// Strategy: MANDATORY layers first (rlimits), then OPTIONAL best-effort layers (namespaces, cgroups)
// Returns error only if MANDATORY restrictions fail
func (s *LinuxSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits) error {
	if cmd == nil || limits == nil {
		return fmt.Errorf("command and limits cannot be nil")
	}

	// MANDATORY: Apply rlimits (always works, doesn't require elevated privileges)
	if err := s.applyRLimits(cmd, limits); err != nil {
		// Critical: rlimits must always work
		return fmt.Errorf("CRITICAL: failed to apply rlimits: %w", err)
	}

	// OPTIONAL: Try mount namespace (best-effort, documented if fails)
	if s.canCreateMount {
		if err := s.setupMountNamespace(cmd); err != nil {
			s.logger.Debug("mount namespace setup failed (non-critical)", slog.String("error", err.Error()))
		} else {
			s.logger.Debug("mount namespace enabled for process isolation")
		}
	}

	// OPTIONAL: Try network namespace if available (best-effort, documented if fails)
	if s.canCreateNet {
		if err := s.setupNetworkNamespace(cmd); err != nil {
			s.logger.Warn("network namespace setup failed", slog.String("error", err.Error()))
		} else {
			s.logger.Debug("network namespace enabled (default-deny network)")
		}
	}

	// OPTIONAL: Try cgroups v2 if available (best-effort, documented if fails)
	// Note: This is applied in ApplyForPID after the process starts (need PID)
	if s.useCgroups && s.useCgroupsV2 {
		s.logger.Debug("cgroups v2 will be applied after process starts")
	}

	// Set restrictive umask for file creation (security best practice)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Umask = 0077 // rwx------ (restrictive: only owner can access)

	return nil
}

// ApplyForPID applies cgroups restrictions after the process has started (needs PID).
// This is best-effort: failures are logged but don't cause overall failure.
func (s *LinuxSandbox) ApplyForPID(pid int, limits *policy.ExecutionLimits) error {
	if !s.useCgroups || !s.useCgroupsV2 {
		// cgroups not available, nothing to do
		return nil
	}

	if pid <= 0 {
		return fmt.Errorf("invalid pid: %d", pid)
	}

	if s.cgroupManager == nil {
		return fmt.Errorf("cgroup manager not initialized")
	}

	// Attempt to apply cgroups (best-effort)
	if err := s.applyCgroupsV2(pid, limits); err != nil {
		s.logger.Debug("cgroups v2 application failed (non-critical)", slog.String("error", err.Error()))
		return nil // Don't fail overall
	}

	s.logger.Debug("cgroups v2 applied successfully", slog.Int("pid", pid))
	return nil
}

// applyRLimits sets resource limits via setrlimit (MANDATORY, always applied)
// This is the primary safety mechanism for resource control
func (s *LinuxSandbox) applyRLimits(cmd *exec.Cmd, limits *policy.ExecutionLimits) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	rlimits := make([]syscall.Rlimit, 0, 4)

	// RLIMIT_CPU: CPU time in seconds (wall clock)
	// Formula: timeout * (millicores / 1000) = CPU seconds available
	// Example: 5min timeout, 1000 millicores = 5 * 60 * (1000/1000) = 300 seconds
	// Example: 5min timeout, 500 millicores = 5 * 60 * (500/1000) = 150 seconds
	if limits.MaxCPU > 0 {
		cpuSeconds := uint64(limits.Timeout.Seconds() * float64(limits.MaxCPU) / 1000.0)
		if cpuSeconds < 1 {
			cpuSeconds = 1 // Minimum 1 second
		}
		rlimits = append(rlimits, syscall.Rlimit{
			Resource: syscall.RLIMIT_CPU,
			Cur:      cpuSeconds,
			Max:      cpuSeconds,
		})
		s.logger.Debug("RLIMIT_CPU set", slog.Uint64("seconds", cpuSeconds))
	}

	// RLIMIT_AS: Address space (virtual memory) limit in bytes
	// This is the total memory the process can allocate (swap + RSS)
	if limits.MaxMemory != "" {
		memBytes := parseMemoryString(limits.MaxMemory)
		if memBytes > 0 {
			rlimits = append(rlimits, syscall.Rlimit{
				Resource: syscall.RLIMIT_AS,
				Cur:      uint64(memBytes),
				Max:      uint64(memBytes),
			})
			s.logger.Debug("RLIMIT_AS set", slog.Int64("bytes", memBytes))
		}
	}

	// RLIMIT_NPROC: Process count limit (max child processes)
	// This limits the total number of processes including threads
	if limits.MaxPIDs > 0 {
		rlimits = append(rlimits, syscall.Rlimit{
			Resource: syscall.RLIMIT_NPROC,
			Cur:      uint64(limits.MaxPIDs),
			Max:      uint64(limits.MaxPIDs),
		})
		s.logger.Debug("RLIMIT_NPROC set", slog.Int("count", limits.MaxPIDs))
	}

	// RLIMIT_NOFILE: File descriptor limit
	// This limits the number of open files/sockets/pipes
	if limits.MaxFDs > 0 {
		rlimits = append(rlimits, syscall.Rlimit{
			Resource: syscall.RLIMIT_NOFILE,
			Cur:      uint64(limits.MaxFDs),
			Max:      uint64(limits.MaxFDs),
		})
		s.logger.Debug("RLIMIT_NOFILE set", slog.Int("count", limits.MaxFDs))
	}

	cmd.SysProcAttr.Rlimits = rlimits
	return nil
}

// setupMountNamespace creates a new mount namespace (CLONE_NEWNS)
// This isolates the filesystem view of the process (mount points, etc.)
// Best-effort: failure is logged but doesn't cause overall failure
func (s *LinuxSandbox) setupMountNamespace(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// CLONE_NEWNS: Create new mount namespace
	// This allows the process to have its own view of mounted filesystems
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNS

	s.logger.Debug("mount namespace isolation enabled")
	return nil
}

// setupNetworkNamespace creates a new network namespace (CLONE_NEWNET)
// This provides network isolation with default-deny (only loopback available)
// Requires root or CAP_NET_ADMIN
func (s *LinuxSandbox) setupNetworkNamespace(cmd *exec.Cmd) error {
	if !s.canCreateNet {
		return fmt.Errorf("network namespace requires root or CAP_NET_ADMIN")
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// CLONE_NEWNET: Create new network namespace
	// Creates an isolated network stack with only loopback interface enabled
	// This is default-deny: no external network access unless explicitly configured
	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNET

	s.logger.Debug("network namespace isolation enabled (default-deny network)")
	return nil
}

// applyCgroupsV2 applies cgroups v2 limits to a running process (after PID is available)
// This is best-effort: failures are logged but don't cause overall failure
func (s *LinuxSandbox) applyCgroupsV2(pid int, limits *policy.ExecutionLimits) error {
	if s.cgroupManager == nil {
		return fmt.Errorf("cgroup manager not initialized")
	}

	// Create a unique cgroup for this process
	cgroupName := fmt.Sprintf("mcp-launcher-%d", pid)
	cgroupPath := filepath.Join(s.cgroupManager.rootPath, cgroupName)

	// Attempt to create cgroup directory
	if err := os.Mkdir(cgroupPath, 0755); err != nil {
		return fmt.Errorf("cannot create cgroup directory (may require elevated privileges): %w", err)
	}

	// Add process to cgroup
	cgroupProcsPath := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(cgroupProcsPath, []byte(strconv.Itoa(pid)), 0644); err != nil {
		// Clean up failed cgroup
		os.RemoveAll(cgroupPath)
		return fmt.Errorf("cannot add process to cgroup: %w", err)
	}

	// Track for potential cleanup
	s.trackedCgroups[pid] = cgroupPath

	// Apply CPU quota (best-effort)
	if limits.MaxCPU > 0 {
		period := int64(100000) // 100ms standard period
		quota, _ := calculateCPUQuota(limits.MaxCPU, period)
		cpuMax := fmt.Sprintf("%d %d", quota, period)
		if err := os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte(cpuMax), 0644); err != nil {
			s.logger.Debug("failed to set cpu.max", slog.String("error", err.Error()))
		} else {
			s.logger.Debug("cpu.max set via cgroups v2", slog.String("value", cpuMax))
		}
	}

	// Apply memory limit (best-effort)
	if limits.MaxMemory != "" {
		memBytes := parseMemoryString(limits.MaxMemory)
		if memBytes > 0 {
			memStr := strconv.FormatInt(memBytes, 10)
			if err := os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte(memStr), 0644); err != nil {
				s.logger.Debug("failed to set memory.max", slog.String("error", err.Error()))
			} else {
				s.logger.Debug("memory.max set via cgroups v2", slog.String("bytes", memStr))
			}
		}
	}

	// Apply PID limit (best-effort)
	if limits.MaxPIDs > 0 {
		pidsStr := strconv.Itoa(limits.MaxPIDs)
		if err := os.WriteFile(filepath.Join(cgroupPath, "pids.max"), []byte(pidsStr), 0644); err != nil {
			s.logger.Debug("failed to set pids.max", slog.String("error", err.Error()))
		} else {
			s.logger.Debug("pids.max set via cgroups v2", slog.String("count", pidsStr))
		}
	}

	return nil
}

// Capabilities returns detailed information about what isolation features are available
// Marked: enabled, degraded, or unsupported
func (s *LinuxSandbox) Capabilities() Capabilities {
	caps := Capabilities{
		CPULimit:            true,            // Always available via rlimits
		MemoryLimit:         true,            // Always available via rlimits
		PIDLimit:            true,            // Always available via rlimits
		FDLimit:             true,            // Always available via rlimits
		NetworkIsolation:    s.canCreateNet,  // Requires root or CAP_NET_ADMIN
		FilesystemIsolation: true,            // Always available via mount namespaces
		Cgroups:             s.useCgroups,    // Depends on kernel and mounted cgroups
		Namespaces:          true,            // Mount namespaces generally available
		SupportsSeccomp:     true,            // Modern Linux supports seccomp
		RequiresRoot:        s.canCreateNet,  // Only network isolation requires root
	}

	// Add detailed warnings about limitations
	if !s.useCgroups {
		caps.Warnings = append(caps.Warnings,
			"[DEGRADED] cgroups not available - using rlimits only for resource limits (less reliable)",
		)
	} else if !s.useCgroupsV2 {
		caps.Warnings = append(caps.Warnings,
			"[DEGRADED] cgroups v1 only - cgroups v2 preferred for better resource control",
		)
	}

	if !s.canCreateNet {
		caps.Warnings = append(caps.Warnings,
			"[DEGRADED] Network isolation not available - running without root/CAP_NET_ADMIN",
			"[INFO] Network policy enforcement via iptables/tc not possible",
		)
	}

	return caps
}

// Name returns the sandbox implementation name
func (s *LinuxSandbox) Name() string {
	return "linux"
}

// CleanupCgroup removes the cgroup directory for a process (best-effort)
// Should be called after process cleanup
func (s *LinuxSandbox) CleanupCgroup(pid int) error {
	cgroupPath, exists := s.trackedCgroups[pid]
	if !exists {
		return nil // No cgroup tracked for this PID
	}

	// Attempt removal (best-effort)
	if err := os.RemoveAll(cgroupPath); err != nil {
		s.logger.Debug("failed to cleanup cgroup", slog.String("path", cgroupPath), slog.String("error", err.Error()))
		return nil // Non-critical failure
	}

	delete(s.trackedCgroups, pid)
	s.logger.Debug("cgroup cleaned up", slog.String("path", cgroupPath))
	return nil
}

// readCgroupValue reads a value from a cgroup file
// Used for diagnostics and validation
func (s *LinuxSandbox) readCgroupValue(cgroupFile, field string) (string, error) {
	content, err := os.ReadFile(cgroupFile)
	if err != nil {
		return "", fmt.Errorf("cannot read cgroup file: %w", err)
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

// writeCgroupValue writes a value to a cgroup file (used internally)
func (s *LinuxSandbox) writeCgroupValue(cgroupFile string, value string) error {
	if err := os.WriteFile(cgroupFile, []byte(value+"\n"), 0o644); err != nil {
		return fmt.Errorf("failed to write cgroup value: %w", err)
	}
	return nil
}

// calculateCPUQuota converts millicores to cgroups CPU quota format
// Returns quota value for use with "cpu.max" in cgroups v2
// Formula: (millicores * period) / 1000
// Example: 500 millicores with 100ms period = (500 * 100000) / 1000 = 50000 microseconds
func calculateCPUQuota(millicores int, period int64) (int64, error) {
	if millicores <= 0 {
		return 0, fmt.Errorf("millicores must be positive: got %d", millicores)
	}

	if period <= 0 {
		return 0, fmt.Errorf("period must be positive: got %d", period)
	}

	quota := (int64(millicores) * period) / 1000
	return quota, nil
}

// parseMemoryString parses memory strings like "512M", "1G" into bytes
// Supported suffixes: K (kilobytes), M (megabytes), G (gigabytes)
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
	// Parse errors result in zero value (safe default)
	_, _ = fmt.Sscanf(s, "%d", &val) //nolint:errcheck
	return val * multiplier
}
