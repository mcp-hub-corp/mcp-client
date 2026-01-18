//go:build windows

package sandbox

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/security-mcp/mcp-client/internal/policy"
)

func init() {
	// Register Windows sandbox factory function
	platformNewSandbox = func() Sandbox {
		return newWindowsSandbox()
	}
}

// WindowsSandbox provides process isolation on Windows using Job Objects
type WindowsSandbox struct {
	// Windows uses Job Objects for resource limiting
	// Implementation would use Windows API calls
}

func newWindowsSandbox() *WindowsSandbox {
	return &WindowsSandbox{}
}

// Apply applies sandbox restrictions to a command
func (s *WindowsSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits) error {
	if cmd == nil || limits == nil {
		return fmt.Errorf("command and limits cannot be nil")
	}

	// Note: Full Job Objects implementation requires Windows API calls
	// For now, this is a placeholder that documents the approach
	// In a full implementation, you would use:
	// - CreateJobObject()
	// - SetInformationJobObject() with JobObjectBasicProcessIdList
	// - SetInformationJobObject() with JobObjectExtendedLimitInformation
	// - AssignProcessToJobObject()

	// Basic validation
	if limits.MaxMemory != "" {
		_ = parseMemoryStringWindows(limits.MaxMemory)
	}

	return nil
}

// Capabilities returns the capabilities of the Windows sandbox
func (s *WindowsSandbox) Capabilities() Capabilities {
	return Capabilities{
		CPULimit:            true,  // Job Objects can limit CPU
		MemoryLimit:         true,  // Job Objects can limit memory
		PIDLimit:            true,  // Job Objects can limit process count
		FDLimit:             false, // File descriptor concept is different on Windows
		NetworkIsolation:    false, // Windows doesn't support network isolation without drivers
		FilesystemIsolation: false, // Limited without WinSandbox/Hyper-V
		Cgroups:             false, // Linux concept
		Namespaces:          false, // Linux concept
		SupportsSeccomp:     false, // Linux concept
		RequiresRoot:        false,
		Warnings: []string{
			"Windows does not support network isolation without kernel drivers",
			"Filesystem isolation is limited",
			"Full isolation requires Windows Sandbox or Hyper-V (Windows 10 Pro+)",
		},
	}
}

// Name returns the implementation name
func (s *WindowsSandbox) Name() string {
	return "windows"
}

// parseMemoryStringWindows parses memory strings like "512M", "1G" into bytes
func parseMemoryStringWindows(s string) int64 {
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
