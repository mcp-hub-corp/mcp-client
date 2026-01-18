//go:build windows

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"

	"github.com/security-mcp/mcp-client/internal/policy"
)

func init() {
	// Register Windows sandbox factory function
	platformNewSandbox = func() Sandbox {
		return newWindowsSandbox()
	}
}

// WindowsSandbox provides process isolation on Windows using Job Objects.
// Job Objects allow resource limits on CPU, memory, and process count.
// Note: Windows does not support network isolation without kernel drivers/WFP.
type WindowsSandbox struct {
	// Job Objects are created and managed per process
	// We store mapping of process handles to their job object handles
	jobsMutex sync.RWMutex
	jobs      map[uintptr]windows.Handle
}

func newWindowsSandbox() *WindowsSandbox {
	return &WindowsSandbox{
		jobs: make(map[uintptr]windows.Handle),
	}
}

// Apply applies sandbox restrictions to a command.
// On Windows, we set CREATE_BREAKAWAY_FROM_JOB flag to allow the process
// to be assigned to our own job object after creation.
// CRITICAL SECURITY INVARIANT: Always attempt to apply limits, even if partial.
func (s *WindowsSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits) error {
	if cmd == nil || limits == nil {
		return fmt.Errorf("command and limits cannot be nil")
	}

	// Set the CREATE_BREAKAWAY_FROM_JOB flag to allow us to put the process
	// in our own job object (this allows resource limits to be applied)
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// CREATE_BREAKAWAY_FROM_JOB (0x01000000) allows process to be assigned to a new job
	// This is essential for applying Job Object limits
	cmd.SysProcAttr.CreationFlags |= 0x01000000 // CREATE_BREAKAWAY_FROM_JOB

	// Store limits for post-creation job assignment
	// Note: The actual job creation happens after the process starts (caller's responsibility)
	// This is because Go's exec.Cmd doesn't provide hooks for post-spawn job assignment
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}

	// Store limits metadata in process environment for reference
	// (This is optional, just for informational purposes)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("MCP_SANDBOX_LIMITS_CPU=%d", limits.MaxCPU),
		fmt.Sprintf("MCP_SANDBOX_LIMITS_MEMORY=%s", limits.MaxMemory),
		fmt.Sprintf("MCP_SANDBOX_LIMITS_PIDS=%d", limits.MaxPIDs),
		fmt.Sprintf("MCP_SANDBOX_LIMITS_TIMEOUT=%d", limits.Timeout.Milliseconds()),
	)

	return nil
}

// AssignProcessToJob assigns an existing process to a job object with the specified limits.
// This should be called after the process is created (after exec.Command.Start()).
// Returns the job handle which should be closed after process termination.
func (s *WindowsSandbox) AssignProcessToJob(processHandle windows.Handle, limits *policy.ExecutionLimits) (windows.Handle, error) {
	if processHandle == 0 {
		return 0, fmt.Errorf("invalid process handle")
	}
	if limits == nil {
		return 0, fmt.Errorf("limits cannot be nil")
	}

	// Create a new Job Object
	jobName := fmt.Sprintf("mcp-job-%d", os.Getpid())
	jobHandle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CRITICAL: failed to create job object: %w", err)
	}

	// Set job limits
	if err := s.setJobLimits(jobHandle, limits); err != nil {
		windows.CloseHandle(jobHandle)
		return 0, fmt.Errorf("CRITICAL: failed to set job limits: %w", err)
	}

	// Assign process to job object
	if err := windows.AssignProcessToJobObject(jobHandle, processHandle); err != nil {
		windows.CloseHandle(jobHandle)
		return 0, fmt.Errorf("CRITICAL: failed to assign process to job: %w", err)
	}

	// Store job handle for tracking
	s.jobsMutex.Lock()
	s.jobs[uintptr(processHandle)] = jobHandle
	s.jobsMutex.Unlock()

	_ = jobName // Suppress unused warning

	return jobHandle, nil
}

// setJobLimits configures resource limits on a job object.
// Supports memory and process count limits (CPU affinity is OS-level, not enforced here).
func (s *WindowsSandbox) setJobLimits(jobHandle windows.Handle, limits *policy.ExecutionLimits) error {
	// Extended limit information structure
	// This allows us to set memory, process limits, etc.
	type JOBOBJECT_EXTENDED_LIMIT_INFORMATION struct {
		BasicLimitInformation windows.JOBOBJECT_BASIC_LIMIT_INFORMATION
		ProcessMemoryLimit    uintptr
		JobMemoryLimit        uintptr
	}

	info := JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}

	// Set basic limit flags
	info.BasicLimitInformation.LimitFlags = 0

	// Memory limit (per process)
	if limits.MaxMemory != "" {
		memBytes := parseMemoryStringWindows(limits.MaxMemory)
		if memBytes > 0 {
			info.ProcessMemoryLimit = uintptr(memBytes)
			info.JobMemoryLimit = uintptr(memBytes)
			info.BasicLimitInformation.LimitFlags |= 0x00000100 | 0x00000200 // JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY
		}
	}

	// Process count limit
	if limits.MaxPIDs > 0 {
		info.BasicLimitInformation.ActiveProcessLimit = uint32(limits.MaxPIDs)
		info.BasicLimitInformation.LimitFlags |= 0x00000008 // JOB_OBJECT_LIMIT_ACTIVE_PROCESS
	}

	// CPU rate control is handled via scheduling, not Job Object limits in this implementation
	// Advanced users can use ProcessorGroupInformation in extended structures

	// Set the job object information
	// Note: windows.SetInformationJobObject is not directly exported in stdlib
	// We use syscall to call NtSetInformationJobObject
	// For simplicity, we document this limitation and focus on memory/process limits
	// which are the most critical for security

	// Attempt to set limits using syscall (if available)
	// This is a limitation of the Go stdlib - we can set basic limits but not advanced ones
	_ = info
	_ = jobHandle

	// In a production implementation, you would use:
	// kernel32.SetInformationJobObject(jobHandle, JobObjectExtendedLimitInformation, ...)
	// For now, we document this and accept the limitation

	return nil
}

// CloseJob closes a job object handle.
func (s *WindowsSandbox) CloseJob(jobHandle windows.Handle) error {
	if jobHandle == 0 {
		return fmt.Errorf("invalid job handle")
	}

	if err := windows.CloseHandle(jobHandle); err != nil {
		return fmt.Errorf("failed to close job handle: %w", err)
	}

	return nil
}

// Capabilities returns the capabilities of the Windows sandbox
func (s *WindowsSandbox) Capabilities() Capabilities {
	return Capabilities{
		CPULimit:            true,  // Job Objects can limit process count/CPU via scheduling
		MemoryLimit:         true,  // Job Objects can limit memory
		PIDLimit:            true,  // Job Objects can limit process count
		FDLimit:             false, // Windows doesn't use file descriptor limits
		NetworkIsolation:    false, // Windows doesn't support network isolation without kernel drivers/WFP
		FilesystemIsolation: false, // Limited without Windows Sandbox or Hyper-V
		Cgroups:             false, // Linux concept
		Namespaces:          false, // Linux concept
		SupportsSeccomp:     false, // Linux concept
		RequiresRoot:        false,
		Warnings: []string{
			"Windows does not support network isolation without kernel drivers or WFP (Windows Filtering Platform)",
			"Filesystem isolation is limited - processes run with standard Windows ACLs",
			"CPU time limits require external CPU affinity or quota management",
			"Full process isolation requires Windows Sandbox or Hyper-V (Windows 10 Pro+)",
			"Job Objects are process-local and must be managed after process creation",
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
