//go:build linux

package sandbox

import (
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/security-mcp/mcp-client/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxSandboxNew(t *testing.T) {
	sandbox := newLinuxSandbox()
	require.NotNil(t, sandbox)
	assert.Equal(t, "linux", sandbox.Name())
}

func TestLinuxSandboxCapabilities(t *testing.T) {
	sandbox := newLinuxSandbox()
	caps := sandbox.Capabilities()

	// Linux should have these capabilities
	assert.True(t, caps.CPULimit)
	assert.True(t, caps.MemoryLimit)
	assert.True(t, caps.PIDLimit)
	assert.True(t, caps.FDLimit)
	assert.True(t, caps.FilesystemIsolation)
	assert.True(t, caps.SupportsSeccomp)
	assert.True(t, caps.Namespaces)

	// cgroups detection might vary based on environment
	// Just verify the field exists
	assert.NotNil(t, caps)
}

func TestLinuxSandboxApplyRLimits(t *testing.T) {
	sandbox := newLinuxSandbox()
	cmd := exec.Command("true")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000, // 1 core
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    1024,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits)
	assert.NoError(t, err)

	// Verify SysProcAttr was set
	assert.NotNil(t, cmd.SysProcAttr)
	assert.NotEmpty(t, cmd.SysProcAttr.Rlimits)

	// Verify umask was set
	assert.Equal(t, 0077, cmd.SysProcAttr.Umask)

	// Verify correct number of rlimits (all 4 should be set)
	assert.Equal(t, 4, len(cmd.SysProcAttr.Rlimits))
}

func TestLinuxSandboxApplyMemory(t *testing.T) {
	sandbox := newLinuxSandbox()
	cmd := exec.Command("true")

	limits := &policy.ExecutionLimits{
		MaxCPU:    0, // No CPU limit
		MaxMemory: "256M",
		MaxPIDs:   0, // No PID limit
		MaxFDs:    0, // No FD limit
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits)
	assert.NoError(t, err)
	assert.NotNil(t, cmd.SysProcAttr)
	// Only memory rlimit should be set (CPU=0, PIDs=0, FDs=0)
	assert.Equal(t, 1, len(cmd.SysProcAttr.Rlimits))
}

func TestLinuxSandboxApplyZeroLimits(t *testing.T) {
	sandbox := newLinuxSandbox()
	cmd := exec.Command("true")

	limits := &policy.ExecutionLimits{
		MaxCPU:    0,
		MaxMemory: "",
		MaxPIDs:   0,
		MaxFDs:    0,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits)
	assert.NoError(t, err)
	// Should still set SysProcAttr for umask
	assert.NotNil(t, cmd.SysProcAttr)
	// No rlimits should be set when all are zero
	assert.Empty(t, cmd.SysProcAttr.Rlimits)
}

func TestLinuxSandboxMountNamespace(t *testing.T) {
	sandbox := newLinuxSandbox()
	cmd := exec.Command("true")

	limits := &policy.ExecutionLimits{
		MaxCPU:    100,
		MaxMemory: "128M",
		MaxPIDs:   5,
		MaxFDs:    512,
		Timeout:   2 * time.Second,
	}

	err := sandbox.Apply(cmd, limits)
	assert.NoError(t, err)

	// Verify mount namespace flag is set
	if cmd.SysProcAttr != nil {
		// Mount namespace should be set (CLONE_NEWNS = 0x00020000)
		assert.True(t, (cmd.SysProcAttr.Cloneflags & syscall.CLONE_NEWNS) != 0)
	}
}

func TestLinuxSandboxNetworkIsolation(t *testing.T) {
	sandbox := newLinuxSandbox()

	// Only test network namespace if we can create it
	if !sandbox.canCreateNet {
		t.Skip("Network namespaces not available (requires root)")
	}

	cmd := exec.Command("true")
	limits := &policy.ExecutionLimits{
		MaxCPU:    100,
		MaxMemory: "128M",
		MaxPIDs:   5,
		MaxFDs:    512,
		Timeout:   2 * time.Second,
	}

	err := sandbox.Apply(cmd, limits)
	assert.NoError(t, err)

	// Verify network namespace flag is set
	if cmd.SysProcAttr != nil {
		// Network namespace should be set (CLONE_NEWNET = 0x40000000)
		assert.True(t, (cmd.SysProcAttr.Cloneflags & syscall.CLONE_NEWNET) != 0)
	}
}

func TestLinuxParseMemoryString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{"512M", "512M", 512 * 1024 * 1024},
		{"1G", "1G", 1024 * 1024 * 1024},
		{"256K", "256K", 256 * 1024},
		{"2G", "2G", 2 * 1024 * 1024 * 1024},
		{"empty", "", 0},
		{"with space", " 512M ", 512 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMemoryString(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLinuxCalculateCPUQuota(t *testing.T) {
	tests := []struct {
		name       string
		millicores int
		period     int64
		wantQuota  int64
		wantErr    bool
	}{
		{
			name:       "1000 millicores with 100ms period",
			millicores: 1000,
			period:     100000,
			wantQuota:  100000,
			wantErr:    false,
		},
		{
			name:       "500 millicores with 100ms period",
			millicores: 500,
			period:     100000,
			wantQuota:  50000,
			wantErr:    false,
		},
		{
			name:       "invalid negative",
			millicores: -1,
			period:     100000,
			wantErr:    true,
		},
		{
			name:       "zero millicores",
			millicores: 0,
			period:     100000,
			wantErr:    true,
		},
		{
			name:       "negative period",
			millicores: 100,
			period:     -1,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quota, err := calculateCPUQuota(tt.millicores, tt.period)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantQuota, quota)
			}
		})
	}
}

func TestLinuxSandboxNilInputs(t *testing.T) {
	sandbox := newLinuxSandbox()

	// Nil command
	err := sandbox.Apply(nil, &policy.ExecutionLimits{})
	assert.Error(t, err)

	// Nil limits
	err = sandbox.Apply(exec.Command("true"), nil)
	assert.Error(t, err)
}

func TestLinuxCgroupsDetection(t *testing.T) {
	sandbox := newLinuxSandbox()

	// Just verify the fields are set (may vary based on system)
	assert.NotNil(t, sandbox)
	assert.NotNil(t, sandbox.trackedCgroups)
	// cgroups detection depends on the system state
	// v2 available, v1 available, or neither
}

func TestLinuxRLimitCPUCalculation(t *testing.T) {
	tests := []struct {
		name        string
		timeout     time.Duration
		millicores  int
		minSeconds  uint64
		maxSeconds  uint64
	}{
		{
			name:       "5s timeout, 1000 millicores = 5 CPU seconds",
			timeout:    5 * time.Second,
			millicores: 1000,
			minSeconds: 5,
			maxSeconds: 5,
		},
		{
			name:       "5s timeout, 500 millicores = 2.5 CPU seconds (min 1)",
			timeout:    5 * time.Second,
			millicores: 500,
			minSeconds: 2,
			maxSeconds: 3,
		},
		{
			name:       "10s timeout, 100 millicores = 1 CPU second (min 1)",
			timeout:    10 * time.Second,
			millicores: 100,
			minSeconds: 1,
			maxSeconds: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sandbox := newLinuxSandbox()
			cmd := exec.Command("true")
			limits := &policy.ExecutionLimits{
				MaxCPU:    tt.millicores,
				MaxMemory: "",
				MaxPIDs:   0,
				MaxFDs:    0,
				Timeout:   tt.timeout,
			}

			err := sandbox.Apply(cmd, limits)
			assert.NoError(t, err)
			assert.NotNil(t, cmd.SysProcAttr)

			// Find the CPU limit in rlimits
			found := false
			for _, rl := range cmd.SysProcAttr.Rlimits {
				if rl.Resource == syscall.RLIMIT_CPU {
					found = true
					assert.GreaterOrEqual(t, rl.Cur, tt.minSeconds)
					assert.LessOrEqual(t, rl.Cur, tt.maxSeconds+1)
					break
				}
			}
			assert.True(t, found, "RLIMIT_CPU should be set")
		})
	}
}

func TestLinuxApplyForPID(t *testing.T) {
	sandbox := newLinuxSandbox()

	limits := &policy.ExecutionLimits{
		MaxCPU:    500,
		MaxMemory: "256M",
		MaxPIDs:   10,
		MaxFDs:    512,
		Timeout:   5 * time.Second,
	}

	// Test with invalid PID (non-existent)
	// ApplyForPID should return early if cgroups not available
	err := sandbox.ApplyForPID(1, limits)
	// Should either succeed (no-op if no cgroups) or fail gracefully
	if sandbox.useCgroups && sandbox.useCgroupsV2 {
		// If cgroups available, it might fail due to permission or invalid PID
		// Just verify it handles gracefully
		t.Logf("ApplyForPID error: %v", err)
	} else {
		// If no cgroups, should return nil
		assert.NoError(t, err)
	}
}

func TestLinuxCleanupCgroup(t *testing.T) {
	sandbox := newLinuxSandbox()

	// Test cleanup for non-existent PID (should be no-op)
	err := sandbox.CleanupCgroup(999999)
	assert.NoError(t, err)

	// Verify no errors on cleanup of untracked PID
	assert.Empty(t, sandbox.trackedCgroups)
}
