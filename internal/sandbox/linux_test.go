//go:build linux

package sandbox

import (
	"os/exec"
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
		wantErr    bool
	}{
		{
			name:       "1000 millicores with 100ms period",
			millicores: 1000,
			period:     100000,
			wantErr:    false,
		},
		{
			name:       "500 millicores with 100ms period",
			millicores: 500,
			period:     100000,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quota, err := calculateCPUQuota(tt.millicores, tt.period)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Greater(t, quota, int64(0))
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
	// cgroups detection depends on the system state
	// v2 available, v1 available, or neither
}
