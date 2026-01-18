//go:build darwin

package sandbox

import (
	"os/exec"
	"testing"
	"time"

	"github.com/security-mcp/mcp-client/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDarwinSandboxNew(t *testing.T) {
	sandbox := newDarwinSandbox()
	require.NotNil(t, sandbox)
	assert.Equal(t, "darwin", sandbox.Name())
}

func TestDarwinSandboxCapabilities(t *testing.T) {
	sandbox := newDarwinSandbox()
	caps := sandbox.Capabilities()

	// macOS supports basic resource limits via rlimits
	assert.True(t, caps.CPULimit)
	assert.True(t, caps.MemoryLimit)
	assert.True(t, caps.PIDLimit)

	// But not these advanced features
	assert.False(t, caps.NetworkIsolation)
	assert.False(t, caps.Cgroups)
	assert.False(t, caps.Namespaces)
	assert.False(t, caps.FilesystemIsolation)

	// Should have warnings
	assert.NotEmpty(t, caps.Warnings)
}

func TestDarwinSandboxApplyRLimits(t *testing.T) {
	sandbox := newDarwinSandbox()
	cmd := exec.Command("true")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    1024,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits)
	assert.NoError(t, err)

	// On macOS, SysProcAttr will be set but Rlimits not directly accessible
	// (different from Linux implementation)
}

func TestDarwinSandboxApplyPartialLimits(t *testing.T) {
	sandbox := newDarwinSandbox()
	cmd := exec.Command("true")

	limits := &policy.ExecutionLimits{
		MaxCPU:    0, // No CPU limit
		MaxMemory: "256M",
		MaxPIDs:   0,
		MaxFDs:    0,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits)
	assert.NoError(t, err)
	assert.NotNil(t, cmd.SysProcAttr)
}

func TestDarwinParseMemoryString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{"512M", "512M", 512 * 1024 * 1024},
		{"1G", "1G", 1024 * 1024 * 1024},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMemoryStringDarwin(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDarwinSandboxNilInputs(t *testing.T) {
	sandbox := newDarwinSandbox()

	// Nil command
	err := sandbox.Apply(nil, &policy.ExecutionLimits{})
	assert.Error(t, err)

	// Nil limits
	err = sandbox.Apply(exec.Command("true"), nil)
	assert.Error(t, err)
}
