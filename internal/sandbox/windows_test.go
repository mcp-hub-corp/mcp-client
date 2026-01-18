//go:build windows

package sandbox

import (
	"os/exec"
	"testing"
	"time"

	"github.com/security-mcp/mcp-client/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsSandboxNew(t *testing.T) {
	sandbox := newWindowsSandbox()
	require.NotNil(t, sandbox)
	assert.Equal(t, "windows", sandbox.Name())
}

func TestWindowsSandboxCapabilities(t *testing.T) {
	sandbox := newWindowsSandbox()
	caps := sandbox.Capabilities()

	// Windows supports Job Objects for basic resource limits
	assert.True(t, caps.CPULimit)
	assert.True(t, caps.MemoryLimit)
	assert.True(t, caps.PIDLimit)

	// But not these features
	assert.False(t, caps.NetworkIsolation)
	assert.False(t, caps.FilesystemIsolation)
	assert.False(t, caps.Cgroups)
	assert.False(t, caps.Namespaces)
	assert.False(t, caps.SupportsSeccomp)
	assert.False(t, caps.FDLimit)

	// Should have warnings
	assert.NotEmpty(t, caps.Warnings)
}

func TestWindowsSandboxApply(t *testing.T) {
	sandbox := newWindowsSandbox()
	cmd := exec.Command("cmd", "/c", "exit 0")

	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    1024,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits)
	assert.NoError(t, err)
}

func TestWindowsSandboxApplyPartialLimits(t *testing.T) {
	sandbox := newWindowsSandbox()
	cmd := exec.Command("cmd", "/c", "exit 0")

	limits := &policy.ExecutionLimits{
		MaxCPU:    0,
		MaxMemory: "",
		MaxPIDs:   0,
		MaxFDs:    0,
		Timeout:   5 * time.Second,
	}

	err := sandbox.Apply(cmd, limits)
	assert.NoError(t, err)
}

func TestWindowsParseMemoryString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int64
	}{
		{"512M", "512M", 512 * 1024 * 1024},
		{"1G", "1G", 1024 * 1024 * 1024},
		{"256K", "256K", 256 * 1024},
		{"empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseMemoryStringWindows(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWindowsSandboxNilInputs(t *testing.T) {
	sandbox := newWindowsSandbox()

	// Nil command
	err := sandbox.Apply(nil, &policy.ExecutionLimits{})
	assert.Error(t, err)

	// Nil limits
	err = sandbox.Apply(exec.Command("cmd", "/c", "exit 0"), nil)
	assert.Error(t, err)
}
