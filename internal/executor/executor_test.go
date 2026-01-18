package executor

import (
	"context"
	"testing"
	"time"

	"github.com/security-mcp/mcp-client/internal/manifest"
	"github.com/security-mcp/mcp-client/internal/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSTDIOExecutor(t *testing.T) {
	workDir := t.TempDir()
	limits := &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   10,
		MaxFDs:    100,
		Timeout:   5 * time.Minute,
	}
	env := map[string]string{"TEST": "value"}

	executor, err := NewSTDIOExecutor(workDir, limits, env)
	require.NoError(t, err)
	require.NotNil(t, executor)
	assert.Equal(t, workDir, executor.workDir)
	assert.Equal(t, limits, executor.limits)
	assert.Equal(t, env, executor.env)
}

func TestNewSTDIOExecutor_EmptyWorkDir(t *testing.T) {
	limits := &policy.ExecutionLimits{Timeout: time.Minute}
	_, err := NewSTDIOExecutor("", limits, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "work directory")
}

func TestNewSTDIOExecutor_NilLimits(t *testing.T) {
	_, err := NewSTDIOExecutor(t.TempDir(), nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "limits")
}

func TestExecute_NilEntrypoint(t *testing.T) {
	executor, _ := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		Timeout: time.Second,
	}, nil)

	ctx := context.Background()
	err := executor.Execute(ctx, nil, t.TempDir())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entrypoint")
}

func TestExecute_EmptyBundlePath(t *testing.T) {
	executor, _ := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		Timeout: time.Second,
	}, nil)

	entrypoint := &manifest.Entrypoint{Command: "test"}
	ctx := context.Background()
	err := executor.Execute(ctx, entrypoint, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "bundle path")
}

func TestExecute_CommandNotFound(t *testing.T) {
	executor, _ := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		Timeout: time.Second,
	}, nil)

	entrypoint := &manifest.Entrypoint{
		Command: "nonexistent_command_xyz",
	}

	ctx := context.Background()
	err := executor.Execute(ctx, entrypoint, t.TempDir())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSTDIOExecutor_EnvironmentHandling(t *testing.T) {
	executor, err := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   32,
		MaxFDs:    256,
		Timeout:   time.Minute,
	}, map[string]string{
		"KEY1": "value1",
		"KEY2": "value2",
	})
	require.NoError(t, err)
	assert.NotNil(t, executor)
	assert.Equal(t, "value1", executor.env["KEY1"])
	assert.Equal(t, "value2", executor.env["KEY2"])
}

func TestSTDIOExecutor_EmptyEnvironment(t *testing.T) {
	executor, err := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   32,
		MaxFDs:    256,
		Timeout:   time.Minute,
	}, nil)
	require.NoError(t, err)
	assert.NotNil(t, executor)
	assert.Nil(t, executor.env)
}

func TestSetLogger(t *testing.T) {
	executor, err := NewSTDIOExecutor(t.TempDir(), &policy.ExecutionLimits{
		MaxCPU:    1000,
		MaxMemory: "512M",
		MaxPIDs:   32,
		MaxFDs:    256,
		Timeout:   time.Minute,
	}, nil)
	require.NoError(t, err)

	// Should not panic
	executor.SetLogger(nil)
	require.NotNil(t, executor)
}

