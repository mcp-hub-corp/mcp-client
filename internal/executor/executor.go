package executor

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/security-mcp/mcp-client/internal/manifest"
	"github.com/security-mcp/mcp-client/internal/policy"
)

// Executor defines the interface for executing MCP servers
type Executor interface {
	Execute(ctx context.Context, entrypoint *manifest.Entrypoint, bundlePath string) error
}

// STDIOExecutor executes MCP servers using STDIO transport
type STDIOExecutor struct {
	workDir string
	limits  *policy.ExecutionLimits
	env     map[string]string
	logger  *slog.Logger
}

// NewSTDIOExecutor creates a new STDIO executor
func NewSTDIOExecutor(workDir string, limits *policy.ExecutionLimits, env map[string]string) (*STDIOExecutor, error) {
	if workDir == "" {
		return nil, fmt.Errorf("work directory cannot be empty")
	}
	if limits == nil {
		return nil, fmt.Errorf("limits cannot be nil")
	}

	return &STDIOExecutor{
		workDir: workDir,
		limits:  limits,
		env:     env,
		logger:  slog.Default(),
	}, nil
}

// SetLogger sets the logger
func (e *STDIOExecutor) SetLogger(logger *slog.Logger) {
	e.logger = logger
}

// Execute starts the MCP server process via STDIO and waits for completion
func (e *STDIOExecutor) Execute(ctx context.Context, entrypoint *manifest.Entrypoint, bundlePath string) error {
	if entrypoint == nil {
		return fmt.Errorf("entrypoint cannot be nil")
	}
	if bundlePath == "" {
		return fmt.Errorf("bundle path cannot be empty")
	}

	// Build the full command path
	commandPath := filepath.Join(bundlePath, entrypoint.Command)

	// Check if command exists and is executable
	if _, err := os.Stat(commandPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("command not found: %s", commandPath)
		}
		return fmt.Errorf("failed to stat command: %w", err)
	}

	e.logger.Info("starting STDIO executor",
		slog.String("command", commandPath),
		slog.String("workdir", e.workDir),
		slog.Int("max_cpu", e.limits.MaxCPU),
		slog.String("max_memory", e.limits.MaxMemory),
		slog.Duration("timeout", e.limits.Timeout),
	)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, e.limits.Timeout)
	defer cancel()

	// Create command
	cmd := exec.CommandContext(ctx, commandPath, entrypoint.Args...)

	// Set working directory
	cmd.Dir = e.workDir

	// Set environment
	cmd.Env = e.buildEnv()

	// Connect STDIO
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process: %w", err)
	}

	e.logger.Debug("process started", slog.Int("pid", cmd.Process.Pid))

	// Wait for process to complete or context to cancel
	err := cmd.Wait()

	if ctx.Err() == context.DeadlineExceeded {
		e.logger.Warn("process timeout exceeded", slog.Duration("timeout", e.limits.Timeout))
		return fmt.Errorf("execution timeout exceeded: %s", e.limits.Timeout)
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			e.logger.Info("process exited with error",
				slog.Int("exit_code", exitErr.ExitCode()),
				slog.String("error", err.Error()),
			)
			return fmt.Errorf("process exited with code %d: %w", exitErr.ExitCode(), err)
		}
		return fmt.Errorf("process execution error: %w", err)
	}

	e.logger.Info("process completed successfully")
	return nil
}

// buildEnv builds the environment for the process
func (e *STDIOExecutor) buildEnv() []string {
	envMap := make(map[string]string)

	// Start with current environment
	for _, env := range os.Environ() {
		// Parse key=value
		var key, value string
		for i := 0; i < len(env); i++ {
			if env[i] == '=' {
				key = env[:i]
				value = env[i+1:]
				break
			}
		}
		if key != "" {
			envMap[key] = value
		}
	}

	// Add provided env vars (override existing)
	for k, v := range e.env {
		envMap[k] = v
	}

	// Convert to slice
	envSlice := make([]string, 0, len(envMap))
	for k, v := range envMap {
		envSlice = append(envSlice, k+"="+v)
	}

	return envSlice
}

// HTTPExecutor executes MCP servers using HTTP transport
// TODO: Implement in Phase 8
type HTTPExecutor struct{}

// NewHTTPExecutor creates a new HTTP executor
// TODO: Implement in Phase 8
func NewHTTPExecutor() *HTTPExecutor {
	return &HTTPExecutor{}
}

// Execute starts the MCP server process with HTTP transport
// TODO: Implement in Phase 8
func (e *HTTPExecutor) Execute(ctx context.Context, entrypoint *manifest.Entrypoint, bundlePath string) error {
	return fmt.Errorf("HTTP executor not yet implemented")
}

// Stop terminates the MCP server process
// TODO: Implement in Phase 8
func (e *HTTPExecutor) Stop() error {
	return nil
}
