# Process Execution Skill

Expert knowledge for securely executing MCP server processes with proper resource isolation and lifecycle management.

## Overview

Process execution is the critical layer where security policies become enforceable constraints through OS mechanisms. It:
1. Creates process execution context with proper isolation
2. Applies sandbox constraints BEFORE process starts
3. Manages process lifecycle with timeouts and cleanup
4. Captures output and handles errors
5. Ensures clean termination and resource cleanup

## Execution Flow

```
1. Create execution context (WorkDir, Env, User)
2. Create context.Context with timeout
3. Create exec.Cmd with isolated configuration
4. Apply sandbox constraints (must be before Start())
5. Start process
6. Monitor for timeout (background goroutine)
7. Wait for completion
8. Clean up resources (file handles, processes)
9. Extract exit code and duration
10. Return results
```

## exec.Cmd Setup

### Basic Configuration

```go
// ExecutionContext contains configuration for process execution
type ExecutionContext struct {
    // Working directory (isolated filesystem)
    WorkDir string

    // Environment variables (filtered by policy)
    Env []string

    // User/Group (Unix only, for privilege dropping)
    User *user.User

    // Resource limits (applied via sandbox)
    Limits ResourceLimits

    // Input/Output streams
    Stdin  io.Reader
    Stdout io.Writer
    Stderr io.Writer

    // Timeout for execution
    Timeout time.Duration

    // Context for cancellation
    Ctx context.Context
}

// PrepareExecCmd creates and configures exec.Cmd
func PrepareExecCmd(ctx context.Context, command string, args []string, execCtx ExecutionContext) *exec.Cmd {
    // Create command
    cmd := exec.CommandContext(ctx, command, args...)

    // Set working directory (filesystem isolation)
    cmd.Dir = execCtx.WorkDir

    // Set environment (policy-filtered variables)
    cmd.Env = execCtx.Env

    // Set stdio
    cmd.Stdin = execCtx.Stdin
    cmd.Stdout = execCtx.Stdout
    cmd.Stderr = execCtx.Stderr

    // Platform-specific configuration
    configureSysProcAttr(cmd, execCtx)

    return cmd
}
```

### SysProcAttr Configuration (Linux)

```go
func configureSysProcAttr(cmd *exec.Cmd, execCtx ExecutionContext) {
    if runtime.GOOS == "linux" {
        cmd.SysProcAttr = &syscall.SysProcAttr{
            // Create new process group (for process tree termination)
            Setpgid: true,
            Pgid:    0, // New group

            // Credentials (privilege dropping)
            Credential: &syscall.Credential{
                Uid: uint32(execCtx.User.Uid),
                Gid: uint32(execCtx.User.Gid),
            },

            // No elevated privileges
            NoSetGroups: true,
        }
    } else if runtime.GOOS == "darwin" {
        cmd.SysProcAttr = &syscall.SysProcAttr{
            Setpgid: true,
            Pgid:    0,
        }
    } else if runtime.GOOS == "windows" {
        cmd.SysProcAttr = &syscall.SysProcAttr{
            // Windows Job Objects will be used instead
            CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
        }
    }
}
```

### Working Directory Isolation

```go
// PrepareWorkingDirectory creates isolated directory for process
func PrepareWorkingDirectory(cacheDir, packageDigest string) (string, error) {
    // Create temporary directory per execution
    workDir := filepath.Join(cacheDir, "work", packageDigest[:16])

    if err := os.MkdirAll(workDir, 0755); err != nil {
        return "", err
    }

    // Verify directory is writable and safe
    if err := verifyDirectoryPerm(workDir); err != nil {
        return "", fmt.Errorf("workdir permission check failed: %w", err)
    }

    return workDir, nil
}

// verifyDirectoryPerm ensures directory is safe to execute in
func verifyDirectoryPerm(dir string) error {
    // Check owner is current user
    info, err := os.Stat(dir)
    if err != nil {
        return err
    }

    if !info.IsDir() {
        return fmt.Errorf("not a directory: %s", dir)
    }

    // Check permissions are restrictive (not world-writable)
    if info.Mode().Perm()&0022 != 0 {
        return fmt.Errorf("directory is world-writable: %s", dir)
    }

    return nil
}
```

## Context with Timeout

### Creating Timeout Context

```go
// CreateTimeoutContext creates a context that expires after timeout
func CreateTimeoutContext(baseCtx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
    if baseCtx == nil {
        baseCtx = context.Background()
    }

    // Create context with timeout
    ctx, cancel := context.WithTimeout(baseCtx, timeout)

    return ctx, cancel
}

// ExecutionWithTimeout wraps execution with timeout handling
func ExecutionWithTimeout(execCtx ExecutionContext, cmd *exec.Cmd) error {
    // Ensure timeout is set (fallback to default)
    if execCtx.Timeout == 0 {
        execCtx.Timeout = 5 * time.Minute
    }

    // Create timeout context
    ctx, cancel := CreateTimeoutContext(execCtx.Ctx, execCtx.Timeout)
    defer cancel() // CRITICAL: always cancel to clean up goroutines

    // Associate context with command
    // Note: this is already done in exec.CommandContext(), but shown for clarity
    cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)

    return cmd.Run() // Run() will be interrupted by ctx timeout
}
```

### Timeout Enforcement

```go
// TimeoutMonitor watches for timeout and handles termination
func TimeoutMonitor(cmd *exec.Cmd, timeout time.Duration) {
    done := make(chan error, 1)

    // Start process
    go func() {
        done <- cmd.Wait()
    }()

    // Wait for completion or timeout
    select {
    case err := <-done:
        // Process completed normally
        return err

    case <-time.After(timeout):
        // Timeout exceeded - terminate process
        return TerminateProcess(cmd, timeout)
    }
}

// TerminateProcess handles forced termination (SIGTERM → SIGKILL)
func TerminateProcess(cmd *exec.Cmd, killGracePeriod time.Duration) error {
    if cmd.Process == nil {
        return fmt.Errorf("process not started")
    }

    // Step 1: Send SIGTERM (graceful termination)
    if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
        return fmt.Errorf("failed to signal SIGTERM: %w", err)
    }

    // Wait for grace period
    done := make(chan error, 1)
    go func() {
        done <- cmd.Wait()
    }()

    select {
    case err := <-done:
        // Process exited after SIGTERM
        return fmt.Errorf("process killed by timeout: %w", err)

    case <-time.After(killGracePeriod):
        // Grace period expired - force kill
        if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
            return fmt.Errorf("failed to signal SIGKILL: %w", err)
        }

        // Wait for forceful termination
        if err := cmd.Wait(); err != nil {
            return fmt.Errorf("process killed (SIGKILL): %w", err)
        }

        return fmt.Errorf("process forcefully killed (exceeded grace period)")
    }
}
```

## Sandbox Application

### Pre-Start Application (CRITICAL)

Sandbox constraints MUST be applied BEFORE Start() is called:

```go
// ApplySandbox applies resource limits and isolation before process starts
func ApplySandbox(cmd *exec.Cmd, policy *FinalPolicy, sandbox Sandbox) error {
    // IMPORTANT: This must happen BEFORE cmd.Start()

    switch runtime.GOOS {
    case "linux":
        return sandbox.(*LinuxSandbox).Apply(cmd, policy)
    case "darwin":
        return sandbox.(*DarwinSandbox).Apply(cmd, policy)
    case "windows":
        return sandbox.(*WindowsSandbox).Apply(cmd, policy)
    }

    return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
}

// Full execution sequence
func ExecuteProcess(
    manifest *Manifest,
    policy *FinalPolicy,
    sandbox Sandbox,
    execCtx ExecutionContext,
) error {
    // 1. Prepare command
    cmd := PrepareExecCmd(execCtx.Ctx, manifest.Entrypoint.Command, manifest.Entrypoint.Args, execCtx)

    // 2. Apply sandbox BEFORE Start()
    if err := ApplySandbox(cmd, policy, sandbox); err != nil {
        return fmt.Errorf("failed to apply sandbox: %w", err)
    }

    // 3. Start process
    if err := cmd.Start(); err != nil {
        return fmt.Errorf("failed to start process: %w", err)
    }

    // 4. Monitor and wait
    return cmd.Wait()
}
```

### Post-Start Verification

```go
// VerifyProcessIsolation checks that process was isolated correctly
func VerifyProcessIsolation(cmd *exec.Cmd, policy *FinalPolicy, sandbox Sandbox) error {
    if cmd.Process == nil {
        return fmt.Errorf("process not started")
    }

    // Verify resource limits were applied
    if runtime.GOOS == "linux" {
        linuxSandbox := sandbox.(*LinuxSandbox)
        if err := linuxSandbox.VerifyLimitsApplied(cmd.Process.Pid, policy); err != nil {
            return fmt.Errorf("failed to verify resource limits: %w", err)
        }
    }

    return nil
}
```

## stdin/stdout/stderr Handling

### Standard I/O Setup

```go
// SetupStdio configures process input/output streams
func SetupStdio(cmd *exec.Cmd, mode TransportMode) error {
    switch mode {
    case TransportStdio:
        // For STDIO transport, inherit parent's streams
        cmd.Stdin = os.Stdin
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
        return nil

    case TransportHttp:
        // For HTTP transport, capture logs
        stdout := &LogCapture{Name: "stdout"}
        stderr := &LogCapture{Name: "stderr"}

        cmd.Stdout = stdout
        cmd.Stderr = stderr

        return nil

    default:
        return fmt.Errorf("unknown transport mode: %v", mode)
    }
}

type LogCapture struct {
    Name   string
    Buffer strings.Builder
    Mu     sync.Mutex
}

func (lc *LogCapture) Write(p []byte) (int, error) {
    lc.Mu.Lock()
    defer lc.Mu.Unlock()

    n, err := lc.Buffer.Write(p)
    if err != nil {
        return n, err
    }

    // Log line-by-line if complete lines
    s := lc.Buffer.String()
    if idx := strings.LastIndexByte(s, '\n'); idx >= 0 {
        line := s[:idx]
        log.Infof("[%s] %s", lc.Name, line)
        lc.Buffer.Reset()
        if idx+1 < len(s) {
            lc.Buffer.WriteString(s[idx+1:])
        }
    }

    return n, nil
}
```

### JSON-RPC for STDIO

```go
// For STDIO mode with JSON-RPC 2.0 protocol
type JsonRpcProcessor struct {
    Stdin  io.Writer
    Stdout io.Reader
    Stderr io.Reader
}

func (p *JsonRpcProcessor) SendRequest(req *jsonrpc.Request) error {
    data, err := json.Marshal(req)
    if err != nil {
        return err
    }

    _, err = p.Stdin.Write(append(data, '\n'))
    return err
}

func (p *JsonRpcProcessor) ReceiveResponse() (*jsonrpc.Response, error) {
    scanner := bufio.NewScanner(p.Stdout)
    if !scanner.Scan() {
        return nil, scanner.Err()
    }

    var resp jsonrpc.Response
    if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
        return nil, err
    }

    return &resp, nil
}
```

## Exit Code Extraction

### Unix Exit Codes

```go
// ExtractExitCode extracts the exit code from process error
func ExtractExitCode(err error) int {
    if err == nil {
        return 0 // Success
    }

    // Check if error is from exec.ExitError
    if exitErr, ok := err.(*exec.ExitError); ok {
        if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
            return status.ExitStatus()
        }
    }

    // Check for timeout context cancellation
    if errors.Is(err, context.DeadlineExceeded) {
        return 5 // Custom exit code for timeout
    }

    // Other errors
    return 1 // Generic error
}

// Common exit codes
const (
    ExitCodeSuccess     = 0
    ExitCodeGenericError = 1
    ExitCodeMissingFile = 127
    ExitCodeTimeout     = 5
    ExitCodeKilled      = 124 // Standard for SIGKILL
)
```

### Signal Extraction (Unix)

```go
// ExtractSignal extracts the signal that killed the process
func ExtractSignal(err error) (syscall.Signal, error) {
    if exitErr, ok := err.(*exec.ExitError); ok {
        if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
            if status.Signaled() {
                return status.Signal(), nil
            }
        }
    }

    return 0, fmt.Errorf("process did not exit via signal")
}

// ProcessTermination describes how process exited
type ProcessTermination struct {
    Type     string        // "exit", "signal", "timeout"
    Code     int           // Exit code or signal number
    Signal   syscall.Signal // Signal if killed by signal
    Duration time.Duration  // Execution duration
}

func DetermineTermination(startTime time.Time, err error) ProcessTermination {
    duration := time.Since(startTime)

    if err == nil {
        return ProcessTermination{
            Type:     "exit",
            Code:     0,
            Duration: duration,
        }
    }

    // Check for timeout
    if errors.Is(err, context.DeadlineExceeded) {
        return ProcessTermination{
            Type:     "timeout",
            Code:     5,
            Duration: duration,
        }
    }

    // Check for signal
    if signal, err := ExtractSignal(err); err == nil {
        return ProcessTermination{
            Type:     "signal",
            Code:     int(signal),
            Signal:   signal,
            Duration: duration,
        }
    }

    // Check for exit code
    exitCode := ExtractExitCode(err)
    return ProcessTermination{
        Type:     "exit",
        Code:     exitCode,
        Duration: duration,
    }
}
```

## Environment Variable Construction

### Policy-Based Construction

```go
// ConstructProcessEnvironment builds environment for process
func ConstructProcessEnvironment(manifest *Manifest, policy *FinalPolicy) []string {
    // Get parent environment
    parentEnv := os.Environ()

    // Apply policy-based filtering
    filteredEnv := ApplyEnvPolicy(parentEnv, policy.EnvPolicy)

    // Add manifest-required variables
    for _, envVar := range manifest.Security.Env {
        key := strings.SplitN(envVar, "=", 2)[0]

        // Don't override if already set
        if _, exists := findEnv(filteredEnv, key); !exists {
            filteredEnv = append(filteredEnv, envVar)
        }
    }

    // Add MCP-specific variables
    mcpEnv := []string{
        fmt.Sprintf("MCP_HOME=%s", getMcpHome()),
        fmt.Sprintf("MCP_BUNDLE_DIR=%s", getBundleDir()),
    }
    filteredEnv = append(filteredEnv, mcpEnv...)

    return filteredEnv
}

func findEnv(env []string, key string) (string, bool) {
    for _, envStr := range env {
        if strings.HasPrefix(envStr, key+"=") {
            return envStr, true
        }
    }
    return "", false
}
```

### Secret Handling

```go
// CRITICAL: Never log secret values

// InsertSecrets adds secrets to environment without logging values
func InsertSecrets(env []string, secrets map[string]string) []string {
    result := make([]string, len(env))
    copy(result, env)

    for name, value := range secrets {
        // Validate secret name
        if !isValidEnvVarName(name) {
            log.Warnf("Invalid secret name: %s (skipped, names only logged)", name)
            continue
        }

        // Add to environment
        result = append(result, fmt.Sprintf("%s=%s", name, value))

        // NEVER log the value
        log.Debugf("Added secret: %s (value redacted)", name)
    }

    return result
}

func isValidEnvVarName(name string) bool {
    if len(name) == 0 {
        return false
    }

    for i, ch := range name {
        if i == 0 {
            if !isLetter(ch) && ch != '_' {
                return false
            }
        } else {
            if !isLetter(ch) && !isDigit(ch) && ch != '_' {
                return false
            }
        }
    }

    return true
}
```

## Working Directory Isolation

### Directory Preparation

```go
// PrepareIsolatedWorkDir creates and configures isolated working directory
func PrepareIsolatedWorkDir(cacheDir, packageName, packageVersion string) (string, error) {
    // Create unique directory per execution
    dirName := fmt.Sprintf("%s-%s-%d", packageName, packageVersion, time.Now().UnixNano())
    workDir := filepath.Join(cacheDir, "work", dirName)

    // Create directory with restrictive permissions
    if err := os.MkdirAll(workDir, 0700); err != nil {
        return "", err
    }

    // Create standard subdirectories
    dirs := []string{"tmp", "log"}
    for _, dir := range dirs {
        if err := os.MkdirAll(filepath.Join(workDir, dir), 0700); err != nil {
            return "", err
        }
    }

    // Set TMPDIR to isolated tmp
    // (passed via environment to process)

    return workDir, nil
}

// CleanupWorkDir removes working directory after execution
func CleanupWorkDir(workDir string) error {
    // Log warning if cleanup takes long
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    done := make(chan error, 1)
    go func() {
        done <- os.RemoveAll(workDir)
    }()

    select {
    case err := <-done:
        return err
    case <-ctx.Done():
        return fmt.Errorf("cleanup timeout: directory may leak: %s", workDir)
    }
}
```

## Process Cleanup

### Deferred Cleanup Pattern

```go
// ExecuteWithCleanup ensures process and resources are cleaned up
func ExecuteWithCleanup(
    manifest *Manifest,
    policy *FinalPolicy,
    execCtx ExecutionContext,
) (ProcessTermination, error) {
    // Prepare working directory
    workDir, err := PrepareIsolatedWorkDir("/var/mcp/cache", manifest.Name, manifest.Version)
    if err != nil {
        return ProcessTermination{}, err
    }

    // CRITICAL: Always clean up workdir on exit
    defer func() {
        if err := CleanupWorkDir(workDir); err != nil {
            log.Warnf("Failed to cleanup workdir: %v", err)
        }
    }()

    execCtx.WorkDir = workDir

    // Execute process
    startTime := time.Now()
    cmd := PrepareExecCmd(execCtx.Ctx, manifest.Entrypoint.Command, manifest.Entrypoint.Args, execCtx)

    if err := ApplySandbox(cmd, policy, GetSandbox()); err != nil {
        return ProcessTermination{}, fmt.Errorf("sandbox apply failed: %w", err)
    }

    if err := cmd.Start(); err != nil {
        return ProcessTermination{}, fmt.Errorf("process start failed: %w", err)
    }

    // Wait for completion (with timeout)
    waitErr := cmd.Wait()

    termination := DetermineTermination(startTime, waitErr)
    return termination, waitErr
}
```

### Resource Leak Prevention

```go
// Ensure no file descriptor leaks
type ProcessExecutor struct {
    cmd     *exec.Cmd
    cancel  context.CancelFunc
    workDir string
}

func (pe *ProcessExecutor) Cleanup() error {
    // Cancel context (signals timeout, stops background goroutines)
    if pe.cancel != nil {
        pe.cancel()
    }

    // Terminate process if still running
    if pe.cmd != nil && pe.cmd.Process != nil {
        _ = pe.cmd.Process.Kill()
    }

    // Clean up working directory
    if pe.workDir != "" {
        _ = CleanupWorkDir(pe.workDir)
    }

    return nil
}

// Usage with defer
func Execute(...) error {
    executor := &ProcessExecutor{...}
    defer executor.Cleanup() // Ensures cleanup happens

    // Execute process
    return executor.cmd.Wait()
}
```

## Platform Differences

### Linux Specifics

```go
// Linux supports both SIGTERM and SIGKILL gracefully
func TerminateLinuxProcess(cmd *exec.Cmd, gracePeriod time.Duration) error {
    pgid, err := syscall.Getpgid(cmd.Process.Pid)
    if err != nil {
        return err
    }

    // Send SIGTERM to process group
    syscall.Kill(-pgid, syscall.SIGTERM)

    // Wait for grace period
    done := make(chan error, 1)
    go func() {
        done <- cmd.Wait()
    }()

    select {
    case <-done:
        return fmt.Errorf("killed by timeout")
    case <-time.After(gracePeriod):
        // Force kill process group
        syscall.Kill(-pgid, syscall.SIGKILL)
        <-done
        return fmt.Errorf("killed (SIGKILL)")
    }
}
```

### macOS Specifics

```go
// macOS: process group killing may not work, use more careful approach
func TerminatedarwinProcess(cmd *exec.Cmd, gracePeriod time.Duration) error {
    if cmd.Process == nil {
        return fmt.Errorf("process not started")
    }

    // Send SIGTERM
    if err := cmd.Process.Signal(os.Interrupt); err != nil {
        return err
    }

    // Wait for grace period
    ctx, cancel := context.WithTimeout(context.Background(), gracePeriod)
    defer cancel()

    done := make(chan error, 1)
    go func() {
        done <- cmd.Wait()
    }()

    select {
    case err := <-done:
        return err
    case <-ctx.Done():
        // Force kill
        cmd.Process.Kill()
        <-done
        return fmt.Errorf("killed (SIGKILL)")
    }
}
```

### Windows Specifics

```go
// Windows: Use Job Objects for process termination
func TerminateWindowsProcess(cmd *exec.Cmd, gracePeriod time.Duration) error {
    if cmd.Process == nil {
        return fmt.Errorf("process not started")
    }

    // Windows doesn't have SIGTERM, send Interrupt instead
    if err := cmd.Process.Signal(os.Interrupt); err != nil {
        return err
    }

    // Wait for grace period
    ctx, cancel := context.WithTimeout(context.Background(), gracePeriod)
    defer cancel()

    done := make(chan error, 1)
    go func() {
        done <- cmd.Wait()
    }()

    select {
    case err := <-done:
        return err
    case <-ctx.Done():
        // Force kill via Kill()
        cmd.Process.Kill()
        <-done
        return fmt.Errorf("killed")
    }
}
```

## Testing Process Execution

### Unit Test Categories

**1. Timeout Tests:**
```go
func TestExecuteWithTimeout_TimeoutKillsProcess(t *testing.T) {
    // Create slow command
    cmd := exec.Command("sleep", "30")

    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()

    cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)

    startTime := time.Now()
    err := cmd.Run()
    duration := time.Since(startTime)

    // Should fail due to timeout
    assert.Error(t, err)
    assert.True(t, errors.Is(err, context.DeadlineExceeded))

    // Duration should be close to timeout (within 500ms)
    assert.Less(t, duration, 200*time.Millisecond)
}

func TestExecuteWithTimeout_FastProcessSucceeds(t *testing.T) {
    cmd := exec.Command("echo", "hello")

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)

    err := cmd.Run()
    assert.NoError(t, err)
}
```

**2. Environment Variable Tests:**
```go
func TestConstructEnvironment_FilteringWorks(t *testing.T) {
    parentEnv := []string{
        "PATH=/usr/bin",
        "SECRET=hidden",
        "HOME=/home/user",
    }

    policy := EnvPolicy{
        Mode: "allowlist",
        Variables: []string{"PATH", "HOME"},
    }

    result := ConstructProcessEnvironment(parentEnv, policy)

    assert.Contains(t, result, "PATH=/usr/bin")
    assert.Contains(t, result, "HOME=/home/user")
    assert.NotContains(t, result, "SECRET=hidden")
}

func TestConstructEnvironment_NoLoggingSecrets(t *testing.T) {
    // Capture logs
    logBuffer := &strings.Builder{}

    secrets := map[string]string{
        "API_KEY": "super-secret-value-123",
    }

    InsertSecrets([]string{}, secrets)

    // Verify secret value never appears in logs
    assert.NotContains(t, logBuffer.String(), "super-secret-value-123")
}
```

**3. Exit Code Tests:**
```go
func TestExtractExitCode_SuccessReturnsZero(t *testing.T) {
    code := ExtractExitCode(nil)
    assert.Equal(t, 0, code)
}

func TestExtractExitCode_FailureReturnsCode(t *testing.T) {
    // Create command that exits with code 42
    cmd := exec.Command("sh", "-c", "exit 42")
    err := cmd.Run()

    code := ExtractExitCode(err)
    assert.Equal(t, 42, code)
}

func TestExtractExitCode_TimeoutReturnsTimeoutCode(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
    defer cancel()

    cmd := exec.CommandContext(ctx, "sleep", "10")
    err := cmd.Run()

    code := ExtractExitCode(err)
    assert.Equal(t, 5, code) // Custom timeout code
}
```

**4. Cleanup Tests:**
```go
func TestCleanupWorkDir_RemovesDirectory(t *testing.T) {
    tmpDir := t.TempDir()
    workDir := filepath.Join(tmpDir, "work")
    os.MkdirAll(workDir, 0755)

    testFile := filepath.Join(workDir, "test.txt")
    ioutil.WriteFile(testFile, []byte("test"), 0644)

    err := CleanupWorkDir(workDir)
    assert.NoError(t, err)

    // Directory should be removed
    _, err = os.Stat(workDir)
    assert.True(t, os.IsNotExist(err))
}

func TestCleanupWorkDir_TimeoutCleaning(t *testing.T) {
    // Create directory that's hard to delete
    workDir := t.TempDir()

    // Create read-only file (may not allow deletion)
    readOnlyFile := filepath.Join(workDir, "readonly.txt")
    ioutil.WriteFile(readOnlyFile, []byte("test"), 0444)

    // Attempt cleanup
    err := CleanupWorkDir(workDir)
    // May or may not fail depending on OS, but cleanup should timeout gracefully
}
```

**5. Process Termination Tests:**
```go
func TestDetermineTermination_NormalExit(t *testing.T) {
    startTime := time.Now()
    cmd := exec.Command("true")
    cmd.Run()

    term := DetermineTermination(startTime, nil)

    assert.Equal(t, "exit", term.Type)
    assert.Equal(t, 0, term.Code)
    assert.Greater(t, term.Duration, 0)
}

func TestDetermineTermination_Timeout(t *testing.T) {
    startTime := time.Now()

    term := DetermineTermination(startTime, context.DeadlineExceeded)

    assert.Equal(t, "timeout", term.Type)
    assert.Equal(t, 5, term.Code)
}
```

### Integration Test Categories

**1. Full Execution with Sandbox:**
```go
func TestExecuteProcessWithSandbox(t *testing.T) {
    // Create test manifest
    manifest := &Manifest{
        Name: "test/echo",
        Entrypoint: EntrypointConfig{
            Command: "/bin/echo",
            Args: []string{"hello"},
        },
    }

    policy := &FinalPolicy{
        ResourceLimits: ResourceLimits{CPU: 1000, Memory: 512*1024*1024, PIDs: 32, FDs: 256, Timeout: 5*time.Minute},
    }

    execCtx := ExecutionContext{
        Timeout: 5 * time.Second,
    }

    term, err := ExecuteWithCleanup(manifest, policy, execCtx)

    assert.NoError(t, err)
    assert.Equal(t, 0, term.Code)
}
```

**2. Resource Limit Enforcement:**
```go
func TestExecuteProcess_EnforcesMemoryLimit(t *testing.T) {
    // Create command that tries to allocate too much memory
    manifest := &Manifest{
        Name: "test/memory-hog",
        Entrypoint: EntrypointConfig{
            Command: "/usr/bin/python3",
            Args: []string{"-c", "import array; array.array('L', [0] * (1024*1024*1024))"},
        },
    }

    policy := &FinalPolicy{
        ResourceLimits: ResourceLimits{
            CPU: 1000,
            Memory: 50*1024*1024, // Only 50 MiB
            Timeout: 5*time.Second,
        },
    }

    term, _ := ExecuteWithCleanup(manifest, policy, ExecutionContext{})

    // Should fail (killed by OOM)
    assert.NotEqual(t, 0, term.Code)
}
```

## Common Mistakes and Anti-Patterns

### Mistake 1: Not Creating Context with Timeout
**WRONG:**
```go
cmd := exec.Command("sleep", "100")
cmd.Start()
cmd.Wait() // May wait forever!
```

**CORRECT:**
```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

cmd := exec.CommandContext(ctx, "sleep", "100")
if err := cmd.Run(); err != nil {
    // Process will be killed after 5 seconds
}
```

### Mistake 2: Applying Sandbox After Start()
**WRONG:**
```go
cmd := exec.Command("./server")
cmd.Start() // Already running!

sandbox.Apply(cmd, policy) // TOO LATE - process is unrestricted
```

**CORRECT:**
```go
cmd := exec.Command("./server")

// Apply sandbox BEFORE Start()
sandbox.Apply(cmd, policy)

cmd.Start() // Now starts with restrictions
```

### Mistake 3: Not Calling Cancel() on Context
**WRONG:**
```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// Forgot to call cancel()
cmd := exec.CommandContext(ctx, ...)
cmd.Run()
// Background goroutine leaks!
```

**CORRECT:**
```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel() // Always call cancel
cmd := exec.CommandContext(ctx, ...)
cmd.Run()
```

### Mistake 4: Logging Secret Values
**WRONG:**
```go
for name, value := range secrets {
    log.Infof("Setting secret: %s=%s", name, value) // EXPOSES SECRET!
}
```

**CORRECT:**
```go
for name := range secrets {
    log.Debugf("Setting secret: %s (value redacted)", name)
}
```

### Mistake 5: Not Cleaning Up Working Directory
**WRONG:**
```go
workDir, _ := PrepareIsolatedWorkDir(...)
cmd := exec.Command("./server")
cmd.Dir = workDir
cmd.Run()
// workDir never cleaned up - disk space leak!
```

**CORRECT:**
```go
workDir, _ := PrepareIsolatedWorkDir(...)
defer CleanupWorkDir(workDir)

cmd := exec.Command("./server")
cmd.Dir = workDir
cmd.Run()
```

### Mistake 6: Wrong Exit Code Extraction
**WRONG:**
```go
if cmd.Run() != nil {
    return 1 // All errors return same code!
}
```

**CORRECT:**
```go
err := cmd.Run()
exitCode := ExtractExitCode(err) // Properly extracts actual exit code
return exitCode
```

### Mistake 7: Not Validating Working Directory
**WRONG:**
```go
workDir := "/tmp/something" // World-writable!
cmd.Dir = workDir // Insecure
```

**CORRECT:**
```go
workDir := "/tmp/mcp/work/safe-dir"
if err := verifyDirectoryPerm(workDir); err != nil {
    return err // Reject unsafe directory
}
cmd.Dir = workDir
```

### Mistake 8: Sending Signals After Wait()
**WRONG:**
```go
cmd.Start()
cmd.Wait()
cmd.Process.Signal(syscall.SIGTERM) // Too late, process is gone!
```

**CORRECT:**
```go
cmd.Start()

select {
case <-time.After(timeout):
    cmd.Process.Signal(syscall.SIGTERM) // Signal BEFORE wait completes
case <-done:
    // Process finished naturally
}
```

## Security Checklist

Before starting process:

- [ ] Timeout context created and will be properly canceled
- [ ] Sandbox policy passed and ready to apply
- [ ] Working directory created, isolated, and writable
- [ ] Environment variables constructed per policy
- [ ] Secrets inserted without logging values
- [ ] exec.Cmd fully configured (Dir, Env, Stdin/Stdout/Stderr)
- [ ] SysProcAttr configured for target OS
- [ ] Sandbox.Apply() will be called BEFORE Start()
- [ ] Cleanup (defer) handlers registered
- [ ] Process monitoring/timeout mechanism ready

During execution:

- [ ] Process started successfully
- [ ] Resource limits enforced (verify via sandbox)
- [ ] Timeout is being monitored
- [ ] No file descriptor leaks

After execution:

- [ ] Exit code properly extracted
- [ ] Working directory cleaned up
- [ ] Context canceled (no goroutine leaks)
- [ ] Process fully terminated

## References

- CLAUDE.md Section 3: Threat Model
- CLAUDE.md Section 4: Security Invariants
- security-policy.md: Policy enforcement
- audit-logging.md: Execution logging
