# Windows Sandbox Expert

Expert knowledge for Windows process isolation via Job Objects.

## Core Concepts

### Job Objects

Windows-specific process management:
- Group processes into "jobs"
- Apply limits to entire job
- Automatic child process inclusion
- Kill-on-close semantics

### Key APIs

```go
import "golang.org/x/sys/windows"

// Create job
job, _ := windows.CreateJobObject(nil, nil)

// Assign process
windows.AssignProcessToJobObject(job, processHandle)

// Set limits
windows.SetInformationJobObject(job, ...)

// Cleanup
windows.CloseHandle(job)
```

### Limit Types

- Memory: ProcessMemoryLimit, JobMemoryLimit
- Process count: ActiveProcessLimit
- CPU: Limited (affinity/priority, not hard time)
- I/O: I/O rate limiting

## Patterns

### Pre-Spawn Setup
```go
func (s *WindowsSandbox) Apply(cmd *exec.Cmd, limits *policy.ExecutionLimits) error {
    if cmd.SysProcAttr == nil {
        cmd.SysProcAttr = &syscall.SysProcAttr{}
    }

    // CREATE_BREAKAWAY_FROM_JOB allows us to assign to our job
    cmd.SysProcAttr.CreationFlags |= 0x01000000

    return nil
}
```

### Post-Spawn Job Assignment
```go
func (s *WindowsSandbox) AssignToJob(processHandle windows.Handle, limits *policy.ExecutionLimits) (windows.Handle, error) {
    job, _ := windows.CreateJobObject(nil, nil)

    // Set memory limit
    info := JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
    info.ProcessMemoryLimit = uintptr(memBytes)
    info.BasicLimitInformation.LimitFlags |= 0x00000100 // JOB_OBJECT_LIMIT_PROCESS_MEMORY

    windows.AssignProcessToJobObject(job, processHandle)

    return job, nil
}
```

## Anti-Patterns

❌ **Assuming rlimits exist**: Windows doesn't have POSIX rlimits
✅ **Use Job Objects**: Windows-native mechanism

❌ **Forgetting CREATE_BREAKAWAY_FROM_JOB**: Process can't be assigned to job
✅ **Set flag pre-spawn**: Required for job assignment

❌ **Not cleaning up handles**: Memory leak
✅ **CloseHandle() in defer**: Proper cleanup

## Debugging

```powershell
# View job info
Process Explorer (sysinternals)

# Check process limits
Get-Process -Id $PID | Select-Object WorkingSet, CPU, Handles
```

## References

- Job Objects: https://docs.microsoft.com/en-us/windows/win32/procthread/job-objects
- golang.org/x/sys/windows documentation
