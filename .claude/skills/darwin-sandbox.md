# macOS Sandbox Expert

Expert knowledge for macOS process isolation (rlimits only).

## Core Concepts

### macOS Limitations

**What works**:
- rlimits (RLIMIT_CPU, RLIMIT_AS, RLIMIT_NPROC, RLIMIT_NOFILE)
- Timeout via context
- Umask inheritance

**What doesn't work**:
- ❌ Network namespaces (Linux concept)
- ❌ Mount namespaces (Linux concept)
- ❌ cgroups (Linux concept)
- ❌ seccomp (Linux concept)
- ❌ Umask in SysProcAttr (not supported)

### rlimits on macOS

Use `syscall.Setrlimit()` directly (NOT SysProcAttr.Rlimits):

```go
func applyRLimits(limits *policy.ExecutionLimits) error {
    // CPU time
    syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{
        Cur: cpuSeconds,
        Max: cpuSeconds,
    })

    // Memory (best-effort on macOS)
    syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{
        Cur: memBytes,
        Max: memBytes,
    })

    // PIDs
    syscall.Setrlimit(syscall.RLIMIT_NPROC, &syscall.Rlimit{
        Cur: pids,
        Max: pids,
    })

    // FDs
    syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{
        Cur: fds,
        Max: fds,
    })

    return nil
}
```

## Patterns

### Correct Build Tags
```go
//go:build darwin

package sandbox
```

### Honest Capability Reporting
```go
func (s *DarwinSandbox) Capabilities() Capabilities {
    return Capabilities{
        CPULimit: true,
        MemoryLimit: true, // Best-effort
        NetworkIsolation: false, // BE HONEST
        Warnings: []string{
            "macOS does not support network isolation",
            "RLIMIT_AS may not prevent all allocations",
        },
    }
}
```

## Anti-Patterns

❌ **Using SysProcAttr.Rlimits on macOS**: Doesn't work
✅ **Use syscall.Setrlimit()**: Works correctly

❌ **Promising network isolation**: Not available
✅ **Document limitation**: Clear warnings

❌ **Assuming Linux syscalls**: Many don't exist
✅ **Check platform**: Build tags, feature detection

## Debugging

```bash
# Check limits of running process
launchctl limit

# Check process limits
ps -o pid,rss,vsz,time,command -p $PID

# Monitor resource usage
top -pid $PID
```

## References

- man setrlimit(2) on macOS
- https://developer.apple.com/library/archive/documentation/Performance/Conceptual/ManagingMemory/
