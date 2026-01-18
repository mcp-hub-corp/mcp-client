# Linux Sandbox Expert

Expert knowledge for implementing and debugging Linux process isolation.

## Core Concepts

### rlimits (Resource Limits)
- RLIMIT_CPU: CPU time in seconds (wall-clock)
- RLIMIT_AS: Virtual memory (address space)
- RLIMIT_NPROC: Process count (per-user)
- RLIMIT_NOFILE: File descriptors (open files/sockets)

**Formula for CPU**: `timeout_seconds * (millicores / 1000) = CPU_seconds`
Example: 5s timeout, 500mc = 2.5s CPU allowed

### Namespaces
- Mount (CLONE_NEWNS): Filesystem isolation
- Network (CLONE_NEWNET): Network isolation (default-deny)
- PID (CLONE_NEWPID): Process ID isolation
- User (CLONE_NEWUSER): UID/GID mapping

**Requires**: CAP_NET_ADMIN for network NS, or root

### cgroups v2
- cpu.max: "quota period" (e.g., "50000 100000" = 50% CPU)
- memory.max: bytes
- pids.max: count
- io.max: I/O limits

**Path**: /sys/fs/cgroup/[hierarchy]/

## Patterns

### Correct rlimit Application
```go
rlimits := []syscall.Rlimit{
    {Resource: syscall.RLIMIT_CPU, Cur: cpuSecs, Max: cpuSecs},
    {Resource: syscall.RLIMIT_AS, Cur: memBytes, Max: memBytes},
    {Resource: syscall.RLIMIT_NPROC, Cur: pids, Max: pids},
    {Resource: syscall.RLIMIT_NOFILE, Cur: fds, Max: fds},
}
cmd.SysProcAttr.Setrlimit = rlimits
```

### Safe cgroup Creation
```go
cgroupPath := filepath.Join("/sys/fs/cgroup", "mcp-"+pid)
os.Mkdir(cgroupPath, 0755)
defer os.RemoveAll(cgroupPath) // Cleanup

// Write PID
os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0644)

// Set limits
os.WriteFile(filepath.Join(cgroupPath, "cpu.max"), []byte("50000 100000"), 0644)
```

### Network Namespace
```go
cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNET
// Process gets empty network namespace (only loopback)
```

## Anti-Patterns

❌ **Wrong CPU calculation**: `cpuSecs := millicores / 100`
✅ **Correct**: `cpuSecs := timeout.Seconds() * (millicores / 1000.0)`

❌ **Forgetting Resource constant**: `syscall.Rlimit{Cur: x, Max: x}`
✅ **Correct**: `syscall.Rlimit{Resource: syscall.RLIMIT_CPU, Cur: x, Max: x}`

❌ **Assuming root**: Network namespaces fail on non-root
✅ **Check first**: `os.Geteuid() == 0` or CAP_NET_ADMIN check

## Debugging

```bash
# Check rlimits of running process
cat /proc/$PID/limits

# Check cgroups
cat /proc/$PID/cgroup
cat /sys/fs/cgroup/mcp-$PID/cpu.max

# Check namespaces
ls -la /proc/$PID/ns/

# Test rlimit enforcement
ulimit -t 5  # 5 seconds CPU
./cpu-intensive-program
```

## References

- man setrlimit(2)
- man cgroups(7)
- man namespaces(7)
- Kernel docs: https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
