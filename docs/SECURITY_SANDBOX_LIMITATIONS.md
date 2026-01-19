# Sandbox Security Limitations

## ⚠️ CRITICAL SECURITY NOTICE

The mcp-client sandbox has **KNOWN LIMITATIONS** on macOS and Windows that allow malicious MCPs to bypass resource limits.

---

## macOS Limitations

### Issue: rlimits Not Applied to Child Processes

**Severity:** CRITICAL
**Status:** DOCUMENTED (not fixable in Go without external tools)
**Vulnerability ID:** CLIENT-CRIT-003

**Problem:**
- `syscall.Setrlimit()` sets limits on **current process** (parent)
- Go's `exec.Cmd` does **NOT** propagate rlimits to child processes
- Child processes inherit **UNLIMITED** resources from the shell/OS defaults
- This is a fundamental limitation of the Go stdlib and macOS process model

**Technical Details:**

```go
// In darwin.go, lines 69-107
_ = syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{
    Cur: cpuSeconds,
    Max: cpuSeconds,
})
```

This call sets limits on the **parent process** that calls `Setrlimit()`, but when Go's `exec.Cmd` spawns a child process, the child inherits the **system defaults**, not the parent's rlimits.

**Why Go doesn't propagate rlimits:**
- Go's `exec.Cmd` uses `fork() + exec()` internally
- After `fork()`, the child inherits limits, but `exec()` **resets** many process attributes
- Go stdlib does not have hooks to re-apply rlimits after exec but before the target binary runs
- This would require `setrlimit()` syscall wrapper in assembly or cgo, which Go stdlib doesn't provide

**Attack Vectors:**

```bash
# Fork bomb bypasses RLIMIT_NPROC
:(){ :|:& };:

# Memory bomb bypasses RLIMIT_AS
python3 -c "data = bytearray(10*1024**3)"

# CPU hog bypasses RLIMIT_CPU
while true; do :; done
```

All of these will succeed because the spawned process has **no effective limits**.

**Mitigation Options:**

1. **Docker Container (RECOMMENDED for production)**
   ```yaml
   services:
     mcp-client:
       image: mcp-client:latest
       deploy:
         resources:
           limits:
             cpus: "1.0"
             memory: 512M
           reservations:
             cpus: "0.5"
             memory: 256M
   ```

2. **launchd with plist limits**
   ```xml
   <key>ResourceLimits</key>
   <dict>
       <key>CPU</key>
       <integer>60</integer>
       <key>NumberOfFiles</key>
       <integer>256</integer>
   </dict>
   ```

3. **Process monitoring + kill**
   ```bash
   # External watchdog script
   timeout 300s mcp run acme/tool
   ```

4. **VM isolation**
   - Run mcp-client in a Linux VM on macOS (e.g., UTM, Parallels, VMware)
   - This provides kernel-level cgroups enforcement

**What DOES work on macOS:**
- Timeout enforcement (parent process monitors and kills child)
- Basic UNIX permissions (file access control)
- Parent process can inspect child resource usage and kill it

**What DOES NOT work on macOS:**
- Resource limits (CPU, memory, PIDs, FDs) on child processes
- Network isolation (no network namespaces)
- Filesystem isolation (no mount namespaces)
- Seccomp-style syscall filtering

**DO NOT:**
- Run untrusted MCPs on macOS in production environments
- Assume resource limits will protect you from malicious code
- Deploy mcp-client on bare metal macOS for security-critical workloads

**Recommended Actions:**
- ✅ Development/testing: macOS is acceptable with awareness of risks
- ✅ Production: Use Linux with cgroups or Docker containers
- ✅ macOS production (if unavoidable): Run in VM with Linux guest
- ❌ Never: Run untrusted MCPs on bare metal macOS

---

## Windows Limitations

### Issue: Job Objects Not Applied to Processes

**Severity:** CRITICAL
**Status:** IMPLEMENTATION BUG (fixable)
**Vulnerability ID:** CLIENT-CRIT-004, CLIENT-CRIT-005

**Problem:**
- Job Objects are **created** in `AssignProcessToJob()` (line 82)
- Job Object limits are configured in `setJobLimits()` (line 121)
- **BUT** `setJobLimits()` is a **NO-OP** (line 162-163: `_ = info; _ = jobHandle`)
- Processes are assigned to Job Object, but **no limits are enforced**
- Result: Processes have **UNLIMITED** resources

**Technical Details:**

```go
// In windows.go, line 121-169
func (s *WindowsSandbox) setJobLimits(jobHandle windows.Handle, limits *policy.ExecutionLimits) error {
    // ... code prepares limits ...

    // Line 162-163: NO-OP - limits are never applied!
    _ = info
    _ = jobHandle

    return nil // Returns success WITHOUT applying limits
}
```

**Why this is broken:**
- Go's `golang.org/x/sys/windows` package does not expose `SetInformationJobObject()`
- The function prepares the `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` struct (line 124)
- But it **never calls the Windows API** to apply the limits (line 162)
- The comment admits this (line 165): "In a production implementation, you would use: kernel32.SetInformationJobObject(...)"

**Attack Vectors:**

```powershell
# Memory bomb - no limits applied
$data = New-Object byte[] 10GB

# Process bomb - no limits applied
1..1000 | ForEach-Object { Start-Process notepad.exe }

# CPU hog - no limits applied
while ($true) { 1+1 }
```

All of these will succeed because Job Object limits are **NOT APPLIED**.

**Root Causes:**
1. **CLIENT-CRIT-004**: `setJobLimits()` does not call Windows API
2. **CLIENT-CRIT-005**: No syscall wrapper for `SetInformationJobObject()`

**Fix Required:**

```go
// Use syscall to call kernel32.dll!SetInformationJobObject
var (
    kernel32 = syscall.NewLazyDLL("kernel32.dll")
    procSetInformationJobObject = kernel32.NewProc("SetInformationJobObject")
)

func (s *WindowsSandbox) setJobLimits(jobHandle windows.Handle, limits *policy.ExecutionLimits) error {
    // Prepare info struct...

    // Call Windows API
    ret, _, err := procSetInformationJobObject.Call(
        uintptr(jobHandle),
        9, // JobObjectExtendedLimitInformation
        uintptr(unsafe.Pointer(&info)),
        unsafe.Sizeof(info),
    )

    if ret == 0 {
        return fmt.Errorf("SetInformationJobObject failed: %w", err)
    }

    return nil
}
```

**Mitigation Until Fixed:**

1. **Docker Desktop on Windows (RECOMMENDED)**
   ```yaml
   services:
     mcp-client:
       image: mcp-client:latest
       deploy:
         resources:
           limits:
             cpus: "1.0"
             memory: 512M
   ```

2. **Windows Sandbox (Windows 10 Pro+ only)**
   - Provides hypervisor-level isolation
   - Requires manual setup per execution

3. **Process monitoring + kill**
   ```powershell
   # External watchdog
   Start-Job { mcp run acme/tool } | Wait-Job -Timeout 300 | Stop-Job
   ```

**What DOES work on Windows:**
- Job Object creation (process grouping)
- Process assignment to Job Object
- Timeout enforcement (parent process monitors and kills child)

**What DOES NOT work on Windows (current implementation):**
- Memory limits (Job Object limits not applied)
- Process count limits (Job Object limits not applied)
- CPU limits (Job Object limits not applied)
- Network isolation (Windows has no network namespaces)
- Filesystem isolation (Windows ACLs only, no namespaces)

**DO NOT:**
- Use current version (v1.x) on Windows in production
- Assume Job Objects provide any resource protection
- Deploy mcp-client on bare metal Windows for security-critical workloads

**Recommended Actions:**
- ✅ Development/testing: Windows is acceptable with awareness of risks
- ✅ Wait for fix: ETA 1 week (P0 priority issue)
- ✅ Production (before fix): Use Docker Desktop on Windows
- ❌ Never: Run untrusted MCPs on bare metal Windows with current implementation

---

## Comparison Matrix

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| **CPU Limits** | ✅ cgroups/rlimits | ❌ Not applied to child | ❌ Not implemented |
| **Memory Limits** | ✅ cgroups/rlimits | ❌ Not applied to child | ❌ Not implemented |
| **Process Limits** | ✅ cgroups/rlimits | ❌ Not applied to child | ❌ Not implemented |
| **FD Limits** | ✅ rlimits | ❌ Not applied to child | ❌ N/A (Windows uses handles) |
| **Network Isolation** | ✅ netns + eBPF | ❌ Not supported | ❌ Not supported |
| **Filesystem Isolation** | ✅ mount namespace | ❌ Not supported | ❌ Not supported |
| **Timeout** | ✅ Parent monitoring | ✅ Parent monitoring | ✅ Parent monitoring |
| **Production Ready** | ✅ YES | ❌ NO (use Docker/VM) | ❌ NO (use Docker) |

---

## Recommendations by Environment

### For Development:
- ✅ **Linux**: Full sandbox, all features work
- ⚠️ **macOS**: Acceptable with awareness of limitations
- ⚠️ **Windows**: Acceptable with awareness of limitations
- **Rule:** Never test malicious/untrusted code on macOS/Windows

### For Production:
- ✅ **Linux bare metal**: Full sandbox with cgroups v2
- ✅ **Docker on any platform**: Container resource limits
- ✅ **Kubernetes**: Pod resource quotas + Network Policies
- ❌ **macOS bare metal**: NOT RECOMMENDED
- ❌ **Windows bare metal**: NOT RECOMMENDED (wait for fix)

### For CI/CD:
- ✅ **Linux runners**: GitHub Actions, GitLab CI (ubuntu-latest)
- ⚠️ **macOS runners**: Only for compilation/unit tests, NOT for running untrusted MCPs
- ⚠️ **Windows runners**: Only for compilation/unit tests, NOT for running untrusted MCPs

### For Enterprise:
- ✅ **Kubernetes**: Best isolation + observability
- ✅ **Docker Swarm**: Good isolation + orchestration
- ✅ **Linux VMs**: KVM/Xen with cgroups
- ⚠️ **Windows VMs**: Wait for Job Object fix
- ❌ **Bare metal macOS/Windows**: PROHIBITED

---

## Status Tracking

### macOS rlimits (CLIENT-CRIT-003)
- **Status:** DOCUMENTED, WON'T FIX (OS limitation)
- **Priority:** Low (documented limitation, use Docker/VM)
- **Workaround:** Run in Linux VM or Docker container
- **ETA:** N/A (fundamental OS limitation)

### Windows Job Objects (CLIENT-CRIT-004, CLIENT-CRIT-005)
- **Status:** IMPLEMENTATION BUG, HIGH PRIORITY
- **Priority:** P0 (broken security control)
- **Fix:** Implement `setJobLimits()` with syscall to `SetInformationJobObject()`
- **ETA:** 1 week
- **Tracking:**
  - [ ] Add syscall wrapper for `SetInformationJobObject()`
  - [ ] Implement memory limit enforcement
  - [ ] Implement process count limit enforcement
  - [ ] Add unit tests with Job Object verification
  - [ ] Add E2E tests verifying limits are applied
  - [ ] Update documentation

---

## Verification Commands

### Check if limits are applied (Linux):
```bash
# Run MCP and check cgroups
mcp run acme/tool &
cat /sys/fs/cgroup/mcp-*/memory.max
cat /sys/fs/cgroup/mcp-*/cpu.max
```

### Check if limits are applied (macOS):
```bash
# This will FAIL (limits not propagated)
mcp run acme/tool &
ps aux | grep mcp-server
# Memory/CPU limits will be system defaults, NOT configured limits
```

### Check if limits are applied (Windows):
```powershell
# This will FAIL (Job Object limits not set)
mcp run acme/tool &
Get-Process -Name "mcp-server" | Select-Object -Property WorkingSet, CPU
# No Job Object limits will be enforced
```

---

## Reporting Security Issues

If you discover additional sandbox bypass techniques:

1. **DO NOT** open a public GitHub issue
2. Email security details to: security@mcp-hub.info
3. Include:
   - Platform (Linux/macOS/Windows)
   - Version (`mcp version`)
   - Steps to reproduce bypass
   - Expected vs actual behavior
   - Proof-of-concept (if safe to share)

**Coordinated disclosure:** We aim to respond within 48 hours and release patches within 1 week for CRITICAL issues.

---

**Last Updated:** 2026-01-19
**Document Version:** 1.0
**Reviewed By:** Security Team

**Related Documents:**
- `docs/SECURITY.md` - Comprehensive security model
- `internal/sandbox/darwin.go` - macOS implementation
- `internal/sandbox/windows.go` - Windows implementation
- `internal/sandbox/linux.go` - Linux implementation (reference)
