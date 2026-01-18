# Security Model

mcp-client implements lightweight security controls to mitigate common threats when executing untrusted MCP packages. This document explains the threat model, security invariants, and platform-specific capabilities.

## Threat Model

### Threats Covered (Reasonable Mitigation)

#### 1. Resource Exhaustion
**Threat**: Malicious code consumes unlimited CPU, memory, processes, or file descriptors.

**Mitigation**:
- Strict limits on CPU time, memory allocation, process count, and open file descriptors
- Timeout-based termination if resource limits are exceeded
- Platform-specific enforcement (rlimits on Linux/macOS, Job Objects on Windows)

#### 2. Unauthorized Filesystem Access
**Threat**: Process writes files outside its designated working directory.

**Mitigation**:
- Filesystem isolation: process confined to working directory + temporary directory
- Best-effort enforcement via OS mechanisms (bind mount on Linux, chroot-like on macOS)
- No write access to system directories or other user data

#### 3. Unauthorized Network Access
**Threat**: Process makes network connections to unexpected hosts.

**Mitigation**:
- Default-deny network policy: no external connections unless explicitly allowed
- Network allowlist in manifest defines allowed domains/IPs
- Platform-specific enforcement (network namespaces on Linux with eBPF/iptables)

#### 4. Secret Exposure
**Threat**: Secrets passed to process are logged, exposing them in plaintext.

**Mitigation**:
- Secrets passed via environment variables, never logged
- Audit logs redact secret names and values
- Configuration prevents accidental logging of sensitive data

#### 5. Supply Chain Attacks (Manifest/Bundle Tampering)
**Threat**: Registry serves corrupted or tampered manifest/bundle.

**Mitigation**:
- Mandatory SHA-256 digest validation of all artifacts
- Digest mismatch causes immediate rejection with clear error
- Cached artifacts validated before reuse

#### 6. Subprocess Escape
**Threat**: Process spawns subprocesses to escape sandbox restrictions.

**Mitigation**:
- Subprocess control via manifest declaration: `subprocess: true/false`
- Platform-specific enforcement (seccomp on Linux, process tree monitoring)
- Failed subprocess launches logged and audited

### Threats NOT Covered (Out of Scope)

#### 1. Kernel/Hardware Exploits
- No protection against kernel vulnerabilities or side-channel attacks (Spectre, Meltdown)
- No hypervisor-level isolation
- Requires kernel patching by system administrator

#### 2. Runtime Interpreter Vulnerabilities
- If MCP server uses Python 3.8 with CVE-2021-XXXXX, mcp-client cannot detect this
- Responsibility falls on:
  - Bundle maintainer to patch interpreter
  - System administrator to keep OS updated
  - Registry to scan bundles for known vulnerabilities

#### 3. Advanced Evasion Techniques
- Sophisticated fork bombs or resource-allocation loops may defeat limits
- Timing attacks cannot be prevented
- Covert channels (CPU cache, memory timing) are not blocked

#### 4. Windows Network Isolation
- Windows lacks native eBPF or netns equivalent
- Requires WFP drivers for network filtering
- Default-deny network not enforced on Windows (documented limitation)

#### 5. macOS Network/Filesystem Isolation
- macOS lacks network namespaces
- Filesystem sandboxing not robust without hypervisor
- Limited to rlimits and timeouts

#### 6. Registry Compromise
- If registry is hacked and serves signed artifacts, mcp-client trusts the digest
- Requires registry-level security (TLS, access controls)
- Audit logs can detect suspicious activity after the fact

## Security Invariants

These rules **MUST NEVER** be violated:

### 1. Mandatory Digest Validation
```
RULE: Before using any manifest or bundle, validate SHA-256 digest.
ACTION: Reject artifact if digest mismatch → exit with code 3.
```

### 2. No Plaintext Secret Logging
```
RULE: Secrets passed by name/reference, never log values.
ACTION: Audit logs must redact secret names/values.
CONFIG: Enable/disable secret logging via explicit config flag only.
```

### 3. Default-Deny Network
```
RULE: Network isolated by default (when OS supports it).
ACTION: Only allow network if manifest declares allowlist.
FALLBACK: Document limitation if OS cannot enforce (macOS, Windows).
```

### 4. Filesystem Isolation
```
RULE: Process writes only to assigned working dir + temp dir.
ACTION: Reject attempts to write to system directories.
FALLBACK: Use OS-level permissions as last resort.
```

### 5. Resource Limits Always Applied
```
RULE: CPU, memory, pids, fds limits enforced on all platforms.
ACTION: Terminate process if limits exceeded.
FALLBACK: Use timeout + kill if OS limit mechanisms unavailable.
```

### 6. Mandatory Audit Logging
```
RULE: Every execution logged (start, end, exit code, duration).
ACTION: Write to ~/.mcp/audit.log with structured format.
CONSTRAINT: Never skip audit in normal operation.
```

### 7. No Subprocess by Default
```
RULE: Subprocess disabled unless manifest declares subprocess: true.
ACTION: Block fork/exec attempts.
FALLBACK: Terminate process if subprocess detected.
```

### 8. No Privilege Escalation
```
RULE: Never execute as root/admin.
ACTION: Refuse execution if running as root.
RECOMMENDATION: Run mcp-client as regular user via sudo if needed.
```

## Platform-Specific Capabilities

### Linux

**Supported Security Mechanisms**:

1. **Resource Limits (rlimits)**
   - `RLIMIT_CPU`: CPU time in seconds
   - `RLIMIT_AS`: Virtual memory limit
   - `RLIMIT_NPROC`: Max process count
   - `RLIMIT_NOFILE`: Max open file descriptors
   - Status: ✅ Always available

2. **Control Groups (cgroups v2)**
   - `cpu.max`: CPU bandwidth throttling
   - `memory.max`: Memory hard limit
   - `pids.max`: PID limit
   - Status: ⚠️ Available if cgroups delegated or running as root
   - Fallback: Use rlimits if cgroups unavailable

3. **Network Namespaces**
   - Isolated network stack (eth0, lo only)
   - eBPF or iptables rules for allowlist enforcement
   - Status: ✅ Available if `CAP_NET_ADMIN` or running as root
   - Limitation: Non-root users may not have `CAP_NET_ADMIN`

4. **Seccomp (Secure Computing)**
   - Block dangerous syscalls (fork, execve if subprocess disabled)
   - Fine-grained syscall filtering
   - Status: ⚠️ Available if kernel supports BPF; disabled for compatibility

**Configuration**:
```yaml
executor:
  # These limits apply on Linux
  max_cpu: 1000       # milicores: 1000 = 1 full core
  max_memory: 512M
  max_pids: 10
  max_fds: 100
  default_timeout: 5m
```

**Diagnostic**: Run `mcp doctor` to check capabilities.

### macOS

**Supported Security Mechanisms**:

1. **Resource Limits (rlimits)**
   - Same as Linux
   - Status: ✅ Always available

2. **Timeouts and Process Termination**
   - Parent process monitors child
   - SIGTERM → SIGKILL after grace period
   - Status: ✅ Always available

3. **Filesystem Permissions**
   - Execute in temporary directory with restricted UNIX permissions
   - Rely on UNIX DAC (Discretionary Access Control)
   - Status: ✅ Available (but weak)

**NOT Available**:
- Network namespaces (no `unshare`)
- cgroups (no native support)
- Seccomp (no BPF equivalent)
- Sandbox API deprecated

**Limitations**:
- No network isolation: process can access any network interface
- Weak filesystem isolation: rely on UNIX permissions (user can bypass)
- CPU throttling limited to timeout + kill

**Configuration**:
```yaml
executor:
  # macOS only uses these
  max_memory: 512M        # soft limit via rlimit
  default_timeout: 5m
  # Note: max_cpu, max_pids, max_fds apply but less effective than Linux
```

**Warning**: For production use, run mcp-client in a macOS VM or container for better isolation.

### Windows

**Supported Security Mechanisms**:

1. **Job Objects**
   - Process group with shared resource limits
   - CPU, memory, process count limits
   - Child processes inherit restrictions
   - Status: ✅ Always available

2. **Timeouts and Termination**
   - Parent monitors child via Job Object
   - Automatic termination after timeout
   - Status: ✅ Always available

3. **NTFS Permissions**
   - File ACLs for directory access control
   - Execute in temporary directory
   - Status: ✅ Available (but weak)

**NOT Available**:
- Network namespaces (no WFP driver without admin)
- Seccomp equivalent (no BPF)
- VM-level isolation

**Limitations**:
- No network isolation without WFP drivers
- Weak filesystem isolation: rely on NTFS ACLs
- Subprocess restrictions limited to Job Object rules

**Configuration**:
```yaml
executor:
  # Windows uses Job Objects for these
  max_memory: 512M
  max_cpu: 1000         # affects scheduling, not strict limit
  default_timeout: 5m
  # Note: max_pids propagates to Job Object process limit
```

**Future Work**: Windows Sandbox API (requires Windows 10 Pro+) for stronger isolation.

## Digest Validation

### SHA-256 Enforcement

Every manifest and bundle **must** be validated before use:

```go
// Pseudocode
downloadedDigest := sha256(downloadedArtifact)
expectedDigest := registryResponse.digest
if downloadedDigest != expectedDigest {
    return Error("digest mismatch: expected %s, got %s", expectedDigest, downloadedDigest)
}
```

### Digest Format

- Supported: `sha256:` prefix (64 hex characters)
- Example: `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- Validation: Case-insensitive hex parsing, error on invalid format

### Cached Validation

- On-disk cached artifacts validated against stored digest
- Re-download if cached artifact fails validation
- Audit log records validation failures

## Environment Variable Filtering

### Allowlist Model

Only environment variables declared in manifest are passed to process:

```json
{
  "manifest": {
    "environment": {
      "allowed_names": [
        "LOG_LEVEL",
        "API_KEY"
      ],
      "deny_patterns": [
        "*SECRET*",
        "*PASSWORD*"
      ]
    }
  }
}
```

### Default Behavior

If manifest omits environment config:
- Only safe, non-sensitive vars passed (none by default, explicit allowlist required)
- Process gets minimal environment (PATH, HOME if safe)

### Redaction in Logs

- Environment variable names logged
- Values **never** logged
- Audit trail shows which vars were filtered

## Network Allowlists

### Manifest Declaration

```json
{
  "manifest": {
    "network": {
      "allowlist": [
        "api.example.com",
        "registry.example.com:443",
        "10.0.0.0/8",
        "2001:db8::/32"
      ]
    }
  }
}
```

### Enforcement Per Platform

| Platform | Mechanism | Status |
|----------|-----------|--------|
| Linux | eBPF/iptables rules | ✅ Enforced |
| macOS | pf rules (limited) | ⚠️ Best-effort |
| Windows | WFP driver (if installed) | ❌ Not enforced |

### Fallback

If enforcement not available:
- Warn user with clear message: "Network isolation not available on this platform"
- Document in `mcp doctor`
- Log warning in audit trail

## Filesystem Isolation

### Working Directory

Process executes with:
- CWD set to isolated working directory
- No write access to parent directories
- Read-only mounts for system directories (Linux only)

### Temporary Directory

Process can create files in:
- `$TMPDIR` / Windows temp directory
- Subdirectories cleaned up after process terminates

### Best-Effort Approach

- Linux: bind mounts + mount namespaces (strong)
- macOS: chroot-like workaround (weak, advisory only)
- Windows: directory ACLs (weak, advisory only)

## Audit Logging for Compliance

### Audit Log Format

```json
{
  "timestamp": "2026-01-18T10:30:00Z",
  "event": "start",
  "package": "acme/tool",
  "version": "1.2.3",
  "digest": "sha256:abc123...",
  "entrypoint": "/bin/mcp-server",
  "user": "alice",
  "exit_code": 0,
  "duration_ms": 5000,
  "limits": {
    "cpu_ms": 1000,
    "memory_mb": 512,
    "pids": 10,
    "fds": 100
  }
}
```

### Log Location

- File: `~/.mcp/audit.log`
- Permissions: `0600` (read/write owner only)
- Rotation: Configurable size/time based

### Compliance

- Suitable for:
  - Security incident investigation
  - Compliance audits (what ran, when, by whom)
  - Usage analytics (non-invasive)

- NOT suitable for:
  - Real-time monitoring (use SIEM integration if needed)
  - PII/sensitive data (never logged)

## Default-Deny Policies

### Network Default-Deny

```
If manifest.network.allowlist is empty:
  → No external connections allowed
  → Loopback (127.0.0.1, ::1) still accessible
Else:
  → Only allowlist + loopback allowed
```

### Subprocess Default-Deny

```
If manifest.subprocess is not set:
  → No child processes allowed
  → fork() / clone() rejected
Else if manifest.subprocess == true:
  → Child processes allowed (inherit limits)
  → fork bombs still limited by pids
```

### Environment Default-Deny

```
If manifest.environment is not set:
  → No env vars passed (empty environment except PATH/HOME)
Else:
  → Only allowlist vars passed
  → Deny patterns filtered out
```

## Known Limitations Per Platform

### Linux
- ✅ Comprehensive isolation available
- ⚠️ Requires proper capabilities/permissions for namespaces
- ℹ️ If running as non-root, some mechanisms limited

### macOS
- ❌ Network isolation NOT available (no netns)
- ❌ Filesystem strict isolation NOT available
- ✅ Resource limits (rlimits) available
- ℹ️ Recommended: Run in VM for untrusted code

### Windows
- ❌ Network isolation NOT available (unless WFP driver)
- ❌ Filesystem strict isolation NOT available
- ✅ Resource limits (Job Objects) available
- ℹ️ Recommended: Windows Sandbox for untrusted code (future work)

## Security Best Practices

1. **Keep mcp-client Updated**
   - Regularly update to get security fixes
   - Subscribe to security advisories

2. **Verify Package Authenticity**
   - Check digest against known-good values
   - Use private registries for sensitive packages
   - Review manifest before execution

3. **Minimal Permissions**
   - Run mcp-client as regular user, not root/admin
   - Grant only required network/filesystem access in manifest
   - Restrict environment variables to minimum necessary

4. **Audit Log Monitoring**
   - Rotate and archive `~/.mcp/audit.log` regularly
   - Monitor for unexpected packages/digests
   - Alert on repeated failures or resource limit hits

5. **Platform-Specific Hardening**
   - **Linux**: Enable cgroups, namespaces; use SELinux/AppArmor if available
   - **macOS**: Use VM, restrict resource access, consider macOS Sandbox
   - **Windows**: Use Windows Sandbox; enable code signing verification

6. **Registry Security**
   - Authenticate with strong credentials
   - Use HTTPS and verify TLS certificates
   - Monitor for unauthorized access
   - Implement registry-side scanning/attestation

## Reporting Security Issues

If you discover a security vulnerability in mcp-client:

1. **Do NOT** open a public GitHub issue
2. Email security details to: [security@example.com]
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Proposed fix (if available)
   - Timeline you prefer for disclosure

We aim to respond within 48 hours and release patches promptly.

---

**Last Updated**: 2026-01-18
**Document Version**: 1.0
