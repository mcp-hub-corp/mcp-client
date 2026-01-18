# MCP Manifest Skill

Expert knowledge for parsing, validating, and using MCP manifest files.

## Complete Manifest Schema

### Top-Level Structure

```json
{
  "schema_version": "1.0",
  "package": {
    "org": "string",
    "name": "string",
    "version": "string (semver)",
    "description": "string",
    "author": "string",
    "author_email": "string",
    "license": "string",
    "homepage": "string (URL)",
    "repository": "string (URL)"
  },
  "bundle": {
    "digest": "string (sha256:hex or sha512:hex)",
    "size_bytes": "integer"
  },
  "transport": "stdio | http",
  "entrypoints": {
    "platform-arch": {
      "command": "string",
      "args": ["string"]
    }
  },
  "permissions": {
    "network": {
      "allow": ["string"]
    },
    "environment": {
      "allow": ["string"],
      "secrets": ["string"]
    },
    "subprocess": "boolean",
    "filesystem": {
      "work_dir": "string",
      "tmp_dir": "string",
      "ro_paths": ["string"]
    }
  },
  "limits": {
    "cpu_millis": "integer",
    "memory_mb": "integer",
    "max_pids": "integer",
    "max_fds": "integer",
    "timeout_seconds": "integer"
  },
  "health_check": {
    "enabled": "boolean",
    "endpoint": "string (for HTTP transport)",
    "interval_seconds": "integer",
    "timeout_seconds": "integer"
  }
}
```

---

## Field Definitions

### `schema_version`
- Type: `string`
- Required: Yes
- Current value: `"1.0"`
- Purpose: Enables forward compatibility, allows parsing logic to evolve
- Example: `"1.0"`

### `package` Object
Contains package metadata.

**Fields:**
- `org` (required): Organization identifier
  - Pattern: `^[a-z0-9_-]{1,32}$`
  - Example: `"acme"`, `"security-mcp"`

- `name` (required): Package name
  - Pattern: `^[a-z0-9_-]{1,64}$`
  - Example: `"hello-world"`, `"api_gateway"`

- `version` (required): Semantic version
  - Pattern: `^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`
  - Examples: `"1.0.0"`, `"2.1.0-alpha.1"`, `"1.0.0+build.123"`

- `description` (optional): Human-readable description
  - Type: `string`
  - Max length: 1000 characters

- `author` (optional): Author name
  - Type: `string`
  - Max length: 256 characters

- `author_email` (optional): Author email
  - Pattern: RFC 5322 email format

- `license` (optional): SPDX license identifier
  - Examples: `"MIT"`, `"Apache-2.0"`, `"GPL-3.0-only"`, `"Proprietary"`

- `homepage` (optional): Project homepage URL
  - Pattern: Valid HTTPS URL

- `repository` (optional): Repository URL
  - Pattern: Valid HTTPS URL
  - Example: `"https://github.com/acme/hello-world"`

### `bundle` Object
Describes the executable bundle.

**Fields:**
- `digest` (required): Content-addressable hash
  - Format: `"sha256:<64-char-hex>"` or `"sha512:<128-char-hex>"`
  - Example: `"sha256:abc123def456..."`
  - Critical rule: MUST validate this digest against downloaded bundle

- `size_bytes` (required): Uncompressed size in bytes
  - Type: `integer`
  - Max: 100GB (100,000,000,000 bytes)
  - Used for storage quota checks

### `transport`
Communication protocol between launcher and server.

**Values:**
- `"stdio"`: Server reads from stdin, writes to stdout (JSON-RPC 2.0)
- `"http"`: Server exposes HTTP API on configurable port

**Rules:**
- STDIO is default and more secure (no network exposure)
- HTTP requires port allocation and firewall rules
- Port selection: use OS-assigned port (port 0) unless manifest specifies
- Cannot be changed per platform (uniform across entrypoints)

### `entrypoints` Object
Platform-specific command definitions.

**Key Format:** `"{platform}-{arch}"`
- Platforms: `linux`, `darwin` (macOS), `windows`
- Architectures: `amd64`, `arm64`, `386`
- Examples: `"linux-amd64"`, `"darwin-arm64"`, `"windows-amd64"`

**Fields per entrypoint:**
- `command` (required): Executable path relative to bundle root
  - Paths MUST use forward slashes (even on Windows)
  - Must be executable after extraction
  - Example: `"./bin/mcp-server"` or `"bin/server.exe"`

- `args` (required): Argument array
  - Type: `array of strings`
  - May be empty: `[]`
  - No shell interpretation (pass to execvp directly)
  - Example: `["--mode", "stdio", "--log-level", "debug"]`

**Selection Algorithm:**
```
1. Get current OS (linux, darwin, windows)
2. Get current architecture (amd64, arm64, 386)
3. Look for exact match: "{os}-{arch}"
4. Fallback to first available entrypoint (warn in logs)
5. If no entrypoints found, fail with error
```

**Platform Specifics:**

Linux:
- `linux-amd64` (most common)
- `linux-arm64` (Raspberry Pi, Cloud)
- `linux-386` (legacy, rare)

macOS:
- `darwin-arm64` (Apple Silicon)
- `darwin-amd64` (Intel Macs)

Windows:
- `windows-amd64` (standard)
- `windows-386` (legacy)
- `windows-arm64` (Surface Pro X)

### `permissions` Object
Security and resource access rules.

#### `network`
Controls outbound network access.

```json
{
  "network": {
    "allow": [
      "example.com",
      "*.api.example.com",
      "10.0.0.0/8",
      "192.168.1.1:8080",
      "[::1]:9000"
    ]
  }
}
```

**Rules:**
- Default: DENY all (if field missing or empty)
- Patterns supported:
  - Domain: `example.com` (exact match)
  - Wildcard domain: `*.api.example.com` (single-label wildcard)
  - IPv4 CIDR: `10.0.0.0/8`
  - IPv6 CIDR: `2001:db8::/32`
  - Port-specific: `example.com:8080`, `[::1]:9000`
  - Special: `localhost`, `127.0.0.1`, `::1` for loopback

**Implementation:**
```go
type NetworkPermission struct {
    Allow []string `json:"allow"` // Domain allowlist
}

func (n *NetworkPermission) IsAllowed(host, port string) bool {
    // Parse host/port
    // Check against patterns in Allow
    // Return true if match found, false otherwise
}
```

**Linux Implementation:**
- Use network namespaces + iptables or eBPF for enforcement
- Default-deny policy, whitelist specific targets
- Document that non-root may have limitations

**macOS/Windows:**
- Limited kernel support
- Document as "best effort" / "advisory"
- Cannot guarantee enforcement

#### `environment`
Controls environment variables passed to process.

```json
{
  "environment": {
    "allow": ["HOME", "PATH", "USER"],
    "secrets": ["API_KEY", "DB_PASSWORD"]
  }
}
```

**Rules:**
- `allow`: List of environment variable names to pass through
- `secrets`: List of secret names to inject (values from config/external)
- Default: EMPTY (no env vars passed if missing)
- Never log secret values (log `<redacted>` instead)

**Important:** Secrets are passed by NAME, not VALUE. Example:
```bash
# In config: secrets.yaml
API_KEY: "my-secret-key"

# In manifest:
"secrets": ["API_KEY"]

# Launcher injects:
export API_KEY=my-secret-key
# (value never appears in logs or configs)
```

#### `subprocess`
Controls ability to spawn child processes.

```json
{
  "subprocess": true  // or false
}
```

**Behavior:**
- `false` (default): Restrict fork/exec syscalls (Linux seccomp)
- `true`: Allow unrestricted subprocess spawning
- On macOS/Windows: Document as advisory only

#### `filesystem`
Filesystem access boundaries.

```json
{
  "filesystem": {
    "work_dir": "/tmp/mcp-acme-hello",
    "tmp_dir": "/tmp/mcp-acme-hello/tmp",
    "ro_paths": ["/etc/hosts", "/etc/ssl/certs"]
  }
}
```

**Fields:**
- `work_dir`: Working directory for the process
  - Must be absolute path or relative to launcher's work dir
  - Created if doesn't exist
  - Only path where process can write

- `tmp_dir`: Temporary directory (Linux: tmpfs, others: regular tmpdir)
  - Must be within work_dir
  - Environment variable: `TMPDIR=/tmp/mcp-acme-hello/tmp`

- `ro_paths`: Read-only file/directory paths
  - Process can read but not modify
  - Enforce via bind mounts (Linux) or chroot (macOS approximation)

### `limits` Object
Resource constraints.

```json
{
  "limits": {
    "cpu_millis": 1000,      // 1 CPU core per second
    "memory_mb": 512,        // 512 MB RAM
    "max_pids": 10,          // Max 10 processes
    "max_fds": 100,          // Max 100 file descriptors
    "timeout_seconds": 300   // 5 minute timeout
  }
}
```

**Fields:**
- `cpu_millis` (optional): CPU throttle in milliseconds per second
  - Range: 10-1000000
  - Default: 1000 (no throttle)
  - Examples:
    - 500: 50% of 1 CPU
    - 2000: 2 CPUs
    - 10: 1% of 1 CPU

- `memory_mb` (optional): RAM limit in MB
  - Range: 32-102400
  - Default: 512 MB
  - Enforced: OOM killer if exceeded

- `max_pids` (optional): Maximum process count
  - Range: 1-10000
  - Default: 10
  - Includes process itself + all children

- `max_fds` (optional): Maximum open file descriptors
  - Range: 64-262144
  - Default: 100
  - Includes stdin/stdout/stderr

- `timeout_seconds` (optional): Process lifetime limit
  - Range: 1-86400 (up to 24 hours)
  - Default: 300 (5 minutes)
  - Action: SIGTERM, then SIGKILL if not terminated

### `health_check` Object
Health monitoring for HTTP transport.

```json
{
  "health_check": {
    "enabled": true,
    "endpoint": "/health",
    "interval_seconds": 10,
    "timeout_seconds": 5
  }
}
```

**Fields:**
- `enabled`: Enable health checks (default: false)
- `endpoint`: HTTP GET path to check (e.g., `/health`, `/healthz`)
- `interval_seconds`: Check frequency (default: 10)
- `timeout_seconds`: Max wait for response (default: 5)

**HTTP Transport Only:**
- Not applicable to STDIO transport
- Launcher periodically GETs the endpoint
- Expected response: 2xx status code
- On failure: log warning, may restart process (optional)

---

## Validation Rules

### Required Field Validation

```go
func (m *Manifest) Validate() error {
    if m.SchemaVersion == "" {
        return errors.New("schema_version is required")
    }
    if m.SchemaVersion != "1.0" {
        return fmt.Errorf("unsupported schema version: %s", m.SchemaVersion)
    }

    if m.Package.Org == "" {
        return errors.New("package.org is required")
    }
    if m.Package.Name == "" {
        return errors.New("package.name is required")
    }
    if m.Package.Version == "" {
        return errors.New("package.version is required")
    }

    if m.Bundle.Digest == "" {
        return errors.New("bundle.digest is required")
    }
    if m.Bundle.SizeBytes == 0 {
        return errors.New("bundle.size_bytes must be > 0")
    }

    if m.Transport == "" {
        m.Transport = "stdio"  // Default
    } else if m.Transport != "stdio" && m.Transport != "http" {
        return fmt.Errorf("invalid transport: %s", m.Transport)
    }

    if len(m.Entrypoints) == 0 {
        return errors.New("entrypoints must have at least one entry")
    }

    return nil
}
```

### Package ID Format Validation

**Pattern:** `{org}/{name}`
- org: `^[a-z0-9_-]{1,32}$`
- name: `^[a-z0-9_-]{1,64}$`

```go
func ValidatePackageID(org, name string) error {
    orgPattern := regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
    namePattern := regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

    if !orgPattern.MatchString(org) {
        return fmt.Errorf("invalid org: %s (must match pattern)", org)
    }
    if !namePattern.MatchString(name) {
        return fmt.Errorf("invalid name: %s (must match pattern)", name)
    }

    return nil
}

// Canonical package ID string
func (m *Manifest) PackageID() string {
    return fmt.Sprintf("%s/%s", m.Package.Org, m.Package.Name)
}
```

### Semantic Version Validation

```go
import "github.com/Masterminds/semver/v3"

func ValidateSemver(version string) error {
    _, err := semver.NewVersion(version)
    return err
}

// Example valid versions:
// "1.0.0"
// "2.1.0-alpha.1"
// "1.0.0+build.123"
// "0.0.1"
```

### Digest Format Validation

```go
func ValidateDigestFormat(digest string) error {
    parts := strings.Split(digest, ":")
    if len(parts) != 2 {
        return fmt.Errorf("digest must be algorithm:hash, got: %s", digest)
    }

    algo, hash := parts[0], parts[1]

    switch algo {
    case "sha256":
        if len(hash) != 64 {
            return fmt.Errorf("sha256 hash must be 64 hex chars, got: %d", len(hash))
        }
        if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(hash) {
            return fmt.Errorf("sha256 hash must be valid hex")
        }

    case "sha512":
        if len(hash) != 128 {
            return fmt.Errorf("sha512 hash must be 128 hex chars, got: %d", len(hash))
        }
        if !regexp.MustCompile(`^[a-f0-9]{128}$`).MatchString(hash) {
            return fmt.Errorf("sha512 hash must be valid hex")
        }

    default:
        return fmt.Errorf("unsupported digest algorithm: %s", algo)
    }

    return nil
}
```

### Entrypoint Validation

```go
func (m *Manifest) ValidateEntrypoints() error {
    validPlatforms := map[string]bool{
        "linux": true, "darwin": true, "windows": true,
    }
    validArchs := map[string]bool{
        "amd64": true, "arm64": true, "386": true,
    }

    for platformArch := range m.Entrypoints {
        parts := strings.Split(platformArch, "-")
        if len(parts) != 2 {
            return fmt.Errorf("invalid entrypoint key: %s (must be platform-arch)", platformArch)
        }

        platform, arch := parts[0], parts[1]

        if !validPlatforms[platform] {
            return fmt.Errorf("unsupported platform: %s", platform)
        }
        if !validArchs[arch] {
            return fmt.Errorf("unsupported architecture: %s", arch)
        }

        ep := m.Entrypoints[platformArch]
        if ep.Command == "" {
            return fmt.Errorf("entrypoint %s: command is required", platformArch)
        }
        if !strings.HasPrefix(ep.Command, "./") && !strings.HasPrefix(ep.Command, "/") {
            return fmt.Errorf("entrypoint %s: command must start with ./ or /", platformArch)
        }
    }

    return nil
}
```

### Manifest-to-Bundle Coherence

Validate that bundle contents match manifest description.

```go
func ValidateManifestBundleCoherence(manifest *Manifest, bundleExtracted string) error {
    // 1. Check all entrypoint commands exist and are executable
    for platformArch, ep := range manifest.Entrypoints {
        cmdPath := filepath.Join(bundleExtracted, ep.Command)
        if _, err := os.Stat(cmdPath); err != nil {
            return fmt.Errorf("entrypoint %s: command not found: %s", platformArch, ep.Command)
        }

        // Check executable bit
        info, _ := os.Stat(cmdPath)
        if info.Mode()&0111 == 0 {
            return fmt.Errorf("entrypoint %s: command not executable: %s", platformArch, ep.Command)
        }
    }

    // 2. Validate permissions filesystem paths exist (if specified)
    if manifest.Permissions.Filesystem.RO != nil {
        for _, path := range manifest.Permissions.Filesystem.RO {
            // Can be absolute or relative - log warning if absolute
            if strings.HasPrefix(path, "/") {
                fmt.Printf("[WARN] Read-only path is absolute: %s (may not be available)\n", path)
            }
        }
    }

    return nil
}
```

---

## Entrypoint Selection Algorithm

### Implementation

```go
func (m *Manifest) SelectEntrypoint(goos, goarch string) (*Entrypoint, error) {
    // Normalize values
    goos = strings.ToLower(goos)
    goarch = strings.ToLower(goarch)

    // Map go runtime values to manifest values
    platformMap := map[string]string{
        "linux":   "linux",
        "darwin":  "darwin",
        "windows": "windows",
    }
    archMap := map[string]string{
        "amd64": "amd64",
        "arm64": "arm64",
        "386":   "386",
    }

    platform, ok := platformMap[goos]
    if !ok {
        return nil, fmt.Errorf("unsupported OS: %s", goos)
    }
    arch, ok := archMap[goarch]
    if !ok {
        return nil, fmt.Errorf("unsupported architecture: %s", goarch)
    }

    // Try exact match
    key := fmt.Sprintf("%s-%s", platform, arch)
    if ep, ok := m.Entrypoints[key]; ok {
        return &ep, nil
    }

    // Fallback: use first available (with warning)
    if len(m.Entrypoints) > 0 {
        for fallbackKey, ep := range m.Entrypoints {
            fmt.Printf("[WARN] No exact entrypoint for %s, using %s\n", key, fallbackKey)
            return &ep, nil
        }
    }

    return nil, fmt.Errorf("no entrypoint found for %s-%s", platform, arch)
}
```

### Usage

```go
// In executor setup
entrypoint, err := manifest.SelectEntrypoint(runtime.GOOS, runtime.GOARCH)
if err != nil {
    return fmt.Errorf("failed to select entrypoint: %w", err)
}

cmd := exec.Command(entrypoint.Command, entrypoint.Args...)
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
cmd.Stdin = os.Stdin
```

---

## Common Manifest Mistakes

### Mistake 1: Invalid Transport Value

**Wrong:**
```json
{
  "transport": "websocket"
}
```

**Fix:**
```json
{
  "transport": "http"
}
```

**Lesson:** Only `stdio` and `http` are valid. Default is `stdio`.

---

### Mistake 2: Missing Entrypoint for Current Platform

**Wrong:**
```json
{
  "entrypoints": {
    "linux-amd64": { "command": "./bin/server", "args": [] }
  }
}
```
(Running on macOS arm64 - will fail)

**Fix:**
```json
{
  "entrypoints": {
    "linux-amd64": { "command": "./bin/server", "args": [] },
    "darwin-arm64": { "command": "./bin/server-mac", "args": [] }
  }
}
```

**Lesson:** Provide entrypoints for all target platforms.

---

### Mistake 3: Invalid Digest

**Wrong:**
```json
{
  "bundle": {
    "digest": "abc123"
  }
}
```

**Fix:**
```json
{
  "bundle": {
    "digest": "sha256:abc123def456..."
  }
}
```

**Lesson:** Digest must be `algorithm:hash` format with full hex hash.

---

### Mistake 4: Command Path Missing "./", "/" Prefix

**Wrong:**
```json
{
  "entrypoints": {
    "linux-amd64": {
      "command": "bin/server",
      "args": []
    }
  }
}
```

**Fix:**
```json
{
  "entrypoints": {
    "linux-amd64": {
      "command": "./bin/server",
      "args": []
    }
  }
}
```

**Lesson:** Commands must be explicit paths, not resolved from PATH.

---

### Mistake 5: Absolute Paths in Entrypoints

**Wrong:**
```json
{
  "entrypoints": {
    "linux-amd64": {
      "command": "/usr/bin/python3",
      "args": ["./script.py"]
    }
  }
}
```

**Fix:**
```json
{
  "entrypoints": {
    "linux-amd64": {
      "command": "./bin/server",
      "args": []
    }
  }
}
```

**Lesson:** Commands must be relative to bundle root (use `./ prefix`). Absolute paths will fail in sandbox.

---

### Mistake 6: Invalid Semver

**Wrong:**
```json
{
  "package": {
    "version": "1.0"
  }
}
```

**Fix:**
```json
{
  "package": {
    "version": "1.0.0"
  }
}
```

**Lesson:** Semantic versioning requires MAJOR.MINOR.PATCH format.

---

### Mistake 7: Network Allowlist Too Permissive

**Wrong:**
```json
{
  "permissions": {
    "network": {
      "allow": ["*"]
    }
  }
}
```

**Fix:**
```json
{
  "permissions": {
    "network": {
      "allow": ["api.example.com", "cdn.example.com"]
    }
  }
}
```

**Lesson:** Be specific with network allowlist. Wildcard `*` defeats security.

---

### Mistake 8: Logging Secret Values

**Wrong:**
```json
{
  "permissions": {
    "environment": {
      "secrets": ["API_KEY"]
    }
  }
}
```
Then in code: `log.Printf("API_KEY=%s", os.Getenv("API_KEY"))`

**Fix:**
```go
// Never log secret values
apiKey := os.Getenv("API_KEY")
log.Printf("API_KEY=<redacted> (length: %d)", len(apiKey))
```

**Lesson:** Secrets are passed by name only. Never log their values.

---

## Example Valid Manifests

### Simple STDIO Server

```json
{
  "schema_version": "1.0",
  "package": {
    "org": "acme",
    "name": "hello-world",
    "version": "1.0.0",
    "description": "Hello World MCP Server",
    "author": "ACME Corp",
    "license": "MIT"
  },
  "bundle": {
    "digest": "sha256:abc123def456...",
    "size_bytes": 5242880
  },
  "transport": "stdio",
  "entrypoints": {
    "linux-amd64": {
      "command": "./bin/hello-world",
      "args": ["--mode", "stdio"]
    },
    "darwin-arm64": {
      "command": "./bin/hello-world-mac",
      "args": ["--mode", "stdio"]
    },
    "windows-amd64": {
      "command": "./bin/hello-world.exe",
      "args": []
    }
  },
  "permissions": {
    "network": {
      "allow": []
    },
    "environment": {
      "allow": ["PATH", "HOME"]
    },
    "subprocess": false,
    "filesystem": {
      "work_dir": "/tmp/mcp-acme-hello",
      "tmp_dir": "/tmp/mcp-acme-hello/tmp"
    }
  },
  "limits": {
    "cpu_millis": 1000,
    "memory_mb": 256,
    "max_pids": 5,
    "max_fds": 100,
    "timeout_seconds": 300
  }
}
```

### HTTP Server with Health Check

```json
{
  "schema_version": "1.0",
  "package": {
    "org": "tools",
    "name": "api-gateway",
    "version": "2.0.0",
    "description": "API Gateway Server",
    "author": "Tools Team",
    "license": "Apache-2.0",
    "repository": "https://github.com/tools/api-gateway"
  },
  "bundle": {
    "digest": "sha256:def456abc123...",
    "size_bytes": 25165824
  },
  "transport": "http",
  "entrypoints": {
    "linux-amd64": {
      "command": "./bin/gateway",
      "args": ["--port", "0", "--log-level", "info"]
    }
  },
  "permissions": {
    "network": {
      "allow": [
        "api.internal.com",
        "*.cdn.example.com",
        "10.0.0.0/8",
        "192.168.0.0/16"
      ]
    },
    "environment": {
      "allow": ["PATH", "HOME", "LANG"],
      "secrets": ["DATABASE_URL", "API_TOKEN"]
    },
    "subprocess": true,
    "filesystem": {
      "work_dir": "/tmp/mcp-tools-gateway",
      "tmp_dir": "/tmp/mcp-tools-gateway/tmp",
      "ro_paths": ["/etc/ssl/certs"]
    }
  },
  "limits": {
    "cpu_millis": 2000,
    "memory_mb": 1024,
    "max_pids": 20,
    "max_fds": 200,
    "timeout_seconds": 1800
  },
  "health_check": {
    "enabled": true,
    "endpoint": "/healthz",
    "interval_seconds": 10,
    "timeout_seconds": 5
  }
}
```

### Minimal Manifest

```json
{
  "schema_version": "1.0",
  "package": {
    "org": "test",
    "name": "minimal",
    "version": "0.0.1"
  },
  "bundle": {
    "digest": "sha256:abc123def456...",
    "size_bytes": 1048576
  },
  "transport": "stdio",
  "entrypoints": {
    "linux-amd64": {
      "command": "./server",
      "args": []
    }
  }
}
```
(Defaults: no network, no env vars, no subprocess, default resource limits)

---

## Testing Patterns

### Unit Test for Validation

```go
func TestValidateManifest(t *testing.T) {
    tests := []struct {
        name      string
        manifest  *Manifest
        wantError bool
        errorMsg  string
    }{
        {
            name: "valid manifest",
            manifest: &Manifest{
                SchemaVersion: "1.0",
                Package: Package{
                    Org:     "test",
                    Name:    "pkg",
                    Version: "1.0.0",
                },
                Bundle: Bundle{
                    Digest:     "sha256:abc123",
                    SizeBytes:  1024,
                },
                Transport: "stdio",
                Entrypoints: map[string]Entrypoint{
                    "linux-amd64": {
                        Command: "./bin/server",
                        Args:    []string{},
                    },
                },
            },
            wantError: false,
        },
        {
            name: "missing schema_version",
            manifest: &Manifest{
                Package: Package{
                    Org:     "test",
                    Name:    "pkg",
                    Version: "1.0.0",
                },
            },
            wantError: true,
            errorMsg:  "schema_version is required",
        },
        {
            name: "invalid transport",
            manifest: &Manifest{
                SchemaVersion: "1.0",
                Package: Package{
                    Org:     "test",
                    Name:    "pkg",
                    Version: "1.0.0",
                },
                Transport: "websocket",
            },
            wantError: true,
            errorMsg:  "invalid transport",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.manifest.Validate()
            if (err != nil) != tt.wantError {
                t.Errorf("wantError %v, got %v", tt.wantError, err)
            }
            if tt.wantError && !strings.Contains(err.Error(), tt.errorMsg) {
                t.Errorf("error message %q should contain %q", err, tt.errorMsg)
            }
        })
    }
}
```

### Test Entrypoint Selection

```go
func TestSelectEntrypoint(t *testing.T) {
    m := &Manifest{
        Entrypoints: map[string]Entrypoint{
            "linux-amd64": {Command: "./bin/linux-amd64", Args: []string{}},
            "darwin-arm64": {Command: "./bin/darwin-arm64", Args: []string{}},
        },
    }

    tests := []struct {
        goos   string
        goarch string
        want   string
    }{
        {"linux", "amd64", "./bin/linux-amd64"},
        {"darwin", "arm64", "./bin/darwin-arm64"},
    }

    for _, tt := range tests {
        ep, err := m.SelectEntrypoint(tt.goos, tt.goarch)
        if err != nil {
            t.Fatal(err)
        }
        if ep.Command != tt.want {
            t.Errorf("SelectEntrypoint(%s, %s) = %s, want %s", tt.goos, tt.goarch, ep.Command, tt.want)
        }
    }
}
```

### JSON Parsing Test

```go
func TestParseManifest(t *testing.T) {
    jsonData := `{
        "schema_version": "1.0",
        "package": {
            "org": "acme",
            "name": "test",
            "version": "1.0.0"
        },
        "bundle": {
            "digest": "sha256:abc123",
            "size_bytes": 1024
        },
        "transport": "stdio",
        "entrypoints": {
            "linux-amd64": {
                "command": "./bin/server",
                "args": []
            }
        }
    }`

    var m Manifest
    if err := json.Unmarshal([]byte(jsonData), &m); err != nil {
        t.Fatal(err)
    }

    if m.Package.Org != "acme" {
        t.Errorf("org = %s, want acme", m.Package.Org)
    }
    if m.Transport != "stdio" {
        t.Errorf("transport = %s, want stdio", m.Transport)
    }
}
```

---

## File I/O Patterns

### Reading Manifest from File

```go
func ReadManifest(path string) (*Manifest, error) {
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read manifest: %w", err)
    }

    var m Manifest
    if err := json.Unmarshal(data, &m); err != nil {
        return nil, fmt.Errorf("failed to parse manifest JSON: %w", err)
    }

    if err := m.Validate(); err != nil {
        return nil, fmt.Errorf("manifest validation failed: %w", err)
    }

    return &m, nil
}
```

### Extracting from Bundle

```go
func ExtractManifestFromBundle(bundlePath string) (*Manifest, error) {
    // Assume bundle is tar.gz
    f, err := os.Open(bundlePath)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    gr, err := gzip.NewReader(f)
    if err != nil {
        return nil, err
    }
    defer gr.Close()

    tr := tar.NewReader(gr)

    for {
        hdr, err := tr.Next()
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, err
        }

        // Look for manifest.json in bundle root
        if hdr.Name == "manifest.json" {
            var m Manifest
            if err := json.NewDecoder(tr).Decode(&m); err != nil {
                return nil, err
            }
            return &m, nil
        }
    }

    return nil, errors.New("manifest.json not found in bundle")
}
```
