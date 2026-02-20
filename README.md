<p align="center">
  <h1 align="center">mcp</h1>
  <p align="center">
    <strong>The secure launcher for MCP servers</strong>
  </p>
  <p align="center">
    Download, validate, sandbox, and execute MCP servers — with integrity checks, resource limits, and audit logging built in.
  </p>
  <p align="center">
    <a href="https://github.com/security-mcp/mcp-client/actions"><img src="https://github.com/security-mcp/mcp-client/workflows/CI/badge.svg" alt="CI"></a>
    <a href="https://goreportcard.com/report/github.com/security-mcp/mcp-client"><img src="https://goreportcard.com/badge/github.com/security-mcp/mcp-client" alt="Go Report Card"></a>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
    <a href="go.mod"><img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white" alt="Go Version"></a>
    <a href="https://github.com/security-mcp/mcp-client/releases"><img src="https://img.shields.io/github/v/release/security-mcp/mcp-client?color=orange" alt="Release"></a>
  </p>
</p>

---

## The problem

Today, running an MCP server means trusting it blindly:

```bash
# With uvx or npx, you're running arbitrary code with full system access
uvx some-mcp-server
npx @someone/mcp-tool
```

No integrity checks. No resource limits. No sandboxing. No audit trail. The MCP server gets the same permissions as your user account — full access to your filesystem, network, and environment variables. If the package is compromised, you won't know until it's too late.

## The solution

**`mcp`** adds a trust layer between you and MCP servers:

```bash
# Validated, sandboxed, audited execution
mcp run acme/hello-world@1.2.3
```

Every package is **integrity-verified** (SHA-256), **sandboxed** (resource limits + process isolation), and **audited** (structured JSON logs). You know exactly what you're running, what it can access, and what it did.

## Why `mcp` over `uvx` / `npx`?

| | `uvx` / `npx` | `mcp` |
|---|---|---|
| **Integrity** | None. Runs whatever is downloaded | SHA-256 digest validation on every manifest and bundle |
| **Sandboxing** | None. Full system access | Process isolation with CPU, memory, PID, and FD limits |
| **Network** | Unrestricted | Default-deny with allowlists (Linux) |
| **Filesystem** | Full access | Confined to working directory (Linux) |
| **Subprocesses** | Unrestricted | Blocked unless explicitly declared |
| **Secrets** | Visible in env/logs | Redacted from all logs, passed by reference |
| **Audit trail** | None | Structured JSON logs of every execution |
| **Certification** | None | 4-level certification system (0-3) |
| **Cache** | Partial | Content-addressable with SHA-256 keying |
| **Policy enforcement** | None | Configurable minimum certification, origin filtering |

## Quick start

```bash
# Install
go install github.com/security-mcp/mcp-client/cmd/mcp@latest

# Check what your system supports
mcp doctor

# Run an MCP server
mcp run acme/hello-world@1.2.3
```

## Installation

### Pre-built binaries

Download from [GitHub Releases](https://github.com/security-mcp/mcp-client/releases):

```bash
# Linux (amd64)
curl -sSL https://github.com/security-mcp/mcp-client/releases/latest/download/mcp_linux_amd64.tar.gz | tar xz
sudo mv mcp /usr/local/bin/

# Linux (arm64)
curl -sSL https://github.com/security-mcp/mcp-client/releases/latest/download/mcp_linux_arm64.tar.gz | tar xz
sudo mv mcp /usr/local/bin/

# macOS (Apple Silicon)
curl -sSL https://github.com/security-mcp/mcp-client/releases/latest/download/mcp_darwin_arm64.tar.gz | tar xz
sudo mv mcp /usr/local/bin/

# macOS (Intel)
curl -sSL https://github.com/security-mcp/mcp-client/releases/latest/download/mcp_darwin_amd64.tar.gz | tar xz
sudo mv mcp /usr/local/bin/
```

### From source

Requires Go 1.24+:

```bash
go install github.com/security-mcp/mcp-client/cmd/mcp@latest
```

Or clone and build:

```bash
git clone https://github.com/security-mcp/mcp-client.git
cd mcp-client
make build    # binary at ./mcp
make install  # installs to $GOPATH/bin
```

### Docker

```bash
docker run --rm -it ghcr.io/security-mcp/mcp-client run acme/tool@1.0.0
```

### Verify installation

```bash
mcp --version
mcp doctor      # shows available security features
```

## Usage

### Run an MCP server

```bash
# By version
mcp run acme/tool@1.2.3

# Latest version
mcp run acme/tool@latest

# By content digest
mcp run acme/tool@sha256:a1b2c3...

# With timeout and env vars
mcp run acme/tool@1.0.0 --timeout 10m --env API_KEY=secret

# Force re-download (skip cache)
mcp run acme/tool@1.0.0 --no-cache
```

### Pre-download packages

```bash
# Pull without executing — useful for CI/CD warm-up
mcp pull acme/tool@1.2.3

# Subsequent runs are instant (served from cache)
mcp run acme/tool@1.2.3
```

### Publish a package

```bash
# Authenticate first
mcp login --token YOUR_TOKEN

# Push to the hub
mcp push acme/my-tool@1.0.0 --source ./dist
```

### Inspect a package

```bash
mcp info acme/tool@1.2.3          # human-readable
mcp info acme/tool@1.2.3 --json   # machine-readable
```

### Manage cache

```bash
mcp cache ls                      # list cached artifacts
mcp cache ls --json               # JSON output
mcp cache rm sha256:abc123...     # remove specific artifact
mcp cache rm --all                # clear everything
```

### Authentication

```bash
mcp login --token YOUR_TOKEN      # store credentials
mcp logout                        # remove credentials

# Or use environment variables
export MCP_REGISTRY_TOKEN=YOUR_TOKEN
mcp run acme/tool@1.0.0
```

### Diagnose system capabilities

```bash
mcp doctor
```

Shows which security features are available on your platform: cgroups, namespaces, seccomp, Landlock, and more.

## Configuration

Create `~/.mcp/config.yaml`:

```yaml
# Registry connection
registry:
  url: https://registry.mcp-hub.info
  timeout: 30s

# Local cache
cache:
  dir: ~/.mcp/cache
  max_size: 10GB
  ttl: 720h          # 30 days

# Execution defaults
executor:
  default_timeout: 5m
  max_cpu: 1000       # millicores (1000 = 1 core)
  max_memory: 512M
  max_pids: 10
  max_fds: 100

# Security policies
security:
  network:
    default_deny: true
  subprocess:
    allow: false

# Policy enforcement
policy:
  min_cert_level: 1             # minimum certification level (0-3)
  cert_enforcement: strict      # strict | warn | disabled
  allowed_origins:              # empty = allow all
    - official
    - verified

# Audit logging
audit:
  enabled: true
  log_file: ~/.mcp/audit.log
  format: json
```

**Configuration precedence:** CLI flags > environment variables > config file

Environment variables use the `MCP_` prefix:

```bash
export MCP_REGISTRY_URL=https://custom-registry.com
export MCP_REGISTRY_TOKEN=secret
export MCP_CACHE_DIR=/custom/cache
export MCP_LOG_LEVEL=debug
```

See [`docs/config.example.yaml`](./docs/config.example.yaml) for all available options.

## Security model

`mcp` implements **defense-in-depth** with multiple security layers:

### Integrity verification

Every manifest and bundle is validated against its SHA-256 digest before use. Digests are immutable — a package reference always resolves to the same content. This prevents supply-chain attacks, rollback attacks, and tampering.

### Process sandboxing

MCP servers run inside lightweight process-level sandboxes with:

- **CPU limits** — prevent crypto-mining and resource exhaustion
- **Memory limits** — prevent OOM conditions on the host
- **PID limits** — prevent fork bombs
- **File descriptor limits** — prevent resource exhaustion
- **Network isolation** — default-deny with manifest-controlled allowlists (Linux)
- **Filesystem confinement** — restricted to working directory (Linux)
- **Subprocess control** — blocked unless the manifest explicitly declares permission

Resource limits are **mandatory** and **cannot be disabled**.

### Certification levels

Packages are assigned a certification level (0-3) based on automated security analysis:

| Level | Name | What it means |
|-------|------|---------------|
| 0 | Integrity Verified | Digest and schema validation passed |
| 1 | Static Verified | Automated analysis score >= 60 |
| 2 | Security Certified | Full analysis score >= 80, evidence available |
| 3 | Runtime Certified | Dynamic analysis passed (future) |

You can enforce a minimum certification level in your config:

```yaml
policy:
  min_cert_level: 1
  cert_enforcement: strict   # block packages below this level
```

### Audit logging

Every execution is logged as structured JSON with:
- Package reference and digest
- Applied resource limits
- Execution duration and exit code
- All secrets redacted automatically

### What `mcp` does NOT protect against

- Kernel exploits or hardware side-channels
- Attacks that require VM-level isolation
- macOS/Windows sandbox bypasses (see Platform Support below)

See [`docs/SECURITY.md`](./docs/SECURITY.md) for the full threat model.

## Platform support

| Feature | Linux | macOS | Windows |
|---------|:-----:|:-----:|:-------:|
| CPU / Memory / PID limits | cgroups v2 + rlimits | rlimits | Job Objects |
| Network isolation | namespaces | — | — |
| Filesystem isolation | Landlock + bind mounts | — | — |
| Subprocess control | seccomp | limited | — |
| Audit logging | full | full | full |
| **Production ready** | **Yes** | **No** | **No** |

> **Important:** macOS and Windows sandboxes have known limitations. Resource limits on child processes are not reliably enforced. For production workloads with untrusted MCP servers, use **Linux with cgroups** or run inside a **Docker container**.

`mcp doctor` reports exactly which capabilities are available on your system.

## Architecture

```
                  ┌──────────────┐
                  │   mcp CLI    │
                  └──────┬───────┘
                         │
              ┌──────────┼──────────┐
              ▼          ▼          ▼
        ┌──────────┐ ┌────────┐ ┌────────┐
        │ Registry │ │ Cache  │ │ Policy │
        │  Client  │ │ Store  │ │ Engine │
        └────┬─────┘ └───┬────┘ └───┬────┘
             │           │          │
             ▼           ▼          ▼
        ┌──────────────────────────────┐
        │       Executor + Sandbox     │
        │  (platform-specific isolation)│
        └──────────────┬───────────────┘
                       │
                       ▼
                 ┌────────────┐
                 │ MCP Server │
                 │  (STDIO)   │
                 └────────────┘
```

**Flow:** resolve package → download & validate → check policy → apply sandbox → execute → audit log

```
internal/
├── cli/         # Cobra command handlers (9 commands)
├── config/      # Configuration loading (YAML + env + flags)
├── registry/    # Registry API client with auth & retries
├── manifest/    # MCP manifest parsing and validation
├── cache/       # Content-addressable SHA-256 cache
├── policy/      # Security policy & resource limits
├── executor/    # Process execution with sandbox
├── sandbox/     # Platform-specific isolation
│   ├── linux.go       # cgroups, namespaces, seccomp, Landlock
│   ├── darwin.go      # rlimits, Seatbelt (limited)
│   └── windows.go     # Job Objects, integrity levels
├── audit/       # Structured JSON audit logging
├── hub/         # Hub API client (push workflow)
└── packaging/   # Bundle creation with security checks
```

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/OVERVIEW.md`](./docs/OVERVIEW.md) | Architecture and concepts |
| [`docs/SECURITY.md`](./docs/SECURITY.md) | Threat model and security invariants |
| [`docs/EXAMPLES.md`](./docs/EXAMPLES.md) | Usage examples and CI/CD integration |
| [`docs/LINUX_SANDBOX.md`](./docs/LINUX_SANDBOX.md) | Linux sandbox deep dive |
| [`docs/MACOS_SANDBOX.md`](./docs/MACOS_SANDBOX.md) | macOS capabilities and limitations |
| [`docs/WINDOWS_SANDBOX.md`](./docs/WINDOWS_SANDBOX.md) | Windows sandbox details |
| [`docs/CERT_LEVEL_POLICY.md`](./docs/CERT_LEVEL_POLICY.md) | Certification level enforcement |
| [`docs/PUSH.md`](./docs/PUSH.md) | Package publishing guide |
| [`docs/REGISTRY-CONTRACT.md`](./docs/REGISTRY-CONTRACT.md) | Registry API specification |
| [`docs/config.example.yaml`](./docs/config.example.yaml) | Full configuration reference |

## Development

### Prerequisites

- Go 1.24+
- Make
- [golangci-lint](https://golangci-lint.run/usage/install/) (for linting)

### Build and test

```bash
make build          # build binary
make test           # run tests with race detection
make test-coverage  # generate HTML coverage report
make lint           # run linter
make fmt            # format code
make all            # format + lint + test + build
```

### Project conventions

- **3 direct dependencies** — Cobra (CLI), Viper (config), Testify (tests)
- **Zero CGO** — `CGO_ENABLED=0` for fully static, cross-platform binaries
- **GORM-style errors** — all errors wrapped with context (`fmt.Errorf("doing X: %w", err)`)
- **Platform isolation via build tags** — `//go:build linux`, `//go:build darwin`, etc.
- **Conventional Commits** — `feat:`, `fix:`, `docs:`, `refactor:`, `test:`

## Contributing

Contributions are welcome! Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md) for guidelines and [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) for community standards.

## License

MIT License — see [`LICENSE`](./LICENSE) for details.

---

<p align="center">
  Part of the <a href="https://github.com/security-mcp">MCP Hub Platform</a> — trust infrastructure for MCP servers.
</p>
