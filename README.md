<p align="center">
  <h1 align="center">mcp</h1>
  <p align="center">
    <strong>The execution layer of MCP Hub Platform</strong>
  </p>
  <p align="center">
    Resolve, validate, sandbox, and execute certified MCP servers — the last mile of a trust pipeline that starts with automated security analysis.
  </p>
  <p align="center">
    <a href="https://github.com/security-mcp/mcp-client/actions"><img src="https://github.com/security-mcp/mcp-client/workflows/CI/badge.svg" alt="CI"></a>
    <a href="https://goreportcard.com/report/github.com/security-mcp/mcp-client"><img src="https://goreportcard.com/badge/github.com/security-mcp/mcp-client" alt="Go Report Card"></a>
    <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
    <a href="go.mod"><img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white" alt="Go Version"></a>
    <a href="https://github.com/security-mcp/mcp-client/releases"><img src="https://img.shields.io/github/v/release/security-mcp/mcp-client?color=orange" alt="Release"></a>
    <a href="https://mcp-hub.info"><img src="https://img.shields.io/badge/ecosystem-MCP%20Hub%20Platform-blueviolet" alt="MCP Hub Platform"></a>
  </p>
</p>

---

## Why MCP Hub exists

**MCP** (Model Context Protocol) is transforming how AI agents interact with external tools. Instead of ad-hoc integrations, MCP provides a **standard protocol**: agents connect to MCP servers that expose capabilities — file access, database queries, API calls, code execution. The ecosystem is growing fast. Thousands of MCP servers already exist, and **every major AI framework** is adding native MCP support.

But there is a **fundamental trust problem**. Today, running an MCP server means executing **arbitrary code with the full permissions of your user account**. The standard workflow looks like this:

```bash
# This runs arbitrary code with your full system access
uvx some-mcp-server
npx @someone/mcp-tool
```

**No integrity verification. No resource limits. No sandboxing. No audit trail.** The package could exfiltrate your SSH keys, mine crypto in the background, or pivot through your network — and you would not know until it is too late. For individual developers experimenting, this might be an acceptable risk. For **organizations deploying MCP servers in production**, connected to internal databases and APIs, it is not.

**MCP Hub Platform** is the trust infrastructure that closes this gap. It is an **end-to-end pipeline**: publish MCP server source code, automatically analyze it for **14 classes of security vulnerabilities**, compute a **deterministic certification score**, distribute the certified artifact through a **content-addressed registry**, and execute it with **runtime sandboxing and policy enforcement**. Every step is auditable. Every artifact is immutable. Every execution is logged.

The platform is built as four components that form a pipeline:

- **[mcp-hub](https://mcp-hub.info)** — Control plane. Ingests source code, orchestrates security analysis, computes certification scores, publishes certified artifacts.
- **mcp-scan** — Analysis engine. Purpose-built static security analyzer developed in-house by the MCP Hub team, specialized exclusively in MCP server threat patterns. Detects **14 vulnerability classes** (A-N) using pattern matching, taint analysis, and AI-assisted detection across Python, TypeScript, JavaScript, and Go. Not open source — core intellectual property of the platform.
- **mcp-registry** (open source coming soon) — Data plane. Content-addressed artifact distribution with SHA-256 integrity, JWT authentication, and scope-based authorization.
- **mcp-client** (this repository) — Execution plane. The last mile — where all upstream certification **materializes as runtime enforcement**.

## How the platform works

```
Developer
    |  mcp push / git commit
    v
[mcp-hub]  ──AMQP: ANALYZE job──>  [mcp-scan worker]
    |                                     |
    |  <──AMQP: ANALYZE_COMPLETE──────────┘
    |
    |  score (0-100) → cert_level (0-3)
    |  publishes certified artifact
    v
[mcp-registry]  ── content-addressed storage (SHA-256)
    ^
    |  resolve + download + validate
    |
[mcp-client]  ── policy check → sandbox → execute → audit
    |
    v
MCP Server (isolated, resource-limited, audited)
```

1. **Ingest** — Developer pushes MCP server source to mcp-hub (Git repo, webhook, or CLI upload)
2. **Analyze** — mcp-scan runs **proprietary static analysis**: 14 vulnerability classes, taint tracking, pattern matching
3. **Certify** — Hub computes **deterministic score** (0-100), maps to **certification level** (0-3)
4. **Distribute** — Certified artifact published to mcp-registry with **immutable SHA-256 digest**
5. **Execute** — mcp-client resolves, validates, **enforces policy**, sandboxes, and audits the execution

## This repository: the execution layer

`mcp` is where **trust becomes enforcement**. The upstream pipeline — analysis, scoring, certification — produces artifacts with known security properties. This client is responsible for **making those properties matter at runtime**.

What `mcp` does:

- **Resolves** packages from the registry by name, version, or content digest
- **Validates** every manifest and bundle against its **SHA-256 digest** before use — no code path can bypass this
- **Enforces** organizational policies: **minimum certification level**, allowed origins, environment filtering
- **Sandboxes** processes with platform-specific isolation: CPU, memory, PID, and file descriptor limits; **network default-deny**; filesystem confinement
- **Audits** every execution as structured JSON with **automatic secret redaction**

This is **not just a launcher**. `uvx` and `npx` download and run. `mcp` downloads, validates, checks policy, confines, monitors, and logs. It is a **runtime trust enforcement layer**.

## Why `mcp` over `uvx` / `npx`?

| | `uvx` / `npx` | `mcp` |
|---|---|---|
| **Integrity** | None. Runs whatever is downloaded | SHA-256 digest validation on every manifest and bundle |
| **Supply chain verification** | None | Full certification pipeline: static analysis of 14 vulnerability classes, deterministic scoring, 4-level certification |
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
# Download the latest binary for your platform
# See Installation below for all options

# Check what your system supports
mcp doctor

# Run a certified MCP server
mcp run acme/hello-world@1.2.3
```

`mcp doctor` reports which security features are available on your system — cgroups, namespaces, seccomp, Landlock, and more. **Start here** to understand your security posture before running anything.

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

### Execute

```bash
# Run by version
mcp run acme/tool@1.2.3

# Run latest version
mcp run acme/tool@latest

# Run by content digest (exact artifact)
mcp run acme/tool@sha256:a1b2c3...

# With timeout and env vars
mcp run acme/tool@1.0.0 --timeout 10m --env API_KEY=secret

# Force re-download (skip cache)
mcp run acme/tool@1.0.0 --no-cache

# Pre-download without executing (useful for CI/CD warm-up)
mcp pull acme/tool@1.2.3

# Inspect a package before running
mcp info acme/tool@1.2.3          # human-readable
mcp info acme/tool@1.2.3 --json   # machine-readable
```

### Manage

```bash
# List cached artifacts
mcp cache ls
mcp cache ls --json

# Remove specific artifact
mcp cache rm sha256:abc123...

# Clear everything
mcp cache rm --all

# Diagnose system sandbox capabilities
mcp doctor
```

### Auth

```bash
# Store credentials
mcp login --token YOUR_TOKEN

# Remove credentials
mcp logout

# Or use environment variables
export MCP_REGISTRY_TOKEN=YOUR_TOKEN
mcp run acme/tool@1.0.0
```

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

Every manifest and bundle is validated against its **SHA-256 digest before use**. Digests are **immutable** — a package reference always resolves to the same content. This prevents **supply-chain attacks**, rollback attacks, and tampering.

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

Packages are assigned a **certification level (0-3)** based on **automated security analysis** upstream in mcp-hub:

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
make lint           # run linter
make all            # format + lint + test + build
```

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for full development guidelines.

## Contributing

Contributions are welcome! Please read [`CONTRIBUTING.md`](./CONTRIBUTING.md) for guidelines and [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) for community standards.

## License

MIT License — see [`LICENSE`](./LICENSE) for details.

---

<p align="center">
  Part of <a href="https://mcp-hub.info">MCP Hub Platform</a> — trust infrastructure for publishing, certifying, and running MCP servers.
</p>
