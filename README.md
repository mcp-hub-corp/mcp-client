# mcp-client

[![CI](https://github.com/security-mcp/mcp-client/workflows/CI/badge.svg)](https://github.com/security-mcp/mcp-client/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/security-mcp/mcp-client)](https://goreportcard.com/report/github.com/security-mcp/mcp-client)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/security-mcp/mcp-client)](go.mod)

Secure CLI launcher for MCP (Model Context Protocol) servers. Download, validate, and execute MCP packages from a compatible registry with lightweight security policies and resource isolation.

## What is mcp-client?

**mcp-client** is a command-line tool that:
- Resolves immutable package references (`org/name@version`, `org/name@sha`, `org/name@digest`)
- Downloads and validates manifests and bundles from a registry
- Applies security policies (network allowlists, environment filtering, subprocess control)
- Enforces resource limits (CPU, memory, processes, file descriptors)
- Executes MCP servers in isolated processes
- Audits all executions locally

## Features

- **Package Resolution**: Resolves immutable references with semantic versioning, SHA, and digest support
- **Content-Addressable Cache**: Avoids repeated downloads with mandatory SHA-256 validation
- **Security Policies**: Network allowlists, environment variable filtering, subprocess control
- **Resource Limits**: CPU, memory, process, and file descriptor limits (platform-specific)
- **Audit Logging**: Structured JSON audit logs of all executions with secret redaction
- **Multi-Platform**: Linux, macOS, and Windows support with platform-specific isolation mechanisms
- **Light-Weight Sandbox**: Process-level isolation (not VM-level), minimal resource overhead

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Resource Limits | ✅ | ⚠️ | ✅ |
| Network Isolation | ✅ | ❌ | ❌ |
| Filesystem Isolation | ✅ | ⚠️ | ⚠️ |
| Subprocess Control | ✅ | ⚠️ | ✅ |
| Audit Logging | ✅ | ✅ | ✅ |

⚠️ = Limited capabilities; ❌ = Not available

## Installation

### From Binary

Pre-built binaries are available for Linux (amd64, arm64), macOS (amd64, arm64), and Windows (amd64, arm64):

```bash
# Linux
curl -sSL https://github.com/security-mcp/mcp-client/releases/download/v1.0.0/mcp-linux-amd64 \
  -o /usr/local/bin/mcp && chmod +x /usr/local/bin/mcp

# macOS
curl -sSL https://github.com/security-mcp/mcp-client/releases/download/v1.0.0/mcp-darwin-amd64 \
  -o /usr/local/bin/mcp && chmod +x /usr/local/bin/mcp

# Windows
curl -sSL https://github.com/security-mcp/mcp-client/releases/download/v1.0.0/mcp-windows-amd64.exe \
  -o "C:\Program Files\mcp.exe"
```

### From Source

```bash
# Clone the repository
git clone https://github.com/security-mcp/mcp-client
cd mcp-client

# Build the binary
make build

# Binary is now available as ./mcp
./mcp --version

# Or install to $GOPATH/bin
make install
mcp --version
```

### Requirements

- Go 1.21 or later (for building from source)
- No external runtime dependencies for pre-built binaries

## Quick Start

### Check System Capabilities

```bash
mcp doctor
```

Shows what security features are available on your system.

### Execute a Package

```bash
# Run with version
mcp run acme/hello-world@1.2.3

# Run with latest version
mcp run acme/hello-world@latest

# Run with SHA reference
mcp run acme/hello-world@sha:abc123def456
```

### Pre-download Package

```bash
# Download to cache without executing
mcp pull acme/tool@1.2.3

# Later, mcp run uses cache (instant execution)
mcp run acme/tool@1.2.3
```

### View Package Information

```bash
# Show package manifest details
mcp info acme/tool@1.2.3 --json
```

### Manage Cache

```bash
# List cached artifacts
mcp cache ls

# Remove specific artifact
mcp cache rm sha256:abc123...

# Clear all cache
mcp cache rm --all
```

### Authenticate with Registry

```bash
# Login to registry
mcp login --token YOUR_TOKEN

# Or use environment variable
export MCP_REGISTRY_TOKEN=YOUR_TOKEN
mcp run acme/tool@1.0.0
```

## Configuration

### Configuration File

Create `~/.mcp/config.yaml`:

```yaml
registry:
  url: https://registry.mcp-hub.info
  timeout: 30s

cache:
  dir: ~/.mcp/cache
  max_size: 10GB
  ttl: 720h

executor:
  default_timeout: 5m
  max_cpu: 1000        # millicores (1000 = 1 core)
  max_memory: 512M
  max_pids: 10
  max_fds: 100

security:
  network:
    default_deny: true
  subprocess:
    allow: false

audit:
  enabled: true
  log_file: ~/.mcp/audit.log
  format: json

log:
  level: info
  format: text
```

See `docs/config.example.yaml` for all available options with detailed explanations.

### Environment Variables

Override configuration file settings:

```bash
export MCP_REGISTRY_URL=https://custom-registry.com
export MCP_CACHE_DIR=/custom/cache
export MCP_LOG_LEVEL=debug
export MCP_REGISTRY_TOKEN=secret

mcp run acme/tool@1.0.0
```

### Command-Line Flags

Override both config and environment variables:

```bash
mcp run acme/tool@1.0.0 \
  --registry https://other-registry.com \
  --cache-dir /tmp/cache \
  --timeout 10m \
  --verbose
```

## Commands Reference

### `mcp run <ref> [flags]`

Execute an MCP server from a package reference.

```bash
# Basic usage
mcp run acme/tool@1.2.3

# With timeout
mcp run acme/tool@1.2.3 --timeout 5m

# With environment variables
mcp run acme/tool@1.2.3 --env LOG_LEVEL=debug --env API_KEY=secret

# Force re-download (ignore cache)
mcp run acme/tool@1.2.3 --no-cache

# Verbose output
mcp run acme/tool@1.2.3 --verbose
```

### `mcp pull <ref> [flags]`

Pre-download a package without executing (useful for CI/CD).

```bash
mcp pull acme/tool@1.2.3
```

### `mcp info <ref> [flags]`

Display package information.

```bash
# Show manifest
mcp info acme/tool@1.2.3

# JSON output
mcp info acme/tool@1.2.3 --json
```

### `mcp login [flags]`

Authenticate with the registry.

```bash
mcp login --token YOUR_TOKEN
mcp login --registry https://custom-registry.com --token TOKEN
```

### `mcp logout [flags]`

Remove stored authentication credentials.

```bash
mcp logout
```

### `mcp cache [command]`

Manage local package cache.

```bash
# List all cached artifacts
mcp cache ls

# List as JSON
mcp cache ls --json

# Remove specific artifact
mcp cache rm sha256:abc123...

# Clear all cache
mcp cache rm --all
```

### `mcp doctor`

Diagnose system capabilities.

```bash
mcp doctor
```

Shows what security isolation features are available on your system.

## Documentation

- **[OVERVIEW.md](./docs/OVERVIEW.md)**: Architecture, concepts, and workflow
- **[SECURITY.md](./docs/SECURITY.md)**: Threat model, security invariants, platform capabilities
- **[EXAMPLES.md](./docs/EXAMPLES.md)**: Usage examples, CI/CD integration, troubleshooting
- **[REGISTRY-CONTRACT.md](./docs/REGISTRY-CONTRACT.md)**: Registry API specification
- **[config.example.yaml](./docs/config.example.yaml)**: Configuration reference

## Development

### Prerequisites

- Go 1.21 or later
- Make (for convenience)
- golangci-lint (for linting)

### Build

```bash
make build
```

Binary is created as `./mcp`.

### Test

```bash
# Run all tests
make test

# Run tests with coverage report
make test-coverage
```

### Lint

```bash
make lint
```

Requires [golangci-lint](https://golangci-lint.run/usage/install/).

### Format Code

```bash
make fmt
```

### Clean

```bash
make clean
```

## Project Status

**Version**: 1.0 (Production Ready)

Current implementation includes:
- ✅ CLI structure and configuration loading
- ✅ Registry integration (resolve, download, authentication)
- ✅ Content-addressable cache with SHA-256 validation
- ✅ Manifest parsing and validation
- ✅ Linux sandbox (cgroups, namespaces, seccomp)
- ✅ macOS sandbox (rlimits, timeouts)
- ✅ Windows sandbox (Job Objects)
- ✅ STDIO executor (HTTP executor planned for future)
- ✅ Policy enforcement (network, environment, subprocess)
- ✅ Audit logging
- ✅ Comprehensive documentation

Future enhancements:
- HTTP executor support
- Signature verification for packages
- Multi-registry federation
- Telemetry and monitoring
- Desktop GUI wrapper

## Security

mcp-client implements **lightweight, process-level security controls**:

### What's Protected
- **Resource Exhaustion**: CPU, memory, process, and file descriptor limits
- **Filesystem Breakout**: Process confined to working directory
- **Network Access**: Default-deny with manifest-controlled allowlist
- **Secret Leakage**: Secrets redacted from logs
- **Supply Chain Attacks**: Mandatory SHA-256 digest validation
- **Subprocess Escape**: Controlled via manifest declaration

### Limitations
- Not a VM-level sandbox (suitable for untrusted code review, not execution)
- macOS: Limited to rlimits (no network/filesystem isolation)
- Windows: Limited without WFP drivers (no network isolation)
- Cannot protect against kernel exploits or hardware side-channels
- Does not inspect or modify package code

See [docs/SECURITY.md](./docs/SECURITY.md) for detailed threat model and platform-specific capabilities.

## Examples

### CI/CD Integration

```bash
# Pre-download packages for faster CI jobs
mcp pull myorg/linter@1.0.0 &
mcp pull myorg/formatter@1.0.0 &
wait

# Run tools (from cache, instant)
mcp run myorg/linter@1.0.0 -- ./src
mcp run myorg/formatter@1.0.0 -- --check ./src
```

### With Environment Variables

```bash
# From file
mcp run myorg/api-tool@2.0.0 --env-file .env

# From CLI
mcp run myorg/api-tool@2.0.0 \
  --env LOG_LEVEL=debug \
  --env API_ENDPOINT=https://api.example.com
```

### Resource Limits

```bash
# Override default limits
mcp run heavy-workload@1.0.0 \
  --timeout 30m \
  --max-memory 2G
```

See [docs/EXAMPLES.md](./docs/EXAMPLES.md) for more examples and troubleshooting.

## License

[License TBD]

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit changes with clear messages
4. Push to the branch
5. Create a Pull Request

## Support

For issues, questions, or discussions:

- **Bug Reports**: [GitHub Issues](https://github.com/security-mcp/mcp-client/issues)
- **Security Issues**: Email security@example.com (do not use issues)
- **Discussions**: [GitHub Discussions](https://github.com/security-mcp/mcp-client/discussions)

## Architecture

```
cmd/mcp/             # CLI entry point
├── main.go

internal/
├── config/          # Configuration (YAML, env, flags)
├── cli/             # Cobra CLI commands
├── registry/        # Registry API client
├── manifest/        # Manifest parsing and validation
├── cache/           # Content-addressable cache
├── executor/        # Process execution (STDIO, HTTP)
├── sandbox/         # Platform-specific isolation
│   ├── sandbox.go
│   ├── linux.go
│   ├── darwin.go
│   └── windows.go
├── policy/          # Security policy enforcement
├── audit/           # Audit logging
└── (other packages)
```

See [docs/OVERVIEW.md](./docs/OVERVIEW.md) for detailed architecture information.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

We welcome contributions! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

See also [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for our community guidelines.

## Acknowledgments

- Built with [Cobra](https://github.com/spf13/cobra) for CLI framework
- Configuration management with [Viper](https://github.com/spf13/viper)
- Testing with [Testify](https://github.com/stretchr/testify)

## Project Status

**Current Version**: v1.0.0

**Stability**: Production-ready for STDIO transport. HTTP transport planned for v1.1.

See [CHANGELOG.md](CHANGELOG.md) for version history and [docs/SECURITY.md](docs/SECURITY.md) for security details.

---

**Made with ❤️ by the MCP community**
