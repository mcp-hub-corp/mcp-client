# mcp-client

CLI launcher for MCP (Model Context Protocol) servers. This tool downloads, validates, and executes MCP packages from a compatible registry with security policies and resource isolation.

## Features

- **Package Resolution**: Resolves immutable package references (`org/name@version`, `org/name@sha`, `org/name@digest`)
- **Content-Addressable Cache**: Avoids repeated downloads with SHA-256 validated caching
- **Security Policies**: Network allowlists, environment filtering, subprocess control
- **Resource Limits**: CPU, memory, process, and file descriptor limits
- **Audit Logging**: Local structured audit logs of all executions
- **Multi-Platform**: Linux, macOS, and Windows support with platform-specific isolation

## Installation

### From Source

```bash
git clone https://github.com/security-mcp/mcp-client
cd mcp-client
make build
```

The binary will be built as `./mcp`.

To install to `$GOPATH/bin`:

```bash
make install
```

### Binary Releases

Pre-built binaries for Linux, macOS, and Windows will be available on the [Releases](https://github.com/security-mcp/mcp-client/releases) page.

## Quick Start

### Basic Usage

```bash
# Execute an MCP server
mcp run acme/hello-world@1.2.3

# Pre-download a package
mcp pull acme/tool@latest

# View package information
mcp info acme/tool@1.2.3

# Check system capabilities
mcp doctor
```

### Configuration

Configuration can be provided via:
1. Config file: `~/.mcp/config.yaml`
2. Environment variables: `MCP_REGISTRY_URL`, `MCP_CACHE_DIR`, `MCP_LOG_LEVEL`
3. Command-line flags: `--registry`, `--cache-dir`, `--verbose`

Example `~/.mcp/config.yaml`:

```yaml
registry:
  url: https://registry.mcp.dev
  timeout: 30s

cache:
  dir: ~/.mcp/cache
  max_size: 10GB

executor:
  default_timeout: 5m
  max_cpu: 1000      # millicores
  max_memory: 512M
  max_pids: 10
  max_fds: 100

log:
  level: info
```

## Commands

### `mcp run <package-ref>`

Execute an MCP server from a package reference.

```bash
mcp run acme/hello-world@1.2.3
mcp run acme/tool@sha:abc123
mcp run acme/tool@digest:sha256:abc123...
```

### `mcp pull <package-ref>`

Pre-download a package without executing it (useful for CI/CD).

```bash
mcp pull acme/tool@1.2.3
```

### `mcp login`

Authenticate with the MCP registry.

```bash
mcp login --token YOUR_TOKEN
```

### `mcp cache`

Manage the local cache.

```bash
# List cached artifacts
mcp cache ls

# Remove specific artifact
mcp cache rm sha256:abc123

# Clear all cache
mcp cache rm --all
```

### `mcp doctor`

Diagnose system capabilities for running MCP servers.

```bash
mcp doctor
```

## Development

### Prerequisites

- Go 1.21 or later
- Make (optional, for convenience)

### Building

```bash
make build
```

### Testing

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage
```

### Linting

```bash
make lint
```

Requires [golangci-lint](https://golangci-lint.run/usage/install/).

### Formatting

```bash
make fmt
```

## Project Status

This project is under active development. Current implementation status:

- [x] Phase 1: Project skeleton, CLI structure, config loading
- [ ] Phase 2: Registry integration
- [ ] Phase 3: Content-addressable cache
- [ ] Phase 4: Manifest parsing and validation
- [ ] Phase 5: Linux sandbox (cgroups, namespaces)
- [ ] Phase 6: macOS sandbox (rlimits, timeouts)
- [ ] Phase 7: Windows sandbox (Job Objects)
- [ ] Phase 8: Process execution (STDIO, HTTP)
- [ ] Phase 9: Policy enforcement
- [ ] Phase 10: Audit logging

See [CLAUDE.md](./CLAUDE.md) for detailed implementation plan.

## Architecture

```
cmd/mcp/            # CLI entry point
internal/
  config/           # Configuration loading
  cli/              # Cobra CLI commands
  registry/         # Registry client
  manifest/         # Manifest parsing
  cache/            # Content-addressable cache
  executor/         # Process execution
  sandbox/          # Platform-specific isolation
  policy/           # Security policies
  audit/            # Audit logging
```

## Security

This project implements lightweight security controls:

- **Digest Validation**: All artifacts validated with SHA-256
- **Resource Limits**: CPU, memory, process, FD limits enforced
- **Network Isolation**: Default-deny network policies (Linux)
- **Filesystem Isolation**: Processes run in controlled directories
- **Audit Logging**: All executions logged locally

See [SECURITY.md](./docs/SECURITY.md) for threat model and security invariants.

## License

[License TBD]

## Contributing

Contributions welcome! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## Support

For issues and questions, please use [GitHub Issues](https://github.com/security-mcp/mcp-client/issues).
