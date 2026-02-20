# MCP-CLIENT

**mcp-client** is the CLI launcher for the MCP Hub ecosystem. It resolves, downloads, validates, and executes MCP (Model Context Protocol) server packages from a compatible registry. It enforces security policies, applies resource limits, and audits all executions locally.

The client acts as the **Execution Plane** of the MCP Hub Platform: it consumes certified artifacts from mcp-registry, validates their integrity via SHA-256 digests, and runs them inside lightweight process-level sandboxes with platform-specific isolation.

---

## Features

- Immutable package resolution (`org/name@version`, `org/name@sha`, `org/name@digest`)
- Content-addressable local cache with mandatory SHA-256 validation
- Lightweight process-level sandboxing (not VM-level)
- Platform-specific resource limits (CPU, memory, PIDs, file descriptors)
- Network default-deny with manifest-controlled allowlists (Linux only)
- Filesystem isolation to working directory (Linux only, best-effort on other OSes)
- Security policy enforcement: certification level, origin filtering, environment filtering, subprocess control
- Structured JSON audit logging with secret redaction
- STDIO transport for MCP servers (HTTP transport planned)
- Package publishing via `mcp push` to MCP Hub

---

## Stack

- **Language:** Go 1.24+
- **CLI Framework:** Cobra
- **Configuration:** Viper (YAML + env vars + flags)
- **Testing:** Testify
- **Build/Release:** Makefile, Goreleaser
- **Containerization:** Docker

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `mcp run <ref>` | Execute an MCP server from a package reference |
| `mcp pull <ref>` | Pre-download a package without executing (useful for CI/CD) |
| `mcp push <org/name@version>` | Publish an MCP package to the hub |
| `mcp info <ref>` | Display package manifest details |
| `mcp login` | Authenticate with the registry (interactive or token-based) |
| `mcp logout` | Remove stored authentication credentials |
| `mcp cache ls` | List cached artifacts |
| `mcp cache rm` | Remove cached artifacts (by digest or `--all`) |
| `mcp doctor` | Diagnose system sandbox capabilities |

---

## Quick Start

```bash
# Build from source
make build

# Check system capabilities
./mcp doctor

# Pull and run a package
./mcp pull acme/hello-world@1.2.3
./mcp run acme/hello-world@1.2.3

# Publish a package
./mcp push acme/my-tool@1.0.0 --source ./dist
```

---

## Configuration

**Config file:** `~/.mcp/config.yaml`

Key sections: `registry` (URL, timeout), `cache` (directory, max size, TTL), `executor` (default timeout, resource limits), `security` (network deny, subprocess control), `audit` (log file, format), `policy` (cert level enforcement, allowed origins).

**Environment variables** (override config):

| Variable | Purpose |
|----------|---------|
| `MCP_REGISTRY_URL` | Registry endpoint URL |
| `MCP_REGISTRY_TOKEN` | Authentication token |
| `MCP_CACHE_DIR` | Cache directory path |
| `MCP_LOG_LEVEL` | Log verbosity (debug, info, warn, error) |
| `MCP_TIMEOUT` | Default execution timeout |

**CLI flags** override both config file and environment variables. Use `--registry`, `--cache-dir`, `--verbose`, `--json`.

**Auth tokens** are stored in `~/.mcp/auth.json` with `0600` permissions.

---

## Security Model

- **Digest validation:** All manifests and bundles are validated against SHA-256 before use
- **Resource limits:** CPU, memory, PIDs, and file descriptors are always enforced (mandatory defaults cannot be disabled)
- **Network isolation:** Default-deny on Linux via network namespaces; not available on macOS/Windows
- **Filesystem isolation:** Process confined to working directory on Linux; best-effort on other platforms
- **Subprocess control:** Restricted by default unless the manifest explicitly declares subprocess permissions
- **Secret handling:** Secrets passed by reference only, never logged in plaintext
- **No elevated privileges:** The launcher never runs as root/admin
- **Policy enforcement:** Configurable minimum certification level (0-3) and allowed origin types (Official, Verified, Community)

---

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Resource Limits | cgroups v2 + rlimits | rlimits only | Job Objects |
| Network Isolation | Network namespaces | Not available | Not available |
| Filesystem Isolation | Bind mounts + Landlock | Best-effort (UNIX perms) | Best-effort (NTFS perms) |
| Subprocess Control | seccomp | Limited | Not available |
| Audit Logging | Full | Full | Full |
| **Production Ready** | Yes | No | No |

**Critical:** macOS and Windows sandboxes have known bypass vulnerabilities. Use Linux with cgroups or Docker containers for production workloads running untrusted MCPs.

---

## Integration with Registry

The client communicates with mcp-registry via REST API:
- **Resolve:** `POST /v1/packages/:org/:name/resolve` to get manifest and bundle digests/URLs
- **Download:** `GET /manifests/:digest` and `GET /bundles/:digest` with redirect support for presigned URLs
- **Authentication:** JWT Bearer tokens for enterprise mode; optional for OSS mode
- **Retries:** Exponential backoff on 5xx errors (3 attempts), respects 429 rate limits
- **Cache headers:** Honors `Cache-Control` and `ETag`/`If-None-Match`

The client also communicates with mcp-hub for the `push` workflow (upload init/finalize).

---

## Development Commands

| Target | Description |
|--------|-------------|
| `make build` | Build the `mcp` binary |
| `make test` | Run all tests with race detection and coverage |
| `make test-coverage` | Generate HTML coverage report |
| `make lint` | Run golangci-lint |
| `make fmt` | Format code (gofmt + goimports) |
| `make clean` | Remove build artifacts |
| `make install` | Install binary to `$GOPATH/bin` |
| `make tidy` | Run `go mod tidy` |
| `make deps` | Download dependencies |
| `make all` | Format, lint, test, and build |
| `make docker-build` | Build Docker image |
| `make release-snapshot` | Build release snapshot (requires goreleaser) |

---

## Testing

```bash
make test              # Unit + integration tests with race detection
make test-coverage     # Generate HTML coverage report
```

Tests include unit, integration, benchmark, fuzz, and E2E tests. Platform-specific sandbox tests use build tags (`linux`, `darwin`, `windows`). All tests run offline using fixtures and mock HTTP servers.

---

## Gotchas

- Linux sandbox tests require root or cgroups v2 delegation; skip with `-short` flag if unavailable
- macOS and Windows cannot provide network isolation; `mcp doctor` reports these limitations
- Binary name is `mcp` (not `mcp-client`); built to `./mcp` by default
- Registry must be running and accessible for `pull`/`run`/`push` commands to work
- Auth tokens stored in `~/.mcp/auth.json` with 0600 perms; token expiry is not auto-refreshed
- `push` command requires authentication; run `mcp login` first
- CGO_ENABLED=0 by default for cross-platform builds

## Commits

- **Author:** Dani (cr0hn@cr0hn.com)
- **Format:** Conventional Commits (`feat:`, `fix:`, `docs:`, etc.)
- **Changelog:** Document all changes in `CHANGELOG.md`
