# MCP-Client Skills Directory

This directory contains comprehensive expert knowledge bases for implementing critical components of the mcp-client launcher.

## Available Skills

### 1. registry-api.md (996 lines, 25 KB)
**Expert knowledge for MCP registry HTTP client implementation**

Key topics:
- OpenAPI contract reference for github.com/security-mcp/mcp-registry
- Authentication methods: Bearer JWT, API Token, Basic Auth
- Core endpoints: Login, Resolve, Download Manifest, Download Bundle, Catalog
- HTTP client setup with timeouts and redirect handling
- Retry logic with exponential backoff (3 max attempts)
- Digest validation (SHA-256/SHA-512) - critical security invariant
- Error handling and custom HTTP error types
- Debugging commands (curl examples, code logging)
- Testing patterns with mock registry and retry simulation
- Response caching and ETag support
- Security considerations (no token logging, HTTPS only)

**Use when:** Implementing registry integration, HTTP client setup, authentication, artifact downloads

**Key code patterns:**
- Client initialization with auth headers
- Redirect following with presigned URLs
- SHA-256/SHA-512 digest validation
- Retry logic with exponential backoff + jitter
- Metadata struct mapping (ResolveResponse, CatalogResponse)

---

### 2. mcp-manifest.md (1214 lines, 27 KB)
**Expert knowledge for MCP manifest parsing and validation**

Key topics:
- Complete manifest schema with all fields defined
- Package ID format validation (org/name regex patterns)
- Semantic version validation (semver patterns)
- Digest format validation (sha256:hex or sha512:hex)
- Transport types: stdio (default) vs http
- Entrypoint selection algorithm with OS/arch matching
- Permissions structure: network allowlists, environment variables, subprocess control, filesystem
- Resource limits: cpu_millis, memory_mb, max_pids, max_fds, timeout_seconds
- Health check configuration (HTTP transport only)
- Manifest-to-bundle coherence validation
- 8 common manifest mistakes and their fixes
- Example valid manifests (simple STDIO, HTTP with health check, minimal)
- Testing patterns for validation and entrypoint selection
- JSON parsing and file I/O patterns

**Use when:** Parsing manifests, validating manifest structure, selecting entrypoints, designing manifest examples

**Key validation rules:**
- Required fields: schema_version, package (org/name/version), bundle (digest/size), transport, entrypoints
- Entrypoint keys: must be platform-arch (e.g., linux-amd64, darwin-arm64)
- Transport values: must be "stdio" or "http" (default: stdio)
- Network allowlist: domain patterns, CIDR ranges, port-specific rules
- Secrets: passed by NAME only, never in plaintext

---

### 3. content-cache.md (1156 lines, 28 KB)
**Expert knowledge for content-addressable cache implementation**

Key topics:
- Content-addressable design principles (immutability, deduplication, integrity)
- Directory structure: ~/.mcp/cache/{manifests,bundles}/sha256:*/
- Metadata file structure (digest, size, timestamps, package info)
- Store interface definition with core operations
- Atomic write pattern: temp file → validate → rename (prevents corruption)
- Get operation with last-access timestamp updates
- Exists checks (single and batch)
- Delete operation with cleanup
- List operation with sorting and filtering
- Cache size calculation (total and by type)
- Eviction strategies: TTL-based, LRU, size-based
- Thread-safety patterns: RWMutex, per-digest locks
- Filesystem locking (optional, platform-specific)
- CopyToPath operation for bundle extraction
- 5 common issues with solutions:
  1. Race conditions on concurrent writes
  2. Partial writes on disk full
  3. Corrupted metadata files
  4. Unbounded cache growth
  5. Lost last-access metadata
- Testing patterns: atomic writes, concurrent access, eviction policies
- Integration with registry client (caching downloaded artifacts)
- Debugging and inspection commands
- Schema versioning for future upgrades

**Use when:** Implementing cache store, handling concurrent access, eviction policies, bundle extraction

**Key patterns:**
- Per-digest mutex locks prevent concurrent corruption
- Atomic writes: write to temp, validate hash, rename to final location
- Digest always used as key (never trust filename)
- Content verified after download and after cache retrieval
- Async last-access updates don't block reads

---

## How to Use These Skills

### In Claude Code / Agent Workflows

Reference the skills explicitly when working on related components:

```
@claude-code analyze registry-api to implement HTTP client with proper retry logic
@claude-code use mcp-manifest for manifest parser validation logic
@claude-code reference content-cache for thread-safe store implementation
```

### For Implementation Tasks

When implementing registry integration:
1. Start with **registry-api.md** for HTTP client structure and endpoints
2. Use **mcp-manifest.md** for manifest parsing logic
3. Apply **content-cache.md** patterns for caching downloaded artifacts

### For Code Review

When reviewing:
- Registry client code → check against registry-api.md patterns
- Manifest parser → validate against mcp-manifest.md schema
- Cache implementation → verify concurrency patterns in content-cache.md

---

## Cross-References Between Skills

### registry-api → mcp-manifest
- Resolve endpoint returns manifest digest
- Download manifest endpoint returns JSON matching manifest schema
- Manifest validation required before execution

### mcp-manifest → content-cache
- Manifest stored in cache by digest
- Digest validation matches content-cache atomic write patterns
- Bundle digest must match manifest bundle.digest

### content-cache → registry-api
- Cache stores artifacts downloaded from registry
- Digest validation follows registry-api patterns
- Concurrent downloads use content-cache locking

---

## Related Files

- **CLAUDE.md** - Project specification and goals
- **docs/REGISTRY-CONTRACT.md** - Detailed registry API contract
- **docs/ARCHITECTURE.md** - System architecture overview
- **internal/registry/client.go** - Registry client implementation
- **internal/manifest/parser.go** - Manifest parsing logic
- **internal/cache/store.go** - Cache store implementation

---

## Skill Maintenance

These skills were created on 2026-01-18 and reflect:
- MCP Registry OpenAPI spec (github.com/security-mcp/mcp-registry)
- Manifest schema version 1.0
- Cache schema version 1
- Go best practices for HTTP clients, JSON parsing, concurrency

Updates may be needed if:
- Registry API changes (breaking changes to endpoints)
- Manifest schema evolution (new required fields)
- Cache requirements change (new eviction policies)
