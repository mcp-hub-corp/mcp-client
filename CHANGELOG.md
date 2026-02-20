# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **2026-02-20**: Rewritten README.md for open-source release with professional structure, comparison table vs uvx/npx, security model documentation, and architecture diagram
- **2026-02-20**: Moved 10 internal development docs to docs/internal/ to clean up repository root
- **2026-02-20**: Updated .gitignore to exclude binaries, test artifacts, OS/IDE files

## [1.0.0] - 2026-01-18

### Added

- Initial release of mcp-client
- CLI commands: run, pull, info, login, logout, cache, doctor
- Registry integration with authentication (Bearer, Token, Basic)
- Content-addressable cache with atomic operations
- Manifest parsing and validation
- Policy engine with resource limits and allowlists
- Audit logging with JSON structured format
- STDIO executor for MCP servers
- Platform-specific sandbox implementations:
  - Linux: rlimits, cgroups v2 detection, namespace support
  - macOS: rlimits with documented limitations
  - Windows: Job Objects placeholder with documented limitations
- SHA-256 digest validation for all artifacts
- Comprehensive documentation (OVERVIEW, SECURITY, EXAMPLES)
- Full test coverage (75.8% average)
- Multi-platform support (Linux, macOS, Windows)

### Security

- Mandatory digest validation (SHA-256)
- Default-deny network policies (Linux only)
- Environment variable filtering
- Subprocess control
- Audit logging for compliance
- Resource limits enforcement
- Directory traversal protection
- Decompression bomb protection

### Documentation

- Complete architecture overview
- Comprehensive threat model
- Platform-specific capabilities matrix
- 50+ usage examples
- Configuration reference
- Troubleshooting guide
- Contributing guidelines
- Code of Conduct

[Unreleased]: https://github.com/security-mcp/mcp-client/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/security-mcp/mcp-client/releases/tag/v1.0.0
