# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: security@mcp-hub.info

Include the following information:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### What to expect

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity
- **Disclosure**: Coordinated disclosure after fix is available

## Security Features

mcp-client implements several security features:

- **Digest validation**: All artifacts validated with SHA-256
- **Resource limits**: CPU, memory, PID, FD limits per platform
- **Audit logging**: All executions logged for compliance
- **Sandboxing**: Platform-specific isolation (see docs/SECURITY.md)
- **Environment filtering**: Only allowlisted env vars passed
- **Network allowlists**: Best-effort per platform

## Known Limitations

See docs/SECURITY.md for comprehensive threat model and platform-specific limitations.

## Security Best Practices

1. Always use digest-based references when possible
2. Review manifest permissions before execution
3. Run on Linux for best isolation capabilities
4. Enable audit logging in production
5. Use restrictive policies
6. Keep mcp-client updated to latest version
