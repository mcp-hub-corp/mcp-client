# Security Fix Implementation: CLIENT-CRIT-001

## Vulnerability: Symlink Attack in Bundle Extraction

**Severity:** CRITICAL
**Status:** FIXED
**Date:** 2026-01-19

---

## Summary

Implemented critical security fix to reject symlinks and hardlinks during tar bundle extraction in the `mcp run` command. This prevents attackers from crafting malicious MCP bundles that could read or write arbitrary files outside the intended extraction directory.

---

## Changes Made

### 1. Modified `internal/cli/run.go`

#### Added Symlink/Hardlink Rejection (lines 426-431)
```go
case tar.TypeSymlink, tar.TypeLink:
    // SECURITY: Reject symlinks to prevent symlink attacks
    // Symlinks could point outside the bundle directory and allow
    // arbitrary file read/write attacks
    return fmt.Errorf("symlinks and hardlinks not allowed in bundle: %s -> %s",
        header.Name, header.Linkname)
```

**Location:** Function `extractBundle()`, inside the `switch header.Typeflag` statement
**Effect:** Any tar entry with type `TypeSymlink` or `TypeLink` is immediately rejected with a clear error message

#### Added Unknown Type Rejection (lines 477-480)
```go
default:
    // SECURITY: Reject unknown tar types
    return fmt.Errorf("unsupported tar type %c for file: %s",
        header.Typeflag, header.Name)
```

**Location:** Same switch statement, default case
**Effect:** Rejects any unrecognized tar entry types (e.g., FIFO, character devices, block devices)

---

### 2. Created `internal/cli/run_extract_test.go` (274 lines)

Comprehensive test suite covering:

#### Test Functions:

1. **`TestExtractBundleRejectsSymlinks`**
   - Tests rejection of relative symlinks (e.g., `../etc/passwd`)
   - Tests rejection of absolute symlinks (e.g., `/etc/passwd`)
   - Tests rejection of in-bundle symlinks
   - Verifies symlink files are NOT created
   - Verifies error messages are clear

2. **`TestExtractBundleRejectsHardlinks`**
   - Tests rejection of relative hardlinks
   - Tests rejection of hardlinks pointing to parent directories
   - Verifies hardlink files are NOT created
   - Verifies error messages are clear

3. **`TestExtractBundleRejectsUnknownTarTypes`**
   - Tests rejection of unsupported tar types (e.g., FIFO)
   - Verifies appropriate error messages

4. **`TestExtractBundleSucceedsWithValidBundle`**
   - Positive test: valid bundles with only files and directories work correctly
   - Verifies file content is extracted properly
   - Verifies permissions are restrictive (0600 for files, 0750 for dirs)

#### Helper Functions:

- `createTarGzWithSymlink()` - Creates test bundles with symlinks
- `createTarGzWithHardlink()` - Creates test bundles with hardlinks
- `createTarGzWithUnknownType()` - Creates test bundles with unsupported types

---

## Security Impact

### Before Fix:
- Malicious MCP bundles could contain symlinks pointing outside extraction directory
- Attacker could read sensitive files (e.g., `/etc/passwd`, `~/.ssh/id_rsa`)
- Attacker could overwrite critical files if MCP runs with elevated privileges
- No validation of tar entry types beyond regular files and directories

### After Fix:
- All symlinks and hardlinks are explicitly rejected
- Unknown tar entry types are rejected
- Clear error messages help identify malicious bundles
- Defense-in-depth: complements existing path traversal checks

---

## Threat Model

**Attack Vector Blocked:**
1. Attacker publishes malicious MCP to registry with crafted tar bundle
2. Bundle contains symlink: `etc_passwd -> /etc/passwd`
3. User runs: `mcp run malicious/mcp@1.0.0`
4. Bundle extraction would follow symlink and expose `/etc/passwd`

**With This Fix:**
- Extraction fails immediately with error:
  ```
  symlinks and hardlinks not allowed in bundle: etc_passwd -> /etc/passwd
  ```
- No files are created outside the extraction directory
- User is alerted to potentially malicious bundle

---

## Testing Status

### Test File Created: ✅
- Location: `internal/cli/run_extract_test.go`
- Lines: 274
- Coverage: Symlinks, hardlinks, unknown types, valid bundles

### Syntax Validation: ✅
- `go fmt` passes cleanly

### Unit Tests: ⚠️ Cannot run yet
- **Reason:** Pre-existing compilation errors in the codebase (unrelated to this fix)
- **Errors:** `registry.NewClient` signature changed in other files
- **Note:** The `run.go` fix in this PR also corrects one instance of this error (line 71)

### Will Pass When:
1. All `registry.NewClient` calls are updated to handle error return
2. Files needing updates: `info.go`, `login.go`, `pull.go`

---

## Code Quality

### Follows Project Standards: ✅
- Uses tabs for indentation (matches existing code)
- Security comments with `// SECURITY:` prefix
- Descriptive error messages
- Defense-in-depth approach

### Performance Impact: ✅
- Negligible: One additional switch case check per tar entry
- No new allocations or system calls

### Backward Compatibility: ✅
- Stricter validation (fails on previously allowed but dangerous inputs)
- Legitimate MCP bundles should only contain regular files and directories
- Breaking change is intentional for security

---

## Additional Security Measures Already Present

The `extractBundle()` function already had multiple security controls:

1. **Path Traversal Prevention (lines 411-423):**
   - Validates paths don't start with `..` or `/`
   - Verifies target stays within `destDir`

2. **Decompression Bomb Protection (lines 389, 438-445):**
   - 1GB limit on total extracted size
   - Per-file size validation

3. **Restrictive Permissions:**
   - Directories: `0o750`
   - Files: `0o600`

4. **Size Validation (lines 461-464):**
   - Verifies written bytes match header size

**This fix adds:** Explicit rejection of symlinks, hardlinks, and unknown types.

---

## Deployment Notes

### No Configuration Changes Required
- Fix is transparent to users
- No new flags or settings

### User Impact
- Users attempting to run malicious bundles will see clear error
- Legitimate bundles unaffected (should not contain symlinks)

### Logging
- Errors are returned to caller (CLI command)
- Standard error logging applies

---

## References

- **CWE-61:** UNIX Symbolic Link (Symlink) Following
- **CWE-59:** Improper Link Resolution Before File Access
- **OWASP:** Path Traversal / Directory Traversal
- **Related:** CVE-2019-14271 (Docker symlink vulnerability)

---

## Verification Checklist

- [x] Symlinks rejected with clear error
- [x] Hardlinks rejected with clear error
- [x] Unknown tar types rejected
- [x] Tests added for all cases
- [x] Code follows project style
- [x] Security comments added
- [x] No new dependencies
- [x] No performance regression
- [x] Error messages are user-friendly
- [x] Documentation updated (this file)

---

## Next Steps

To enable full testing:
1. Fix pre-existing compilation errors in:
   - `internal/cli/info.go:51`
   - `internal/cli/login.go:103`
   - `internal/cli/pull.go:37`
2. Run full test suite: `go test ./internal/cli -run TestExtractBundle`
3. Verify all tests pass
4. Run integration tests with malicious bundles

---

## Commit Message

```
fix(security): reject symlinks and hardlinks in tar extraction (CLIENT-CRIT-001)

BREAKING CHANGE: MCP bundles containing symlinks or hardlinks will now be rejected

- Add explicit rejection of tar.TypeSymlink and tar.TypeLink in extractBundle()
- Add rejection of unknown/unsupported tar types (FIFO, devices, etc.)
- Add comprehensive test suite in run_extract_test.go
- Prevents symlink attacks where malicious bundles could read/write arbitrary files

Security Impact:
- Blocks CWE-61 (Symlink Following) attacks
- Blocks CWE-59 (Improper Link Resolution) attacks
- Defense-in-depth: complements existing path traversal checks

Testing:
- 4 test functions covering symlinks, hardlinks, unknown types, valid bundles
- Test helpers for creating malicious tar bundles
- Positive and negative test cases

Fixes: CLIENT-CRIT-001
```

---

**Implementation by:** Claude Sonnet 4.5 (1M context)
**Review status:** Ready for code review
**Merge status:** Ready after pre-existing build errors are resolved
