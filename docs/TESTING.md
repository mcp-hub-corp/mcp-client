# Testing Documentation

## Test Coverage Summary

### Overall Statistics

- **Total test modules**: 8
- **Total test files**: 17
- **Total test cases**: 200+
- **Total test code**: 3,776 lines
- **Average coverage**: ~75%

### Coverage by Module

| Module | Coverage | Test Count | Status |
|--------|----------|------------|--------|
| policy | 100.0% | 13 | Excellent |
| config | 94.6% | 7 | Excellent |
| manifest | 87.5% | 16 | Excellent |
| audit | 83.8% | 9 | Excellent |
| registry | 80.8% | 64+ | Excellent |
| sandbox | 75.8% | 33 | Good |
| cache | 68.8% | 25+ | Good |
| executor | 23.3% | 9 | Adequate |
| cli | 4.7% | 4 | Limited* |

*CLI has low coverage because most logic is in other modules. Integration tests cover full workflows.

## Test Types

### Unit Tests

**Purpose**: Test individual functions in isolation

**Coverage**: Majority of tests (~85%)

**Examples**:
- `internal/config/config_test.go`: Configuration loading
- `internal/manifest/parser_test.go`: Manifest validation
- `internal/policy/policy_test.go`: Policy enforcement
- `internal/registry/digest_test.go`: Digest validation

**Characteristics**:
- Fast execution (< 1s per module)
- No external dependencies
- Mock HTTP servers (httptest)
- Temp directories for filesystem operations

### Integration Tests

**Purpose**: Test multiple modules working together

**Coverage**: ~10% of tests

**Examples**:
- `internal/registry/client_test.go`: Full HTTP client workflow with mock server
- `internal/cache/store_test.go`: Cache with real filesystem
- `internal/cli/*_test.go`: Command execution (limited)

**Characteristics**:
- Moderate execution time (1-10s)
- Real filesystem operations
- Mock external services only

### Platform-Specific Tests

**Purpose**: Test OS-specific functionality

**Coverage**: ~5% of tests

**Examples**:
- `internal/sandbox/linux_test.go` (build tag: `//go:build linux`)
- `internal/sandbox/darwin_test.go` (build tag: `//go:build darwin`)
- `internal/sandbox/windows_test.go` (build tag: `//go:build windows`)

**Characteristics**:
- Only run on target platform
- Test actual OS capabilities (rlimits, cgroups, etc.)
- Skip on other platforms

## Running Tests

### All Tests

```bash
make test
```

### Specific Module

```bash
go test ./internal/registry/...
```

### With Coverage Report

```bash
make test-coverage
# Opens coverage.html in browser
```

### Platform-Specific

```bash
# Run only on Linux
go test -tags linux ./internal/sandbox/...

# Run only on macOS
go test -tags darwin ./internal/sandbox/...
```

### With Race Detection

```bash
go test -race ./...
```

### Verbose Output

```bash
go test -v ./internal/cache/...
```

### Short Mode (Skip Integration Tests)

```bash
go test -short ./...
```

## Test Organization

### Naming Conventions

- **Files**: `*_test.go` in same package
- **Functions**: `TestFunctionName` for unit tests
- **Functions**: `TestFunctionName_Scenario` for specific scenarios
- **Examples**: `ExampleFunctionName` for documentation

### Table-Driven Tests

Many tests use table-driven approach:

```go
func TestParseDigest(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        wantErr bool
    }{
        {"valid sha256", "sha256:abc123...", false},
        {"invalid format", "nocolon", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            _, _, err := ParseDigest(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

### Test Helpers

**testify/assert**: Assertions
```go
assert.Equal(t, expected, actual)
assert.NoError(t, err)
assert.Contains(t, str, substr)
```

**testify/require**: Fatal assertions
```go
require.NoError(t, err) // Stops test on failure
require.NotNil(t, obj)
```

**t.TempDir()**: Automatic cleanup
```go
dir := t.TempDir() // Auto-removed after test
```

## Coverage Goals

### Current Targets

- **Critical paths**: > 80% (registry, manifest, cache, audit)
- **Business logic**: > 70% (policy, sandbox)
- **Infrastructure**: > 60% (config, executor)
- **CLI**: > 20% (mostly integration-tested)

### Excluded from Coverage

- `cmd/mcp/main.go`: Entry point (integration-tested)
- Error messages and logging
- Platform detection code (runtime-only)

## Continuous Integration

### GitHub Actions

Tests run automatically on:
- Every push to `main`
- Every pull request
- Multiple platforms: Ubuntu, macOS, Windows
- Multiple Go versions: 1.21, 1.22

### Local Pre-Commit

Recommended workflow:

```bash
make fmt      # Format code
make lint     # Run linters
make test     # Run tests
make build    # Build binary
```

Or simply:

```bash
make all      # Runs all of the above
```

## Test Maintenance

### Adding New Tests

1. Create `*_test.go` file in same package
2. Use table-driven tests for multiple scenarios
3. Mock external dependencies (use httptest for HTTP)
4. Aim for > 70% coverage
5. Test error paths, not just happy path

### Platform-Specific Tests

1. Add build tag: `//go:build linux`
2. Create separate test file: `module_linux_test.go`
3. Test actual OS capabilities
4. Document expected behavior per platform

### Updating Tests

When modifying code:
1. Update existing tests if behavior changes
2. Add new tests for new functionality
3. Verify coverage doesn't decrease
4. Run full test suite before committing

## Known Test Limitations

### CLI Tests (4.7% coverage)

**Why low**: CLI code orchestrates other modules, hard to test without mocks

**Mitigation**: Other modules have high coverage, integration tests cover workflows

**Future**: Add CLI integration tests with mock registry

### Executor Tests (23.3% coverage)

**Why moderate**: Process execution is platform-specific, hard to test portably

**Mitigation**: Error handling well-tested, integration tests verify execution

**Future**: Add more platform-specific execution tests

### Platform-Specific Code

**Challenge**: Can only test on native platform

**Solution**: Use build tags, CI tests on multiple platforms

**Risk**: Low (stdlib APIs are well-tested)

## Test Data

### Fixtures

Test data stored in:
- Inline strings (manifests, JSON responses)
- `testdata/` directories (future: for large fixtures)

### Mock Servers

HTTP tests use `httptest.Server`:

```go
server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // Mock response
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(response)
}))
defer server.Close()
```

## Performance Testing

### Current Approach

- Standard `go test` (no benchmarks yet)
- Race detection enabled (`-race`)
- Timeout protection (30s default)

### Future Enhancements

- Add benchmark tests for critical paths
- Profile cache operations
- Measure download performance

## Contributing Tests

When contributing, ensure:

1. **New code has tests**: Aim for > 70% coverage
2. **All tests pass**: `make test` succeeds
3. **No race conditions**: `go test -race` clean
4. **Linting passes**: `make lint` succeeds
5. **Platform tests work**: Test on target OS if platform-specific

See [CONTRIBUTING.md](../CONTRIBUTING.md) for full guidelines.
