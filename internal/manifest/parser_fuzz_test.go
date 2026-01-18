package manifest

import (
	"testing"
)

// Fuzz test for manifest parsing - security critical
func FuzzParse(f *testing.F) {
	// Seed corpus with valid manifests
	f.Add([]byte(`{
		"schema_version": "1.0",
		"package": {"id": "org/name", "version": "1.0.0", "git_sha": "abc123"},
		"bundle": {"digest": "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234", "size_bytes": 1000},
		"transport": {"type": "stdio"},
		"entrypoints": [{"os": "linux", "arch": "amd64", "command": "./bin/server"}]
	}`))

	f.Add([]byte(`{"schema_version": "1.0"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(`123`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Should never panic, even with malicious input
		manifest, err := Parse(data)

		if err == nil {
			// If parsing succeeds, validation might still fail
			_ = Validate(manifest)
		}

		// Test should complete without panic
	})
}

// Fuzz test for entrypoint selection
func FuzzSelectEntrypoint(f *testing.F) {
	// Seed with valid manifest JSON
	f.Add([]byte(`{
		"entrypoints": [
			{"os": "linux", "arch": "amd64", "command": "./server"},
			{"os": "darwin", "arch": "arm64", "command": "./server-mac"},
			{"os": "windows", "arch": "amd64", "command": "./server.exe"}
		]
	}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		manifest, err := Parse(data)
		if err != nil {
			return
		}

		// Should not panic even with weird entrypoint data
		_, _ = SelectEntrypoint(manifest)
	})
}
