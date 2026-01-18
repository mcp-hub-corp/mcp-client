package manifest

import (
	"encoding/json"
	"testing"
)

var validManifestJSON = []byte(`{
  "schema_version": "1.0",
  "package": {
    "id": "acme/test-package",
    "version": "1.0.0",
    "git_sha": "abc123def456"
  },
  "bundle": {
    "digest": "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
    "size_bytes": 1048576
  },
  "transport": {
    "type": "stdio"
  },
  "entrypoints": [
    {
      "os": "linux",
      "arch": "amd64",
      "command": "./bin/server",
      "args": ["--mode", "stdio"]
    }
  ],
  "permissions_requested": {
    "network": ["*.example.com"],
    "environment": ["HOME", "USER"],
    "subprocess": false
  },
  "limits_recommended": {
    "max_cpu": 1000,
    "max_memory": "512M",
    "max_pids": 10,
    "max_fds": 100,
    "timeout": "5m"
  }
}`)

func BenchmarkParse(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(validManifestJSON)
	}
}

func BenchmarkValidate(b *testing.B) {
	manifest, _ := Parse(validManifestJSON)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Validate(manifest)
	}
}

func BenchmarkSelectEntrypoint(b *testing.B) {
	manifest, _ := Parse(validManifestJSON)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SelectEntrypoint(manifest)
	}
}

func BenchmarkJSONUnmarshal_Manifest(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var m Manifest
		_ = json.Unmarshal(validManifestJSON, &m)
	}
}

func BenchmarkFullManifestWorkflow(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manifest, err := Parse(validManifestJSON)
		if err != nil {
			b.Fatal(err)
		}
		if err := Validate(manifest); err != nil {
			b.Fatal(err)
		}
		_, err = SelectEntrypoint(manifest)
		if err != nil {
			b.Logf("SelectEntrypoint failed (expected on non-Linux): %v", err)
		}
	}
}
