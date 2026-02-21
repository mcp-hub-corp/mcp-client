package manifest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_ValidManifest(t *testing.T) {
	data := []byte(`{
		"schema_version": "1.0",
		"package": {
			"id": "acme/hello",
			"version": "1.0.0",
			"git_sha": "abc123"
		},
		"bundle": {
			"digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"size_bytes": 1024
		},
		"transport": {
			"type": "stdio"
		},
		"entrypoints": [
			{
				"os": "linux",
				"arch": "amd64",
				"command": "./bin/server"
			}
		],
		"permissions_requested": {},
		"limits_recommended": {}
	}`)

	m, err := Parse(data)
	require.NoError(t, err)
	assert.Equal(t, "acme/hello", m.Package.ID)
	assert.Equal(t, "1.0.0", m.Package.Version)
	assert.Equal(t, "stdio", m.Transport.Type)
	assert.Len(t, m.Entrypoints, 1)
}

func TestParse_EmptyData(t *testing.T) {
	_, err := Parse([]byte{})
	assert.Error(t, err)
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := Parse([]byte(`{invalid json}`))
	assert.Error(t, err)
}

func TestValidate_ValidManifest(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
			GitSHA:  "abc123",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "stdio",
		},
		Entrypoints: []Entrypoint{
			{
				OS:      "linux",
				Arch:    "amd64",
				Command: "./bin/server",
			},
		},
	}

	err := Validate(m)
	assert.NoError(t, err)
}

func TestValidate_NilManifest(t *testing.T) {
	err := Validate(nil)
	assert.Error(t, err)
}

func TestValidate_MissingSchemaVersion(t *testing.T) {
	m := &Manifest{
		Package: PackageInfo{ID: "acme/hello", Version: "1.0.0"},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "schema_version")
}

func TestValidate_InvalidPackageID(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "invalid",
			Version: "1.0.0",
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "org/name")
}

func TestValidate_InvalidDigest(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "invalid",
			SizeBytes: 1024,
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "digest")
}

func TestValidate_InvalidTransportType(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "invalid",
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transport")
}

func TestValidate_HTTPTransportWithoutPort(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "http",
			Port: 0,
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "port")
}

func TestValidate_NoEntrypoints(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "stdio",
		},
		Entrypoints: []Entrypoint{},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entrypoint")
}

func TestValidate_InvalidEntrypointOS(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "stdio",
		},
		Entrypoints: []Entrypoint{
			{
				OS:      "invalid",
				Arch:    "amd64",
				Command: "./bin/server",
			},
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "os")
}

func TestValidate_InvalidEntrypointArch(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/hello",
			Version: "1.0.0",
		},
		Bundle: BundleInfo{
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 1024,
		},
		Transport: TransportInfo{
			Type: "stdio",
		},
		Entrypoints: []Entrypoint{
			{
				OS:      "linux",
				Arch:    "invalid",
				Command: "./bin/server",
			},
		},
	}
	err := Validate(m)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "arch")
}

func TestSelectEntrypoint_FoundForCurrentOS(t *testing.T) {
	m := &Manifest{
		Entrypoints: []Entrypoint{
			{
				OS:      "linux",
				Arch:    "amd64",
				Command: "./bin/linux",
			},
			{
				OS:      "linux",
				Arch:    "arm64",
				Command: "./bin/linux-arm",
			},
			{
				OS:      "darwin",
				Arch:    "amd64",
				Command: "./bin/darwin",
			},
			{
				OS:      "darwin",
				Arch:    "arm64",
				Command: "./bin/darwin-arm",
			},
			{
				OS:      "windows",
				Arch:    "amd64",
				Command: "./bin/windows.exe",
			},
		},
	}

	ep, err := SelectEntrypoint(m)
	require.NoError(t, err)
	assert.NotNil(t, ep)
	// The result depends on runtime environment, so just check it's one of them
	assert.Contains(t, []string{"linux", "darwin", "windows"}, ep.OS)
	assert.Contains(t, []string{"amd64", "arm64"}, ep.Arch)
}

func TestSelectEntrypoint_NotFound(t *testing.T) {
	m := &Manifest{
		Entrypoints: []Entrypoint{
			{
				OS:      "freebsd",
				Arch:    "amd64",
				Command: "./bin/freebsd",
			},
		},
	}

	_, err := SelectEntrypoint(m)
	assert.Error(t, err)
}

func TestSelectEntrypoint_NilManifest(t *testing.T) {
	_, err := SelectEntrypoint(nil)
	assert.Error(t, err)
}

func TestIsValidPackageID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"acme/hello", true},
		{"org-123/pkg_name", true},
		{"org/pkg", true},
		{"org", false},
		{"org/", false},
		{"/name", false},
		{"org/name/extra", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			result := isValidPackageID(tt.id)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestIsValidDigest(t *testing.T) {
	tests := []struct {
		digest string
		valid  bool
	}{
		{"sha256:0000000000000000000000000000000000000000000000000000000000000000", true},
		{"sha256:abc123def456", false},
		{"sha1:abc123", false},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.digest, func(t *testing.T) {
			result := isValidDigest(tt.digest)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestIsValidOS(t *testing.T) {
	tests := []struct {
		os    string
		valid bool
	}{
		{"linux", true},
		{"darwin", true},
		{"windows", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.os, func(t *testing.T) {
			result := isValidOS(tt.os)
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestIsValidArch(t *testing.T) {
	tests := []struct {
		arch  string
		valid bool
	}{
		{"amd64", true},
		{"arm64", true},
		{"386", false},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.arch, func(t *testing.T) {
			result := isValidArch(tt.arch)
			assert.Equal(t, tt.valid, result)
		})
	}
}
