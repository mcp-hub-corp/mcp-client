package manifest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateManifest_InvalidInputs(t *testing.T) {
	tests := []struct {
		name        string
		sourceDir   string
		pkg         *PackageRef
		config      *GeneratorConfig
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty source directory",
			sourceDir:   "",
			pkg:         &PackageRef{Org: "test", Name: "app", Version: "1.0.0"},
			expectError: true,
			errorMsg:    "source directory cannot be empty",
		},
		{
			name:        "nil package reference",
			sourceDir:   ".",
			pkg:         nil,
			expectError: true,
			errorMsg:    "package reference cannot be nil",
		},
		{
			name:        "missing package org",
			sourceDir:   ".",
			pkg:         &PackageRef{Org: "", Name: "app", Version: "1.0.0"},
			expectError: true,
			errorMsg:    "package org, name, and version are required",
		},
		{
			name:        "missing package name",
			sourceDir:   ".",
			pkg:         &PackageRef{Org: "test", Name: "", Version: "1.0.0"},
			expectError: true,
			errorMsg:    "package org, name, and version are required",
		},
		{
			name:        "missing package version",
			sourceDir:   ".",
			pkg:         &PackageRef{Org: "test", Name: "app", Version: ""},
			expectError: true,
			errorMsg:    "package org, name, and version are required",
		},
		{
			name:      "invalid transport type",
			sourceDir: ".",
			pkg:       &PackageRef{Org: "test", Name: "app", Version: "1.0.0"},
			config: &GeneratorConfig{
				TransportType: "invalid",
			},
			expectError: true,
			errorMsg:    "transport type must be 'stdio' or 'http'",
		},
		{
			name:      "http transport without port",
			sourceDir: ".",
			pkg:       &PackageRef{Org: "test", Name: "app", Version: "1.0.0"},
			config: &GeneratorConfig{
				TransportType: "http",
				HTTPPort:      0,
			},
			expectError: true,
			errorMsg:    "http port is required and must be > 0 for http transport",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			if tt.sourceDir == "." {
				tt.sourceDir = tempDir
			}

			_, err := GenerateManifest(tt.sourceDir, tt.pkg, tt.config)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGenerateManifest_NodeJS(t *testing.T) {
	tempDir := t.TempDir()

	// Create a minimal package.json
	packageJSON := []byte(`{
		"name": "test-app",
		"version": "1.0.0",
		"main": "src/index.js",
		"bin": {
			"test-app": "src/cli.js"
		}
	}`)

	err := os.WriteFile(filepath.Join(tempDir, "package.json"), packageJSON, 0o644)
	require.NoError(t, err)

	// Create the main file
	err = os.WriteFile(filepath.Join(tempDir, "src", "index.js"), []byte("console.log('hello')"), 0o644)
	require.Error(t, err) // Will fail because src dir doesn't exist
	os.MkdirAll(filepath.Join(tempDir, "src"), 0o755)
	err = os.WriteFile(filepath.Join(tempDir, "src", "index.js"), []byte("console.log('hello')"), 0o644)
	require.NoError(t, err)

	manifest, err := GenerateManifest(
		tempDir,
		&PackageRef{Org: "acme", Name: "nodejs-app", Version: "1.0.0"},
		nil,
	)

	require.NoError(t, err)
	assert.NotNil(t, manifest)
	assert.Equal(t, "acme/nodejs-app", manifest.Package.ID)
	assert.Equal(t, "1.0.0", manifest.Package.Version)
	assert.Equal(t, "stdio", manifest.Transport.Type)
	assert.Len(t, manifest.Entrypoints, 5) // Current platform + 4 cross-platform

	// Note: Full validation requires bundle digest/size which are calculated later
	// Just verify the structure is correct

	// Verify permissions are safe defaults
	assert.Equal(t, 0, len(manifest.Permissions.Network))
	assert.Equal(t, 0, len(manifest.Permissions.FileSystem))
	assert.Equal(t, false, manifest.Permissions.Subprocess)

	// Verify limits
	assert.Equal(t, 1000, manifest.Limits.MaxCPU)
	assert.Equal(t, "512M", manifest.Limits.MaxMemory)
}

func TestGenerateManifest_Python(t *testing.T) {
	tempDir := t.TempDir()

	// Create requirements.txt
	err := os.WriteFile(
		filepath.Join(tempDir, "requirements.txt"),
		[]byte("requests==2.28.0\nclick==8.1.0"),
		0o644,
	)
	require.NoError(t, err)

	// Create main.py
	err = os.WriteFile(
		filepath.Join(tempDir, "main.py"),
		[]byte("print('hello')"),
		0o644,
	)
	require.NoError(t, err)

	manifest, err := GenerateManifest(
		tempDir,
		&PackageRef{Org: "acme", Name: "python-app", Version: "2.0.0"},
		nil,
	)

	require.NoError(t, err)
	assert.NotNil(t, manifest)
	assert.Equal(t, "acme/python-app", manifest.Package.ID)
	assert.Equal(t, "2.0.0", manifest.Package.Version)

	// Verify entrypoints
	assert.Greater(t, len(manifest.Entrypoints), 0)
	found := false
	for _, ep := range manifest.Entrypoints {
		if ep.Command == "python main.py" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected 'python main.py' command")

}

func TestGenerateManifest_Go(t *testing.T) {
	tempDir := t.TempDir()

	// Create go.mod
	goMod := []byte(`module github.com/acme/myapp

go 1.21

require (
	github.com/lib/pq v1.10.9
)`)

	err := os.WriteFile(filepath.Join(tempDir, "go.mod"), goMod, 0o644)
	require.NoError(t, err)

	// Create main.go
	err = os.WriteFile(
		filepath.Join(tempDir, "main.go"),
		[]byte("package main\n\nfunc main() {}"),
		0o644,
	)
	require.NoError(t, err)

	manifest, err := GenerateManifest(
		tempDir,
		&PackageRef{Org: "acme", Name: "go-app", Version: "1.5.0"},
		nil,
	)

	require.NoError(t, err)
	assert.NotNil(t, manifest)
	assert.Equal(t, "acme/go-app", manifest.Package.ID)
	assert.Equal(t, "1.5.0", manifest.Package.Version)

	// Verify entrypoints contain Go app
	assert.Greater(t, len(manifest.Entrypoints), 0)
	found := false
	for _, ep := range manifest.Entrypoints {
		if ep.Command == "./myapp" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected './myapp' command in entrypoints")

}

func TestGenerateManifest_Binary(t *testing.T) {
	tempDir := t.TempDir()

	// Create a server directory (will be treated as binary)
	err := os.MkdirAll(filepath.Join(tempDir, "server"), 0o755)
	require.NoError(t, err)

	manifest, err := GenerateManifest(
		tempDir,
		&PackageRef{Org: "acme", Name: "binary-app", Version: "1.0.0"},
		nil,
	)

	require.NoError(t, err)
	assert.NotNil(t, manifest)
	assert.Equal(t, "acme/binary-app", manifest.Package.ID)

}

func TestGenerateManifest_WithHTTPTransport(t *testing.T) {
	tempDir := t.TempDir()

	// Create a simple project file
	err := os.WriteFile(filepath.Join(tempDir, "main.py"), []byte("print('hi')"), 0o644)
	require.NoError(t, err)

	manifest, err := GenerateManifest(
		tempDir,
		&PackageRef{Org: "test", Name: "http-app", Version: "1.0.0"},
		&GeneratorConfig{
			TransportType: "http",
			HTTPPort:      8080,
			Description:   "HTTP service",
			Repository:    "https://github.com/test/http-app",
		},
	)

	require.NoError(t, err)
	assert.Equal(t, "http", manifest.Transport.Type)
	assert.Equal(t, 8080, manifest.Transport.Port)

}

func TestGenerateManifest_DefaultConfig(t *testing.T) {
	tempDir := t.TempDir()

	// Create a simple project file
	err := os.WriteFile(filepath.Join(tempDir, "main.py"), []byte("print('hi')"), 0o644)
	require.NoError(t, err)

	// Generate with nil config (should use defaults)
	manifest, err := GenerateManifest(
		tempDir,
		&PackageRef{Org: "test", Name: "default-app", Version: "1.0.0"},
		nil,
	)

	require.NoError(t, err)
	assert.Equal(t, "stdio", manifest.Transport.Type)
	assert.Equal(t, 0, manifest.Transport.Port)
	assert.Equal(t, 1000, manifest.Limits.MaxCPU)
	assert.Equal(t, "512M", manifest.Limits.MaxMemory)
	assert.Equal(t, "30s", manifest.Limits.Timeout)
	assert.Equal(t, false, manifest.Permissions.Subprocess)
}

func TestGenerateManifest_SafePermissions(t *testing.T) {
	tempDir := t.TempDir()

	err := os.WriteFile(filepath.Join(tempDir, "main.py"), []byte("print('hi')"), 0o644)
	require.NoError(t, err)

	manifest, err := GenerateManifest(
		tempDir,
		&PackageRef{Org: "test", Name: "secure-app", Version: "1.0.0"},
		nil,
	)

	require.NoError(t, err)

	// Verify permissions are conservative
	assert.Empty(t, manifest.Permissions.Network, "network should be empty by default")
	assert.Empty(t, manifest.Permissions.FileSystem, "filesystem should be empty by default")
	assert.False(t, manifest.Permissions.Subprocess, "subprocess should be disabled by default")
	assert.Empty(t, manifest.Permissions.Environment, "environment should be empty by default")
}

func TestGenerateEntrypoints_MultiPlatform(t *testing.T) {
	entrypoints := generateEntrypoints("./myapp")

	assert.Greater(t, len(entrypoints), 0)

	// Check that we have entries for major platforms
	osArchMap := make(map[string]bool)
	for _, ep := range entrypoints {
		key := ep.OS + "/" + ep.Arch
		osArchMap[key] = true
	}

	// Should have at least these
	expectedPlatforms := []string{
		"linux/amd64",
		"linux/arm64",
		"darwin/amd64",
		"darwin/arm64",
	}

	for _, platform := range expectedPlatforms {
		assert.True(t, osArchMap[platform], "missing platform %s", platform)
	}

	// All should have the same command
	for _, ep := range entrypoints {
		assert.Equal(t, "./myapp", ep.Command)
	}
}

func TestDetectRuntime_Node(t *testing.T) {
	tempDir := t.TempDir()

	packageJSON := []byte(`{"name": "test", "main": "index.js"}`)
	err := os.WriteFile(filepath.Join(tempDir, "package.json"), packageJSON, 0o644)
	require.NoError(t, err)

	rt, cmdResult, err := detectRuntime(tempDir)
	require.NoError(t, err)
	assert.Equal(t, RuntimeNode, rt)
	assert.Contains(t, cmdResult, "node")
}

func TestDetectRuntime_Python_RequirementsTxt(t *testing.T) {
	tempDir := t.TempDir()

	err := os.WriteFile(filepath.Join(tempDir, "requirements.txt"), []byte("requests"), 0o644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tempDir, "main.py"), []byte("print('hi')"), 0o644)
	require.NoError(t, err)

	rt, cmdResult, err := detectRuntime(tempDir)
	require.NoError(t, err)
	assert.Equal(t, RuntimePython, rt)
	assert.Contains(t, cmdResult, "python")
}

func TestDetectRuntime_Python_SetupPy(t *testing.T) {
	tempDir := t.TempDir()

	err := os.WriteFile(filepath.Join(tempDir, "setup.py"), []byte("from setuptools import setup"), 0o644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tempDir, "main.py"), []byte("print('hi')"), 0o644)
	require.NoError(t, err)

	rt, _, err := detectRuntime(tempDir)
	require.NoError(t, err)
	assert.Equal(t, RuntimePython, rt)
}

func TestDetectRuntime_Go(t *testing.T) {
	tempDir := t.TempDir()

	goMod := []byte("module test\n\ngo 1.21")
	err := os.WriteFile(filepath.Join(tempDir, "go.mod"), goMod, 0o644)
	require.NoError(t, err)

	rt, cmd, err := detectRuntime(tempDir)
	require.NoError(t, err)
	assert.Equal(t, RuntimeGo, rt)
	assert.Contains(t, cmd, "./")
}

func TestSerializeManifest(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "test/app",
			Version: "1.0.0",
		},
		Transport: TransportInfo{
			Type: "stdio",
		},
		Entrypoints: []Entrypoint{
			{
				OS:      "linux",
				Arch:    "amd64",
				Command: "./app",
			},
		},
	}

	data, err := SerializeManifest(m)
	require.NoError(t, err)

	// Verify it's valid JSON
	parsed, err := Parse(data)
	require.NoError(t, err)
	assert.Equal(t, m.Package.ID, parsed.Package.ID)
	assert.Equal(t, m.Package.Version, parsed.Package.Version)
}

func TestSerializeManifest_NilManifest(t *testing.T) {
	_, err := SerializeManifest(nil)
	assert.Error(t, err)
}

func TestSaveAndLoadManifest(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "manifest.json")

	m := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      "acme/test",
			Version: "1.0.0",
		},
		Transport: TransportInfo{
			Type: "stdio",
		},
		Entrypoints: []Entrypoint{
			{
				OS:      "linux",
				Arch:    "amd64",
				Command: "./server",
			},
		},
		Permissions: PermissionsInfo{
			Network: []string{"*.example.com"},
		},
	}

	// Save manifest
	err := SaveManifest(m, filePath)
	require.NoError(t, err)

	// Verify file exists
	_, err = os.Stat(filePath)
	require.NoError(t, err)

	// Load manifest
	loaded, err := LoadManifest(filePath)
	require.NoError(t, err)

	// Verify loaded content
	assert.Equal(t, m.Package.ID, loaded.Package.ID)
	assert.Equal(t, m.Package.Version, loaded.Package.Version)
	assert.Equal(t, m.Transport.Type, loaded.Transport.Type)
	assert.Equal(t, len(m.Entrypoints), len(loaded.Entrypoints))
	assert.Equal(t, m.Permissions.Network, loaded.Permissions.Network)
}

func TestLoadManifest_NonExistent(t *testing.T) {
	_, err := LoadManifest("/nonexistent/path/manifest.json")
	assert.Error(t, err)
}

func TestHasFile(t *testing.T) {
	tempDir := t.TempDir()

	// Create a file
	filePath := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(filePath, []byte("test"), 0o644)
	require.NoError(t, err)

	assert.True(t, hasFile(tempDir, "test.txt"))
	assert.False(t, hasFile(tempDir, "nonexistent.txt"))
}

func TestIsExecutableCandidate(t *testing.T) {
	tests := []struct {
		filename string
		expected bool
	}{
		{"server", true},
		{"app", true},
		{"main", true},
		{"binary", true},
		{"main.go", false},
		{"main.py", false},
		{"test.sh", false},
		{"config.json", false},
		{"README.md", false},
		{"file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result := isExecutableCandidate(tt.filename)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContains(t *testing.T) {
	slice := []string{"apple", "banana", "cherry"}

	assert.True(t, contains(slice, "banana"))
	assert.False(t, contains(slice, "date"))
	assert.True(t, contains(slice, "apple"))
	assert.False(t, contains([]string{}, "anything"))
}

func TestGetNodeEntrypoint_WithMain(t *testing.T) {
	tempDir := t.TempDir()

	packageJSON := []byte(`{
		"name": "myapp",
		"main": "src/server.js"
	}`)

	err := os.WriteFile(filepath.Join(tempDir, "package.json"), packageJSON, 0o644)
	require.NoError(t, err)

	cmd, err := getNodeEntrypoint(tempDir)
	require.NoError(t, err)
	assert.Equal(t, "node src/server.js", cmd)
}

func TestGetNodeEntrypoint_WithBin(t *testing.T) {
	tempDir := t.TempDir()

	packageJSON := []byte(`{
		"name": "myapp",
		"bin": {
			"myapp": "cli.js"
		}
	}`)

	err := os.WriteFile(filepath.Join(tempDir, "package.json"), packageJSON, 0o644)
	require.NoError(t, err)

	cmd, err := getNodeEntrypoint(tempDir)
	require.NoError(t, err)
	assert.Equal(t, "node cli.js", cmd)
}

func TestGetNodeEntrypoint_Default(t *testing.T) {
	tempDir := t.TempDir()

	packageJSON := []byte(`{
		"name": "myapp"
	}`)

	err := os.WriteFile(filepath.Join(tempDir, "package.json"), packageJSON, 0o644)
	require.NoError(t, err)

	cmd, err := getNodeEntrypoint(tempDir)
	require.NoError(t, err)
	assert.Equal(t, "node index.js", cmd)
}

func TestGetPythonEntrypoint_MainPy(t *testing.T) {
	tempDir := t.TempDir()

	err := os.WriteFile(filepath.Join(tempDir, "main.py"), []byte("print('hi')"), 0o644)
	require.NoError(t, err)

	cmd, err := getPythonEntrypoint(tempDir)
	require.NoError(t, err)
	assert.Equal(t, "python main.py", cmd)
}

func TestGetPythonEntrypoint_AppPy(t *testing.T) {
	tempDir := t.TempDir()

	err := os.WriteFile(filepath.Join(tempDir, "app.py"), []byte("from flask import Flask"), 0o644)
	require.NoError(t, err)

	cmd, err := getPythonEntrypoint(tempDir)
	require.NoError(t, err)
	assert.Equal(t, "python app.py", cmd)
}

func TestGetPythonEntrypoint_Package(t *testing.T) {
	tempDir := t.TempDir()

	// Create a package with __main__.py
	pkgDir := filepath.Join(tempDir, "mypackage")
	err := os.MkdirAll(pkgDir, 0o755)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(pkgDir, "__main__.py"), []byte("print('main')"), 0o644)
	require.NoError(t, err)

	cmd, err := getPythonEntrypoint(tempDir)
	require.NoError(t, err)
	assert.Equal(t, "python -m mypackage", cmd)
}

func TestGetGoEntrypoint_WithModuleName(t *testing.T) {
	tempDir := t.TempDir()

	goMod := []byte("module github.com/test/myapp\n\ngo 1.21")
	err := os.WriteFile(filepath.Join(tempDir, "go.mod"), goMod, 0o644)
	require.NoError(t, err)

	cmd, err := getGoEntrypoint(tempDir)
	require.NoError(t, err)
	assert.Equal(t, "./myapp", cmd)
}

func TestGetGoEntrypoint_WithMainGo(t *testing.T) {
	tempDir := t.TempDir()

	goMod := []byte("module myserver\n\ngo 1.21")
	err := os.WriteFile(filepath.Join(tempDir, "go.mod"), goMod, 0o644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte("package main"), 0o644)
	require.NoError(t, err)

	cmd, err := getGoEntrypoint(tempDir)
	require.NoError(t, err)
	assert.Equal(t, "./myserver", cmd)
}
