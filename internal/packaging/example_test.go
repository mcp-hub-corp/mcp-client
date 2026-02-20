package packaging

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBundlerExample demonstrates creating a bundle in a test context
func TestBundlerExample(t *testing.T) {
	// Create a temporary directory structure
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "my-mcp")

	// Create example MCP structure
	os.MkdirAll(filepath.Join(sourceDir, "bin"), 0o755)
	os.WriteFile(filepath.Join(sourceDir, "manifest.json"), []byte(`{
		"schema_version": "1.0",
		"package": {
			"id": "acme/my-mcp",
			"version": "1.0.0"
		}
	}`), 0o644)
	os.WriteFile(filepath.Join(sourceDir, "README.md"), []byte("# My MCP"), 0o644)
	os.WriteFile(filepath.Join(sourceDir, "bin", "mcp-server"), []byte("#!/bin/bash"), 0o755)

	// Create bundle
	bundler := NewBundler()
	result, err := bundler.Create(sourceDir, filepath.Join(tmpDir, "bundle.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}

	if result.FileCount != 3 {
		t.Fatalf("expected 3 files, got %d", result.FileCount)
	}
	if result.DirCount != 1 {
		t.Fatalf("expected 1 directory, got %d", result.DirCount)
	}
}

// TestBundlerWithIgnoreExample demonstrates bundling with .mcpignore
func TestBundlerWithIgnoreExample(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "my-mcp")

	// Create directory structure with files to ignore
	os.MkdirAll(sourceDir, 0o755)
	os.MkdirAll(filepath.Join(sourceDir, "src"), 0o755)
	os.MkdirAll(filepath.Join(sourceDir, "node_modules"), 0o755)
	os.WriteFile(filepath.Join(sourceDir, "src", "main.go"), []byte("package main"), 0o644)
	os.WriteFile(filepath.Join(sourceDir, "node_modules", "pkg.js"), []byte("module.exports"), 0o644)
	os.WriteFile(filepath.Join(sourceDir, "debug.log"), []byte("log"), 0o644)

	// Create .mcpignore
	mcpignore := filepath.Join(sourceDir, ".mcpignore")
	os.WriteFile(mcpignore, []byte("node_modules/\n*.log\n.mcpignore"), 0o644)

	// Bundle with ignore patterns
	bundler := NewBundler()
	bundler.LoadIgnoreFile(mcpignore)
	result, err := bundler.Create(sourceDir, filepath.Join(tmpDir, "bundle.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}

	if result.FileCount != 1 {
		t.Fatalf("expected 1 file, got %d", result.FileCount)
	}
}

// TestBundlerProgrammaticExample demonstrates adding patterns programmatically
func TestBundlerProgrammaticExample(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "my-mcp")

	// Create directory structure
	os.MkdirAll(sourceDir, 0o755)
	os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte("code"), 0o644)
	os.WriteFile(filepath.Join(sourceDir, "main.test"), []byte("test"), 0o644)
	os.WriteFile(filepath.Join(sourceDir, "debug.log"), []byte("log"), 0o644)

	// Add patterns programmatically
	bundler := NewBundler()
	bundler.AddIgnorePattern("*.test")
	bundler.AddIgnorePattern("*.log")

	result, err := bundler.Create(sourceDir, filepath.Join(tmpDir, "bundle.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}

	if result.FileCount != 1 {
		t.Fatalf("expected 1 file, got %d", result.FileCount)
	}
}
