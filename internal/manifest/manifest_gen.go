package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PackageRef contains the package reference for manifest generation
type PackageRef struct {
	Org     string
	Name    string
	Version string
}

// GeneratorConfig contains configuration for manifest generation
type GeneratorConfig struct {
	// TransportType is either "stdio" or "http" (default: "stdio")
	TransportType string
	// HTTPPort is required if TransportType is "http"
	HTTPPort int
	// Description is optional package description
	Description string
	// Repository is optional repository URL
	Repository string
}

// GenerateManifest generates a manifest from a source directory
// It auto-detects the runtime, entrypoints, and applies safe defaults
func GenerateManifest(sourceDir string, pkg *PackageRef, config *GeneratorConfig) (*Manifest, error) {
	if sourceDir == "" {
		return nil, fmt.Errorf("source directory cannot be empty")
	}

	// Normalize paths
	sourceDir = filepath.Clean(sourceDir)

	// Validate package reference
	if pkg == nil {
		return nil, fmt.Errorf("package reference cannot be nil")
	}
	if pkg.Org == "" || pkg.Name == "" || pkg.Version == "" {
		return nil, fmt.Errorf("package org, name, and version are required")
	}

	// Use default config if not provided
	if config == nil {
		config = &GeneratorConfig{
			TransportType: "stdio",
		}
	}

	// Validate transport config
	if config.TransportType == "" {
		config.TransportType = "stdio"
	}
	if config.TransportType != "stdio" && config.TransportType != "http" {
		return nil, fmt.Errorf("transport type must be 'stdio' or 'http'")
	}
	if config.TransportType == "http" && config.HTTPPort <= 0 {
		return nil, fmt.Errorf("http port is required and must be > 0 for http transport")
	}

	// Detect runtime
	_, entrypointCmd, err := detectRuntime(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to detect runtime: %w", err)
	}

	// Generate entrypoints for common architectures
	entrypoints := generateEntrypoints(entrypointCmd)
	if len(entrypoints) == 0 {
		return nil, fmt.Errorf("failed to generate entrypoints")
	}

	// Build the manifest template
	// Note: Bundle digest and size will be filled in later when the bundle is created
	manifest := &Manifest{
		SchemaVersion: "1.0",
		Package: PackageInfo{
			ID:      fmt.Sprintf("%s/%s", pkg.Org, pkg.Name),
			Version: pkg.Version,
		},
		Bundle: BundleInfo{
			// These will be calculated when the bundle is created
			Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			SizeBytes: 0,
		},
		Transport: TransportInfo{
			Type: config.TransportType,
			Port: config.HTTPPort,
		},
		Entrypoints: entrypoints,
		Permissions: PermissionsInfo{
			Network:    []string{}, // Default: no network access
			FileSystem: []string{},  // Default: no filesystem access
			Subprocess: false,       // Default: no subprocess
		},
		Limits: LimitsInfo{
			MaxCPU:    1000,         // 1 CPU core
			MaxMemory: "512M",       // 512MB
			MaxPIDs:   100,          // 100 processes
			MaxFDs:    256,          // 256 file descriptors
			Timeout:   "30s",        // 30 second timeout
		},
	}

	// Validate the generated manifest structure
	// Note: Bundle digest will fail validation here, so we do a partial check
	if manifest.SchemaVersion == "" {
		return nil, fmt.Errorf("schema_version is required")
	}
	if manifest.Package.ID == "" || manifest.Package.Version == "" {
		return nil, fmt.Errorf("package id and version are required")
	}
	if manifest.Transport.Type == "" || manifest.Transport.Type != "stdio" && manifest.Transport.Type != "http" {
		return nil, fmt.Errorf("invalid transport type")
	}
	if len(manifest.Entrypoints) == 0 {
		return nil, fmt.Errorf("at least one entrypoint is required")
	}

	return manifest, nil
}

// RuntimeType represents the detected runtime type
type RuntimeType string

const (
	RuntimeNode   RuntimeType = "node"
	RuntimePython RuntimeType = "python"
	RuntimeGo     RuntimeType = "go"
	RuntimeBinary RuntimeType = "binary"
)

// detectRuntime detects the runtime type and entrypoint command
func detectRuntime(sourceDir string) (RuntimeType, string, error) {
	// Check for package.json (Node.js)
	if hasFile(sourceDir, "package.json") {
		entrypoint, err := getNodeEntrypoint(sourceDir)
		if err != nil {
			return "", "", fmt.Errorf("failed to detect Node.js entrypoint: %w", err)
		}
		return RuntimeNode, entrypoint, nil
	}

	// Check for requirements.txt or setup.py (Python)
	if hasFile(sourceDir, "requirements.txt") || hasFile(sourceDir, "setup.py") || hasFile(sourceDir, "pyproject.toml") {
		entrypoint, err := getPythonEntrypoint(sourceDir)
		if err != nil {
			return "", "", fmt.Errorf("failed to detect Python entrypoint: %w", err)
		}
		return RuntimePython, entrypoint, nil
	}

	// Check for go.mod (Go)
	if hasFile(sourceDir, "go.mod") {
		entrypoint, err := getGoEntrypoint(sourceDir)
		if err != nil {
			return "", "", fmt.Errorf("failed to detect Go entrypoint: %w", err)
		}
		return RuntimeGo, entrypoint, nil
	}

	// Fallback to binary detection
	entrypoint, err := getBinaryEntrypoint(sourceDir)
	if err != nil {
		return "", "", fmt.Errorf("failed to detect binary entrypoint: %w", err)
	}

	return RuntimeBinary, entrypoint, nil
}

// getNodeEntrypoint detects the Node.js entrypoint
func getNodeEntrypoint(sourceDir string) (string, error) {
	packageJSONPath := filepath.Join(sourceDir, "package.json")
	data, err := os.ReadFile(packageJSONPath)
	if err != nil {
		return "", fmt.Errorf("failed to read package.json: %w", err)
	}

	var packageJSON map[string]interface{}
	if err := json.Unmarshal(data, &packageJSON); err != nil {
		return "", fmt.Errorf("failed to parse package.json: %w", err)
	}

	// Try to find main field
	if main, ok := packageJSON["main"].(string); ok && main != "" {
		return fmt.Sprintf("node %s", main), nil
	}

	// Check for bin field (executable)
	if bin, ok := packageJSON["bin"].(map[string]interface{}); ok {
		for _, entry := range bin {
			if binPath, ok := entry.(string); ok {
				return fmt.Sprintf("node %s", binPath), nil
			}
		}
	}

	// Default to node with index.js
	return "node index.js", nil
}

// getPythonEntrypoint detects the Python entrypoint
func getPythonEntrypoint(sourceDir string) (string, error) {
	// Check for common entry points
	entrypoints := []string{
		"main.py",
		"app.py",
		"run.py",
		"server.py",
		"cli.py",
	}

	for _, ep := range entrypoints {
		if hasFile(sourceDir, ep) {
			return fmt.Sprintf("python %s", ep), nil
		}
	}

	// Look for __main__.py in a package
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return "", fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			if hasFile(filepath.Join(sourceDir, entry.Name()), "__main__.py") {
				return fmt.Sprintf("python -m %s", entry.Name()), nil
			}
		}
	}

	// Default to main.py
	return "python main.py", nil
}

// getGoEntrypoint detects the Go entrypoint
func getGoEntrypoint(sourceDir string) (string, error) {
	// Read go.mod to get module name
	goModPath := filepath.Join(sourceDir, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return "", fmt.Errorf("failed to read go.mod: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			moduleName := strings.TrimPrefix(line, "module ")
			moduleName = strings.TrimSpace(moduleName)
			// Return path to main binary (typically ./bin/module_name or just the module name)
			binaryName := filepath.Base(moduleName)
			return fmt.Sprintf("./%s", binaryName), nil
		}
	}

	// Fallback to searching for main.go
	if hasFile(sourceDir, "main.go") {
		return "./server", nil
	}

	return "./app", nil
}

// getBinaryEntrypoint detects a binary entrypoint
func getBinaryEntrypoint(sourceDir string) (string, error) {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return "", fmt.Errorf("failed to read directory: %w", err)
	}

	// Look for common binary names
	commonNames := []string{"server", "app", "main", "bin", "run"}

	for _, entry := range entries {
		if entry.IsDir() && contains(commonNames, entry.Name()) {
			return fmt.Sprintf("./%s", entry.Name()), nil
		}
	}

	// Fallback to looking for any executable-like file
	for _, entry := range entries {
		if !entry.IsDir() && isExecutableCandidate(entry.Name()) {
			return fmt.Sprintf("./%s", entry.Name()), nil
		}
	}

	// Final fallback
	return "./server", nil
}

// generateEntrypoints generates entrypoints for common OS/arch combinations
func generateEntrypoints(command string) []Entrypoint {
	// Start with empty slice for cross-platform support
	entrypoints := []Entrypoint{}

	// Add other common architectures if not already present
	osArchPairs := []struct {
		os   string
		arch string
	}{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
		{"windows", "amd64"},
	}

	seen := make(map[string]bool)
	for _, ep := range entrypoints {
		seen[fmt.Sprintf("%s/%s", ep.OS, ep.Arch)] = true
	}

	for _, pair := range osArchPairs {
		key := fmt.Sprintf("%s/%s", pair.os, pair.arch)
		if !seen[key] {
			// For cross-platform, we assume the same command works
			// (or it's a compiled binary that works on that platform)
			entrypoints = append(entrypoints, Entrypoint{
				OS:      pair.os,
				Arch:    pair.arch,
				Command: command,
			})
		}
	}

	return entrypoints
}

// Helper functions

// hasFile checks if a file exists in the directory
func hasFile(dir, filename string) bool {
	path := filepath.Join(dir, filename)
	_, err := os.Stat(path)
	return err == nil
}

// isExecutableCandidate checks if a filename looks like an executable
func isExecutableCandidate(name string) bool {
	// Exclude common non-executable files
	excludeExtensions := map[string]bool{
		".txt": true, ".md": true, ".json": true, ".yaml": true,
		".yml": true, ".toml": true, ".cfg": true, ".conf": true,
		".log": true, ".tmp": true, ".bak": true, ".sh": true,
	}

	for ext := range excludeExtensions {
		if strings.HasSuffix(name, ext) {
			return false
		}
	}

	// Check if it doesn't have a typical source extension
	sourceExtensions := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true,
		".java": true, ".rs": true, ".c": true, ".cpp": true,
	}

	for ext := range sourceExtensions {
		if strings.HasSuffix(name, ext) {
			return false
		}
	}

	// It's a candidate if it doesn't have a dot extension or has a generic one
	return !strings.Contains(name, ".")
}

// contains checks if a slice contains a string
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// SerializeManifest serializes a manifest to JSON bytes
func SerializeManifest(m *Manifest) ([]byte, error) {
	if m == nil {
		return nil, fmt.Errorf("manifest cannot be nil")
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal manifest: %w", err)
	}

	return data, nil
}

// SaveManifest saves a manifest to a file
func SaveManifest(m *Manifest, filePath string) error {
	if m == nil {
		return fmt.Errorf("manifest cannot be nil")
	}

	data, err := SerializeManifest(m)
	if err != nil {
		return err
	}

	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		return fmt.Errorf("failed to write manifest file: %w", err)
	}

	return nil
}

// LoadManifest loads a manifest from a file
func LoadManifest(filePath string) (*Manifest, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	return Parse(data)
}
