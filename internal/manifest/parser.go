package manifest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
)

// Manifest represents the complete MCP manifest structure
type Manifest struct {
	SchemaVersion string            `json:"schema_version"`
	Package       PackageInfo       `json:"package"`
	Bundle        BundleInfo        `json:"bundle"`
	Transport     TransportInfo     `json:"transport"`
	Entrypoints   []Entrypoint      `json:"entrypoints"`
	Permissions   PermissionsInfo   `json:"permissions_requested"`
	Limits        LimitsInfo        `json:"limits_recommended"`
}

// PackageInfo contains package metadata
type PackageInfo struct {
	ID      string `json:"id"`       // "org/name"
	Version string `json:"version"`  // semantic version
	GitSHA  string `json:"git_sha"`  // git commit SHA
}

// BundleInfo contains bundle metadata
type BundleInfo struct {
	Digest    string `json:"digest"`     // SHA-256 digest
	SizeBytes int64  `json:"size_bytes"` // bundle size
}

// TransportInfo describes the transport mechanism
type TransportInfo struct {
	Type string `json:"type"` // "stdio" or "http"
	Port int    `json:"port,omitempty"`
}

// Entrypoint represents an executable entry point
type Entrypoint struct {
	OS      string   `json:"os"`        // "linux", "darwin", "windows"
	Arch    string   `json:"arch"`      // "amd64", "arm64"
	Command string   `json:"command"`   // path to executable
	Args    []string `json:"args,omitempty"`
}

// PermissionsInfo contains requested permissions
type PermissionsInfo struct {
	Network      []string `json:"network,omitempty"`       // allowlist of domains/IPs
	Environment  []string `json:"environment,omitempty"`   // env var allowlist
	Subprocess   bool     `json:"subprocess"`              // allow subprocess creation
	FileSystem   []string `json:"filesystem,omitempty"`    // filesystem paths allowlist
}

// LimitsInfo contains recommended resource limits
type LimitsInfo struct {
	MaxCPU    int    `json:"max_cpu"`      // millicores
	MaxMemory string `json:"max_memory"`   // e.g. "512M"
	MaxPIDs   int    `json:"max_pids"`
	MaxFDs    int    `json:"max_fds"`
	Timeout   string `json:"timeout"` // e.g. "5m"
}

// Parse parses a manifest from JSON bytes
func Parse(data []byte) (*Manifest, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("manifest data cannot be empty")
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest JSON: %w", err)
	}

	return &manifest, nil
}

// Validate validates a manifest schema and required fields
func Validate(manifest *Manifest) error {
	if manifest == nil {
		return fmt.Errorf("manifest cannot be nil")
	}

	// Validate schema version
	if manifest.SchemaVersion == "" {
		return fmt.Errorf("schema_version is required")
	}

	// Validate package info
	if manifest.Package.ID == "" {
		return fmt.Errorf("package.id is required")
	}
	if !isValidPackageID(manifest.Package.ID) {
		return fmt.Errorf("package.id must be in format 'org/name', got: %s", manifest.Package.ID)
	}
	if manifest.Package.Version == "" {
		return fmt.Errorf("package.version is required")
	}

	// Validate bundle info
	if manifest.Bundle.Digest == "" {
		return fmt.Errorf("bundle.digest is required")
	}
	if !isValidDigest(manifest.Bundle.Digest) {
		return fmt.Errorf("bundle.digest must be a valid SHA-256 digest (sha256:hex...)")
	}
	if manifest.Bundle.SizeBytes <= 0 {
		return fmt.Errorf("bundle.size_bytes must be > 0")
	}

	// Validate transport info
	if manifest.Transport.Type == "" {
		return fmt.Errorf("transport.type is required")
	}
	if manifest.Transport.Type != "stdio" && manifest.Transport.Type != "http" {
		return fmt.Errorf("transport.type must be 'stdio' or 'http', got: %s", manifest.Transport.Type)
	}
	if manifest.Transport.Type == "http" && manifest.Transport.Port <= 0 {
		return fmt.Errorf("transport.port is required for http transport")
	}

	// Validate entrypoints
	if len(manifest.Entrypoints) == 0 {
		return fmt.Errorf("at least one entrypoint is required")
	}
	for i, ep := range manifest.Entrypoints {
		if ep.OS == "" {
			return fmt.Errorf("entrypoints[%d].os is required", i)
		}
		if !isValidOS(ep.OS) {
			return fmt.Errorf("entrypoints[%d].os must be 'linux', 'darwin', or 'windows', got: %s", i, ep.OS)
		}
		if ep.Arch == "" {
			return fmt.Errorf("entrypoints[%d].arch is required", i)
		}
		if !isValidArch(ep.Arch) {
			return fmt.Errorf("entrypoints[%d].arch must be 'amd64' or 'arm64', got: %s", i, ep.Arch)
		}
		if ep.Command == "" {
			return fmt.Errorf("entrypoints[%d].command is required", i)
		}
	}

	return nil
}

// SelectEntrypoint selects the appropriate entrypoint for the current OS/arch
func SelectEntrypoint(manifest *Manifest) (*Entrypoint, error) {
	if manifest == nil {
		return nil, fmt.Errorf("manifest cannot be nil")
	}

	currentOS := runtime.GOOS
	currentArch := runtime.GOARCH

	// Map Go runtime names to manifest names if needed
	manifestOS := currentOS
	manifestArch := currentArch

	// Go uses "darwin" for macOS, which matches our manifest format
	// Go uses "amd64" and "arm64", which match our manifest format

	for i := range manifest.Entrypoints {
		ep := &manifest.Entrypoints[i]
		if ep.OS == manifestOS && ep.Arch == manifestArch {
			return ep, nil
		}
	}

	return nil, fmt.Errorf("no entrypoint found for %s/%s", currentOS, currentArch)
}

// isValidPackageID validates package ID format (org/name)
func isValidPackageID(id string) bool {
	parts := strings.Split(id, "/")
	if len(parts) != 2 {
		return false
	}
	if parts[0] == "" || parts[1] == "" {
		return false
	}
	// Allow alphanumeric, hyphens, underscores
	re := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return re.MatchString(parts[0]) && re.MatchString(parts[1])
}

// isValidDigest validates SHA-256 digest format
func isValidDigest(digest string) bool {
	// Format: sha256:hexstring (64 hex chars after colon)
	re := regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	return re.MatchString(digest)
}

// isValidOS validates supported operating systems
func isValidOS(os string) bool {
	return os == "linux" || os == "darwin" || os == "windows"
}

// isValidArch validates supported architectures
func isValidArch(arch string) bool {
	return arch == "amd64" || arch == "arm64"
}
