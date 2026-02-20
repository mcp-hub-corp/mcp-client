package cache

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Store represents a content-addressable cache organized by digest
type Store struct {
	baseDir string
	lock    sync.RWMutex
}

// CachedArtifact represents metadata about a cached artifact
type CachedArtifact struct {
	Digest    string    // Digest (e.g., sha256:abc123...)
	Type      string    // "manifest" or "bundle"
	SizeBytes int64     // Size in bytes
	ModTime   time.Time // Last modification time
	Path      string    // Absolute path to the artifact
}

// NewStore creates a new cache store with the specified base directory
func NewStore(baseDir string) (*Store, error) {
	if baseDir == "" {
		return nil, fmt.Errorf("cache base directory cannot be empty")
	}

	// Create cache directories if they don't exist
	manifestDir := filepath.Join(baseDir, "manifests")
	bundleDir := filepath.Join(baseDir, "bundles")

	if err := os.MkdirAll(manifestDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create manifest cache directory: %w", err)
	}

	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create bundle cache directory: %w", err)
	}

	return &Store{
		baseDir: baseDir,
	}, nil
}

// GetManifest retrieves a manifest from cache by digest
func (s *Store) GetManifest(digest string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	path := s.manifestPath(digest)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("manifest not in cache: %s", digest)
		}
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	return data, nil
}

// PutManifest stores a manifest in cache with atomic write semantics
func (s *Store) PutManifest(digest string, data []byte) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.putArtifact(digest, data, "manifests")
}

// GetBundle retrieves a bundle from cache by digest
func (s *Store) GetBundle(digest string) ([]byte, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	path := s.bundlePath(digest)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("bundle not in cache: %s", digest)
		}
		return nil, fmt.Errorf("failed to read bundle: %w", err)
	}

	return data, nil
}

// PutBundle stores a bundle in cache with atomic write semantics
func (s *Store) PutBundle(digest string, data []byte) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	return s.putArtifact(digest, data, "bundles")
}

// Exists checks if an artifact exists in cache by digest
func (s *Store) Exists(digest, artifactType string) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var path string
	switch artifactType {
	case "manifest":
		path = s.manifestPath(digest)
	case "bundle":
		path = s.bundlePath(digest)
	default:
		return false
	}

	_, err := os.Stat(path)
	return err == nil
}

// Delete removes an artifact from cache by digest
func (s *Store) Delete(digest, artifactType string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	var path string
	switch artifactType {
	case "manifest":
		path = s.manifestPath(digest)
	case "bundle":
		path = s.bundlePath(digest)
	default:
		return fmt.Errorf("invalid artifact type: %s", artifactType)
	}

	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("artifact not in cache: %s", digest)
		}
		return fmt.Errorf("failed to delete artifact: %w", err)
	}

	return nil
}

// List returns all cached artifacts
func (s *Store) List() ([]CachedArtifact, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var artifacts []CachedArtifact

	// List manifests
	manifestDir := filepath.Join(s.baseDir, "manifests")
	manifestArtifacts, err := s.listArtifacts(manifestDir, "manifest")
	if err != nil {
		return nil, fmt.Errorf("failed to list manifests: %w", err)
	}
	artifacts = append(artifacts, manifestArtifacts...)

	// List bundles
	bundleDir := filepath.Join(s.baseDir, "bundles")
	bundleArtifacts, err := s.listArtifacts(bundleDir, "bundle")
	if err != nil {
		return nil, fmt.Errorf("failed to list bundles: %w", err)
	}
	artifacts = append(artifacts, bundleArtifacts...)

	return artifacts, nil
}

// Size returns the total cache size in bytes
func (s *Store) Size() (int64, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var totalSize int64

	err := filepath.Walk(filepath.Join(s.baseDir, "manifests"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return 0, fmt.Errorf("failed to calculate cache size for manifests: %w", err)
	}

	err = filepath.Walk(filepath.Join(s.baseDir, "bundles"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return 0, fmt.Errorf("failed to calculate cache size for bundles: %w", err)
	}

	return totalSize, nil
}

// putArtifact stores an artifact with atomic write semantics using temp file + rename
func (s *Store) putArtifact(digest string, data []byte, dir string) error {
	// Validate digest format before using as path
	safeDigest, err := sanitizeDigest(digest)
	if err != nil {
		return fmt.Errorf("invalid digest for cache storage: %w", err)
	}

	artifactDir := filepath.Join(s.baseDir, dir)
	targetPath := filepath.Join(artifactDir, safeDigest)

	// Create temp file in the same directory to ensure atomic rename
	tempFile, err := os.CreateTemp(artifactDir, "tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tempPath := tempFile.Name()
	defer func() {
		// Clean up temp file if it still exists (in case of error)
		_ = os.Remove(tempPath) //nolint:errcheck // cleanup in defer
	}()

	// Write data to temp file
	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close() //nolint:errcheck // best effort close on error
		return fmt.Errorf("failed to write to temporary file: %w", err)
	}

	// Sync to ensure data is written to disk
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close() //nolint:errcheck // best effort close on error
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	// Atomically rename temp file to target path
	if err := os.Rename(tempPath, targetPath); err != nil {
		return fmt.Errorf("failed to move artifact to cache: %w", err)
	}

	// Ensure restrictive permissions
	if err := os.Chmod(targetPath, 0o600); err != nil {
		// Log but don't fail - the artifact is already in place
		_ = err //nolint:errcheck // chmod failure is not critical
	}

	return nil
}

// digestPattern validates digest format: sha256:<64 hex chars>
var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// sanitizeDigest validates and sanitizes a digest for use as a filename
func sanitizeDigest(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("invalid digest format: %s", digest)
	}
	// Reject any path separators
	if strings.ContainsAny(digest, "/\\") {
		return "", fmt.Errorf("digest contains path separators: %s", digest)
	}
	// Replace : with - for safe filename
	return strings.ReplaceAll(digest, ":", "-"), nil
}

// manifestPath returns the cache path for a manifest digest
func (s *Store) manifestPath(digest string) string {
	safe, err := sanitizeDigest(digest)
	if err != nil {
		// Fallback to replacing colon (caller should validate beforehand)
		safe = strings.ReplaceAll(digest, ":", "-")
	}
	return filepath.Join(s.baseDir, "manifests", safe)
}

// bundlePath returns the cache path for a bundle digest
func (s *Store) bundlePath(digest string) string {
	safe, err := sanitizeDigest(digest)
	if err != nil {
		safe = strings.ReplaceAll(digest, ":", "-")
	}
	return filepath.Join(s.baseDir, "bundles", safe)
}

// listArtifacts lists all artifacts in a directory
func (s *Store) listArtifacts(dir, artifactType string) ([]CachedArtifact, error) {
	var artifacts []CachedArtifact

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return artifacts, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		artifacts = append(artifacts, CachedArtifact{
			Digest:    entry.Name(),
			Type:      artifactType,
			SizeBytes: info.Size(),
			ModTime:   info.ModTime(),
			Path:      filepath.Join(dir, entry.Name()),
		})
	}

	return artifacts, nil
}

// CopyToPath copies a cached artifact to the specified destination path
func (s *Store) CopyToPath(digest, artifactType, destPath string) error {
	s.lock.RLock()
	defer s.lock.RUnlock()

	var srcPath string
	switch artifactType {
	case "manifest":
		srcPath = s.manifestPath(digest)
	case "bundle":
		srcPath = s.bundlePath(digest)
	default:
		return fmt.Errorf("invalid artifact type: %s", artifactType)
	}

	srcFile, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() {
		_ = srcFile.Close() //nolint:errcheck // best effort close
	}()

	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() {
		_ = destFile.Close() //nolint:errcheck // best effort close
	}()

	if _, err := io.Copy(destFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	if err := destFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync destination file: %w", err)
	}

	return nil
}
