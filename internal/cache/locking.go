package cache

import (
	"fmt"
	"os"
	"path/filepath"
)

// FileLock provides file-based locking for cache operations
type FileLock struct {
	path string
	file *os.File
}

// NewFileLock creates a new file lock for the specified path
func NewFileLock(path string) *FileLock {
	return &FileLock{
		path: path,
	}
}

// Lock acquires an exclusive lock on the file
// On Unix systems, this uses os.Open with O_EXCL for atomic creation
// On other systems, it creates a lock file that acts as a mutual exclusion mechanism
func (l *FileLock) Lock() error {
	if l.path == "" {
		return fmt.Errorf("lock path cannot be empty")
	}

	// Ensure lock directory exists
	lockDir := filepath.Dir(l.path)
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return fmt.Errorf("failed to create lock directory: %w", err)
	}

	// Try to create the lock file exclusively
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("lock is held by another process")
		}
		return fmt.Errorf("failed to acquire lock: %w", err)
	}

	l.file = file
	return nil
}

// Unlock releases the lock by removing the lock file
func (l *FileLock) Unlock() error {
	if l.file != nil {
		_ = l.file.Close() //nolint:errcheck // best effort close
		l.file = nil
	}

	if l.path == "" {
		return fmt.Errorf("lock path cannot be empty")
	}

	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to release lock: %w", err)
	}

	return nil
}

// TryLock attempts to acquire the lock without blocking
// Returns true if lock was acquired, false otherwise
func (l *FileLock) TryLock() bool {
	return l.Lock() == nil
}

// IsLocked checks if the lock file exists
func (l *FileLock) IsLocked() bool {
	if l.path == "" {
		return false
	}
	_, err := os.Stat(l.path)
	return err == nil
}
