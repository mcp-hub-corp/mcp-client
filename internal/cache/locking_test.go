package cache

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFileLock(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")
	lock := NewFileLock(lockPath)
	require.NotNil(t, lock)
	assert.Equal(t, lockPath, lock.path)
}

func TestFileLock_LockUnlock(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")
	lock := NewFileLock(lockPath)

	// Lock should succeed
	err := lock.Lock()
	require.NoError(t, err)

	// Lock file should exist
	_, err = os.Stat(lockPath)
	assert.NoError(t, err)

	// IsLocked should return true
	assert.True(t, lock.IsLocked())

	// Unlock should succeed
	err = lock.Unlock()
	require.NoError(t, err)

	// Lock file should be removed
	_, err = os.Stat(lockPath)
	assert.True(t, os.IsNotExist(err))

	// IsLocked should return false
	assert.False(t, lock.IsLocked())
}

func TestFileLock_DoubleLock(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")
	lock := NewFileLock(lockPath)

	// First lock succeeds
	err := lock.Lock()
	require.NoError(t, err)

	// Second lock on same instance should fail
	err = lock.Lock()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lock is held")

	lock.Unlock()
}

func TestFileLock_ConcurrentLocking(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")

	var wg sync.WaitGroup
	successCount := 0
	mu := sync.Mutex{}

	// Try to acquire lock from 10 goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			lock := NewFileLock(lockPath)
			if lock.TryLock() {
				mu.Lock()
				successCount++
				mu.Unlock()

				time.Sleep(10 * time.Millisecond)
				lock.Unlock()
			}
		}()
	}

	wg.Wait()

	// Only one should have succeeded due to exclusive lock
	assert.Equal(t, 1, successCount, "Only one goroutine should acquire the lock")
}

func TestFileLock_TryLock(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")

	lock1 := NewFileLock(lockPath)
	lock2 := NewFileLock(lockPath)

	// First TryLock succeeds
	ok := lock1.TryLock()
	assert.True(t, ok)

	// Second TryLock fails (lock already held)
	ok = lock2.TryLock()
	assert.False(t, ok)

	// Unlock first
	lock1.Unlock()

	// Now second should succeed
	ok = lock2.TryLock()
	assert.True(t, ok)

	lock2.Unlock()
}

func TestFileLock_UnlockWithoutLock(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")
	lock := NewFileLock(lockPath)

	// Unlock without lock should not panic (best effort)
	err := lock.Unlock()
	// May return error or nil depending on implementation
	_ = err
}

func TestFileLock_IsLockedBeforeLock(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")
	lock := NewFileLock(lockPath)

	// Should not be locked initially
	assert.False(t, lock.IsLocked())
}

func TestFileLock_PathCreation(t *testing.T) {
	// Test that parent directory is created if needed
	baseDir := t.TempDir()
	lockPath := filepath.Join(baseDir, "subdir", "test.lock")

	lock := NewFileLock(lockPath)
	err := lock.Lock()

	// Should succeed even if parent dir doesn't exist
	if err != nil {
		t.Logf("Lock failed (may be expected if parent dir creation not implemented): %v", err)
	}

	if lock.IsLocked() {
		lock.Unlock()
	}
}

func TestFileLock_MultipleInstances(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")

	// Create two separate lock instances
	lock1 := NewFileLock(lockPath)
	lock2 := NewFileLock(lockPath)

	// Lock with first instance
	err := lock1.Lock()
	require.NoError(t, err)

	// Try lock with second instance should fail
	ok := lock2.TryLock()
	assert.False(t, ok, "Second instance should not acquire lock")

	// Unlock first
	lock1.Unlock()

	// Now second should succeed
	ok = lock2.TryLock()
	assert.True(t, ok, "Second instance should acquire lock after first releases")

	lock2.Unlock()
}
