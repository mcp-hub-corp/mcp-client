package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore_Success(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)
	assert.NotNil(t, store)
	assert.Equal(t, tempDir, store.baseDir)

	// Verify directories were created
	assert.DirExists(t, filepath.Join(tempDir, "manifests"))
	assert.DirExists(t, filepath.Join(tempDir, "bundles"))
}

func TestNewStore_EmptyBaseDir(t *testing.T) {
	store, err := NewStore("")
	assert.Error(t, err)
	assert.Nil(t, store)
}

func TestPutManifest_Success(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:abc123def456"
	data := []byte("manifest data")

	err = store.PutManifest(digest, data)
	require.NoError(t, err)

	// Verify file was created
	manifestPath := filepath.Join(tempDir, "manifests", digest)
	assert.FileExists(t, manifestPath)

	// Verify permissions
	info, err := os.Stat(manifestPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode())
}

func TestGetManifest_Success(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:abc123def456"
	expectedData := []byte("manifest data")

	err = store.PutManifest(digest, expectedData)
	require.NoError(t, err)

	retrievedData, err := store.GetManifest(digest)
	require.NoError(t, err)
	assert.Equal(t, expectedData, retrievedData)
}

func TestGetManifest_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	data, err := store.GetManifest("sha256:nonexistent")
	assert.Error(t, err)
	assert.Nil(t, data)
	assert.Contains(t, err.Error(), "not in cache")
}

func TestPutBundle_Success(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:xyz789abc123"
	data := []byte("bundle data content")

	err = store.PutBundle(digest, data)
	require.NoError(t, err)

	// Verify file was created
	bundlePath := filepath.Join(tempDir, "bundles", digest)
	assert.FileExists(t, bundlePath)

	// Verify permissions
	info, err := os.Stat(bundlePath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode())
}

func TestGetBundle_Success(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:xyz789abc123"
	expectedData := []byte("bundle data content")

	err = store.PutBundle(digest, expectedData)
	require.NoError(t, err)

	retrievedData, err := store.GetBundle(digest)
	require.NoError(t, err)
	assert.Equal(t, expectedData, retrievedData)
}

func TestGetBundle_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	data, err := store.GetBundle("sha256:nonexistent")
	assert.Error(t, err)
	assert.Nil(t, data)
	assert.Contains(t, err.Error(), "not in cache")
}

func TestExists_Manifest(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:abc123def456"
	assert.False(t, store.Exists(digest, "manifest"))

	err = store.PutManifest(digest, []byte("data"))
	require.NoError(t, err)

	assert.True(t, store.Exists(digest, "manifest"))
}

func TestExists_Bundle(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:xyz789abc123"
	assert.False(t, store.Exists(digest, "bundle"))

	err = store.PutBundle(digest, []byte("data"))
	require.NoError(t, err)

	assert.True(t, store.Exists(digest, "bundle"))
}

func TestExists_InvalidType(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	assert.False(t, store.Exists("sha256:abc123", "invalid"))
}

func TestDelete_Manifest(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:abc123def456"
	err = store.PutManifest(digest, []byte("data"))
	require.NoError(t, err)

	assert.True(t, store.Exists(digest, "manifest"))

	err = store.Delete(digest, "manifest")
	require.NoError(t, err)

	assert.False(t, store.Exists(digest, "manifest"))
}

func TestDelete_Bundle(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:xyz789abc123"
	err = store.PutBundle(digest, []byte("data"))
	require.NoError(t, err)

	assert.True(t, store.Exists(digest, "bundle"))

	err = store.Delete(digest, "bundle")
	require.NoError(t, err)

	assert.False(t, store.Exists(digest, "bundle"))
}

func TestDelete_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	err = store.Delete("sha256:nonexistent", "manifest")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in cache")
}

func TestDelete_InvalidType(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	err = store.Delete("sha256:abc123", "invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid artifact type")
}

func TestList_Empty(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	artifacts, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, artifacts)
}

func TestList_MultipleArtifacts(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	// Add multiple manifests and bundles
	manifests := map[string][]byte{
		"sha256:manifest1": []byte("manifest1"),
		"sha256:manifest2": []byte("manifest2"),
	}
	bundles := map[string][]byte{
		"sha256:bundle1": []byte("bundle1"),
		"sha256:bundle2": []byte("bundle2"),
	}

	for digest, data := range manifests {
		err = store.PutManifest(digest, data)
		require.NoError(t, err)
	}

	for digest, data := range bundles {
		err = store.PutBundle(digest, data)
		require.NoError(t, err)
	}

	artifacts, err := store.List()
	require.NoError(t, err)

	assert.Len(t, artifacts, 4)

	// Verify artifact types and digests
	for _, artifact := range artifacts {
		if artifact.Type == "manifest" {
			assert.Contains(t, []string{"sha256:manifest1", "sha256:manifest2"}, artifact.Digest)
		} else {
			assert.Contains(t, []string{"sha256:bundle1", "sha256:bundle2"}, artifact.Digest)
		}
	}
}

func TestSize_Empty(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	size, err := store.Size()
	require.NoError(t, err)
	assert.Equal(t, int64(0), size)
}

func TestSize_MultipleArtifacts(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	data1 := []byte("manifest data")    // 13 bytes
	data2 := []byte("bundle data")      // 11 bytes
	data3 := []byte("another artifact") // 16 bytes

	err = store.PutManifest("sha256:manifest1", data1)
	require.NoError(t, err)

	err = store.PutBundle("sha256:bundle1", data2)
	require.NoError(t, err)

	err = store.PutManifest("sha256:manifest2", data3)
	require.NoError(t, err)

	size, err := store.Size()
	require.NoError(t, err)

	expectedSize := int64(len(data1) + len(data2) + len(data3))
	assert.Equal(t, expectedSize, size)
}

func TestConcurrentAccess_RaceDetection(t *testing.T) {
	tempDir := t.TempDir()
	store, storeErr := NewStore(tempDir)
	require.NoError(t, storeErr)

	numGoroutines := 10
	var wg sync.WaitGroup

	// Half goroutines write manifests
	for i := 0; i < numGoroutines/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			digest := fmt.Sprintf("sha256:manifest%d", idx)
			data := []byte(fmt.Sprintf("manifest data %d", idx))
			putErr := store.PutManifest(digest, data)
			assert.NoError(t, putErr)
		}(i)
	}

	// Half goroutines write bundles
	for i := numGoroutines / 2; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			digest := fmt.Sprintf("sha256:bundle%d", idx)
			data := []byte(fmt.Sprintf("bundle data %d", idx))
			putErr := store.PutBundle(digest, data)
			assert.NoError(t, putErr)
		}(i)
	}

	wg.Wait()

	// Verify all artifacts are present
	artifacts, err := store.List()
	require.NoError(t, err)
	assert.Len(t, artifacts, numGoroutines)
}

func TestConcurrentAccess_Read(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	// Pre-populate with some data
	err = store.PutManifest("sha256:manifest1", []byte("data1"))
	require.NoError(t, err)
	err = store.PutBundle("sha256:bundle1", []byte("bundledata"))
	require.NoError(t, err)

	numGoroutines := 20
	var wg sync.WaitGroup

	// Multiple concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.GetManifest("sha256:manifest1")
			assert.NoError(t, err)
		}()
	}

	wg.Wait()
}

func TestCopyToPath_Success(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:abc123def456"
	originalData := []byte("manifest data content")

	err = store.PutManifest(digest, originalData)
	require.NoError(t, err)

	destPath := filepath.Join(tempDir, "copy_output.txt")
	err = store.CopyToPath(digest, "manifest", destPath)
	require.NoError(t, err)

	// Verify file was copied
	assert.FileExists(t, destPath)

	// Verify content matches
	copiedData, err := os.ReadFile(destPath)
	require.NoError(t, err)
	assert.Equal(t, originalData, copiedData)
}

func TestCopyToPath_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	destPath := filepath.Join(tempDir, "output.txt")
	err = store.CopyToPath("sha256:nonexistent", "manifest", destPath)
	assert.Error(t, err)
	_, err = os.Stat(destPath)
	assert.True(t, os.IsNotExist(err), "destination file should not exist")
}

func TestCopyToPath_InvalidType(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	destPath := filepath.Join(tempDir, "output.txt")
	err = store.CopyToPath("sha256:abc123", "invalid", destPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid artifact type")
}

func TestAtomicWrite_Integrity(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:abc123def456"
	largeData := make([]byte, 10000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	err = store.PutManifest(digest, largeData)
	require.NoError(t, err)

	retrievedData, err := store.GetManifest(digest)
	require.NoError(t, err)

	// Verify exact match
	assert.Equal(t, largeData, retrievedData)
}

func TestManifestAndBundleSeparation(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:abc123"
	manifestData := []byte("manifest")
	bundleData := []byte("bundle")

	err = store.PutManifest(digest, manifestData)
	require.NoError(t, err)

	err = store.PutBundle(digest, bundleData)
	require.NoError(t, err)

	// Verify they are stored separately
	retrievedManifest, err := store.GetManifest(digest)
	require.NoError(t, err)
	assert.Equal(t, manifestData, retrievedManifest)

	retrievedBundle, err := store.GetBundle(digest)
	require.NoError(t, err)
	assert.Equal(t, bundleData, retrievedBundle)

	// Verify file locations are different
	manifestPath := filepath.Join(tempDir, "manifests", digest)
	bundlePath := filepath.Join(tempDir, "bundles", digest)
	assert.NotEqual(t, manifestPath, bundlePath)
	assert.FileExists(t, manifestPath)
	assert.FileExists(t, bundlePath)
}

func TestOverwrite_Manifest(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	digest := "sha256:abc123"
	firstData := []byte("first version")
	secondData := []byte("second version")

	err = store.PutManifest(digest, firstData)
	require.NoError(t, err)

	err = store.PutManifest(digest, secondData)
	require.NoError(t, err)

	retrieved, err := store.GetManifest(digest)
	require.NoError(t, err)
	assert.Equal(t, secondData, retrieved)
}

func TestListArtifacts_Ordering(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	// Add artifacts with slight delays to ensure different modification times
	digests := []string{"sha256:first", "sha256:second", "sha256:third"}
	for _, digest := range digests {
		err = store.PutManifest(digest, []byte(digest))
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}

	artifacts, err := store.List()
	require.NoError(t, err)

	// Should have 3 artifacts
	assert.Len(t, artifacts, 3)

	// Verify all digests are present
	digestMap := make(map[string]bool)
	for _, artifact := range artifacts {
		digestMap[artifact.Digest] = true
		assert.Equal(t, "manifest", artifact.Type)
	}

	for _, digest := range digests {
		assert.True(t, digestMap[digest], "digest should be in list: "+digest)
	}
}

func TestLargeData_Manifest(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	// Test with 1MB data
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	digest := "sha256:largemanifest"
	err = store.PutManifest(digest, largeData)
	require.NoError(t, err)

	retrieved, err := store.GetManifest(digest)
	require.NoError(t, err)
	assert.Equal(t, largeData, retrieved)
}

func TestLargeData_Bundle(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	// Test with 10MB data
	largeData := make([]byte, 10*1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	digest := "sha256:largebundle"
	err = store.PutBundle(digest, largeData)
	require.NoError(t, err)

	retrieved, err := store.GetBundle(digest)
	require.NoError(t, err)
	assert.Equal(t, largeData, retrieved)
}
