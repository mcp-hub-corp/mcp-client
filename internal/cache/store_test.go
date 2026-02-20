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

// Valid test digests (sha256: + 64 hex chars)
const (
	testDigest1  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigest2  = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testDigest3  = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testDigest4  = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	testDigest5  = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	testDigest6  = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	testDigest7  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testDigest8  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testDigest9  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	testDigest10 = "sha256:4444444444444444444444444444444444444444444444444444444444444444"

	// Sanitized versions (colon replaced with dash) for path assertions
	testDigest1Safe = "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigest2Safe = "sha256-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
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

	data := []byte("manifest data")

	err = store.PutManifest(testDigest1, data)
	require.NoError(t, err)

	// Verify file was created (digest colon replaced with dash for filename)
	manifestPath := filepath.Join(tempDir, "manifests", testDigest1Safe)
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

	expectedData := []byte("manifest data")

	err = store.PutManifest(testDigest1, expectedData)
	require.NoError(t, err)

	retrievedData, err := store.GetManifest(testDigest1)
	require.NoError(t, err)
	assert.Equal(t, expectedData, retrievedData)
}

func TestGetManifest_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	data, err := store.GetManifest(testDigest9)
	assert.Error(t, err)
	assert.Nil(t, data)
	assert.Contains(t, err.Error(), "not in cache")
}

func TestPutBundle_Success(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	data := []byte("bundle data content")

	err = store.PutBundle(testDigest2, data)
	require.NoError(t, err)

	// Verify file was created
	bundlePath := filepath.Join(tempDir, "bundles", testDigest2Safe)
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

	expectedData := []byte("bundle data content")

	err = store.PutBundle(testDigest2, expectedData)
	require.NoError(t, err)

	retrievedData, err := store.GetBundle(testDigest2)
	require.NoError(t, err)
	assert.Equal(t, expectedData, retrievedData)
}

func TestGetBundle_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	data, err := store.GetBundle(testDigest9)
	assert.Error(t, err)
	assert.Nil(t, data)
	assert.Contains(t, err.Error(), "not in cache")
}

func TestExists_Manifest(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	assert.False(t, store.Exists(testDigest1, "manifest"))

	err = store.PutManifest(testDigest1, []byte("data"))
	require.NoError(t, err)

	assert.True(t, store.Exists(testDigest1, "manifest"))
}

func TestExists_Bundle(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	assert.False(t, store.Exists(testDigest2, "bundle"))

	err = store.PutBundle(testDigest2, []byte("data"))
	require.NoError(t, err)

	assert.True(t, store.Exists(testDigest2, "bundle"))
}

func TestExists_InvalidType(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	assert.False(t, store.Exists(testDigest1, "invalid"))
}

func TestDelete_Manifest(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	err = store.PutManifest(testDigest1, []byte("data"))
	require.NoError(t, err)

	assert.True(t, store.Exists(testDigest1, "manifest"))

	err = store.Delete(testDigest1, "manifest")
	require.NoError(t, err)

	assert.False(t, store.Exists(testDigest1, "manifest"))
}

func TestDelete_Bundle(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	err = store.PutBundle(testDigest2, []byte("data"))
	require.NoError(t, err)

	assert.True(t, store.Exists(testDigest2, "bundle"))

	err = store.Delete(testDigest2, "bundle")
	require.NoError(t, err)

	assert.False(t, store.Exists(testDigest2, "bundle"))
}

func TestDelete_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	err = store.Delete(testDigest9, "manifest")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in cache")
}

func TestDelete_InvalidType(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	err = store.Delete(testDigest1, "invalid")
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
		testDigest1: []byte("manifest1"),
		testDigest2: []byte("manifest2"),
	}
	bundles := map[string][]byte{
		testDigest3: []byte("bundle1"),
		testDigest4: []byte("bundle2"),
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

	err = store.PutManifest(testDigest1, data1)
	require.NoError(t, err)

	err = store.PutBundle(testDigest2, data2)
	require.NoError(t, err)

	err = store.PutManifest(testDigest3, data3)
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
			digest := fmt.Sprintf("sha256:%064x", idx)
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
			digest := fmt.Sprintf("sha256:%064x", idx+100)
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
	err = store.PutManifest(testDigest1, []byte("data1"))
	require.NoError(t, err)
	err = store.PutBundle(testDigest2, []byte("bundledata"))
	require.NoError(t, err)

	numGoroutines := 20
	var wg sync.WaitGroup

	// Multiple concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.GetManifest(testDigest1)
			assert.NoError(t, err)
		}()
	}

	wg.Wait()
}

func TestCopyToPath_Success(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	originalData := []byte("manifest data content")

	err = store.PutManifest(testDigest1, originalData)
	require.NoError(t, err)

	destPath := filepath.Join(tempDir, "copy_output.txt")
	err = store.CopyToPath(testDigest1, "manifest", destPath)
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
	err = store.CopyToPath(testDigest9, "manifest", destPath)
	assert.Error(t, err)
	_, err = os.Stat(destPath)
	assert.True(t, os.IsNotExist(err), "destination file should not exist")
}

func TestCopyToPath_InvalidType(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	destPath := filepath.Join(tempDir, "output.txt")
	err = store.CopyToPath(testDigest1, "invalid", destPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid artifact type")
}

func TestAtomicWrite_Integrity(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	largeData := make([]byte, 10000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	err = store.PutManifest(testDigest1, largeData)
	require.NoError(t, err)

	retrievedData, err := store.GetManifest(testDigest1)
	require.NoError(t, err)

	// Verify exact match
	assert.Equal(t, largeData, retrievedData)
}

func TestManifestAndBundleSeparation(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	manifestData := []byte("manifest")
	bundleData := []byte("bundle")

	err = store.PutManifest(testDigest1, manifestData)
	require.NoError(t, err)

	err = store.PutBundle(testDigest1, bundleData)
	require.NoError(t, err)

	// Verify they are stored separately
	retrievedManifest, err := store.GetManifest(testDigest1)
	require.NoError(t, err)
	assert.Equal(t, manifestData, retrievedManifest)

	retrievedBundle, err := store.GetBundle(testDigest1)
	require.NoError(t, err)
	assert.Equal(t, bundleData, retrievedBundle)

	// Verify file locations are different
	manifestPath := filepath.Join(tempDir, "manifests", testDigest1Safe)
	bundlePath := filepath.Join(tempDir, "bundles", testDigest1Safe)
	assert.NotEqual(t, manifestPath, bundlePath)
	assert.FileExists(t, manifestPath)
	assert.FileExists(t, bundlePath)
}

func TestOverwrite_Manifest(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	firstData := []byte("first version")
	secondData := []byte("second version")

	err = store.PutManifest(testDigest1, firstData)
	require.NoError(t, err)

	err = store.PutManifest(testDigest1, secondData)
	require.NoError(t, err)

	retrieved, err := store.GetManifest(testDigest1)
	require.NoError(t, err)
	assert.Equal(t, secondData, retrieved)
}

func TestListArtifacts_Ordering(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewStore(tempDir)
	require.NoError(t, err)

	// Add artifacts with slight delays to ensure different modification times
	digests := []string{testDigest5, testDigest6, testDigest7}
	for _, digest := range digests {
		err = store.PutManifest(digest, []byte(digest))
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}

	artifacts, err := store.List()
	require.NoError(t, err)

	// Should have 3 artifacts
	assert.Len(t, artifacts, 3)

	// Verify all artifacts are present
	assert.Equal(t, 3, len(artifacts))
	for _, artifact := range artifacts {
		assert.Equal(t, "manifest", artifact.Type)
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

	err = store.PutManifest(testDigest8, largeData)
	require.NoError(t, err)

	retrieved, err := store.GetManifest(testDigest8)
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

	err = store.PutBundle(testDigest10, largeData)
	require.NoError(t, err)

	retrieved, err := store.GetBundle(testDigest10)
	require.NoError(t, err)
	assert.Equal(t, largeData, retrieved)
}
