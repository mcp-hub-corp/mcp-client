package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTarGzWithSymlink creates a test tar.gz bundle containing a symlink
func createTarGzWithSymlink(t *testing.T, symlinkName, symlinkTarget string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	// Add a regular file first
	regularFile := &tar.Header{
		Name:     "test.txt",
		Mode:     0o600,
		Size:     4,
		Typeflag: tar.TypeReg,
	}
	require.NoError(t, tarWriter.WriteHeader(regularFile))
	_, err := tarWriter.Write([]byte("test"))
	require.NoError(t, err)

	// Add the symlink
	symlinkHeader := &tar.Header{
		Name:     symlinkName,
		Linkname: symlinkTarget,
		Typeflag: tar.TypeSymlink,
	}
	require.NoError(t, tarWriter.WriteHeader(symlinkHeader))

	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzWriter.Close())

	return buf.Bytes()
}

// createTarGzWithHardlink creates a test tar.gz bundle containing a hardlink
func createTarGzWithHardlink(t *testing.T, hardlinkName, hardlinkTarget string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	// Add a regular file first (target of hardlink)
	regularFile := &tar.Header{
		Name:     hardlinkTarget,
		Mode:     0o600,
		Size:     4,
		Typeflag: tar.TypeReg,
	}
	require.NoError(t, tarWriter.WriteHeader(regularFile))
	_, err := tarWriter.Write([]byte("test"))
	require.NoError(t, err)

	// Add the hardlink
	hardlinkHeader := &tar.Header{
		Name:     hardlinkName,
		Linkname: hardlinkTarget,
		Typeflag: tar.TypeLink,
	}
	require.NoError(t, tarWriter.WriteHeader(hardlinkHeader))

	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzWriter.Close())

	return buf.Bytes()
}

// createTarGzWithUnknownType creates a test tar.gz bundle with an unknown tar type
func createTarGzWithUnknownType(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	// Add a header with an unknown/unsupported type
	unknownHeader := &tar.Header{
		Name:     "unknown.file",
		Typeflag: tar.TypeFifo, // FIFO is not supported
	}
	require.NoError(t, tarWriter.WriteHeader(unknownHeader))

	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzWriter.Close())

	return buf.Bytes()
}

func TestExtractBundleRejectsSymlinks(t *testing.T) {
	tests := []struct {
		name           string
		symlinkName    string
		symlinkTarget  string
		expectedErrMsg string
	}{
		{
			name:           "relative symlink",
			symlinkName:    "link.txt",
			symlinkTarget:  "../etc/passwd",
			expectedErrMsg: "symlinks and hardlinks not allowed in bundle: link.txt -> ../etc/passwd",
		},
		{
			name:           "absolute symlink",
			symlinkName:    "link.txt",
			symlinkTarget:  "/etc/passwd",
			expectedErrMsg: "symlinks and hardlinks not allowed in bundle: link.txt -> /etc/passwd",
		},
		{
			name:           "in-bundle symlink",
			symlinkName:    "link.txt",
			symlinkTarget:  "test.txt",
			expectedErrMsg: "symlinks and hardlinks not allowed in bundle: link.txt -> test.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory for extraction
			tmpDir, err := os.MkdirTemp("", "test-extract-*")
			require.NoError(t, err)
			defer func() {
				_ = os.RemoveAll(tmpDir)
			}()

			// Create tar.gz with symlink
			tarData := createTarGzWithSymlink(t, tt.symlinkName, tt.symlinkTarget)

			// Attempt extraction - should fail
			err = extractBundle(tarData, tmpDir)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErrMsg)

			// Verify the symlink was NOT created
			symlinkPath := filepath.Join(tmpDir, tt.symlinkName)
			_, err = os.Lstat(symlinkPath)
			assert.True(t, os.IsNotExist(err), "symlink should not have been created")
		})
	}
}

func TestExtractBundleRejectsHardlinks(t *testing.T) {
	tests := []struct {
		name           string
		hardlinkName   string
		hardlinkTarget string
		expectedErrMsg string
	}{
		{
			name:           "relative hardlink",
			hardlinkName:   "hardlink.txt",
			hardlinkTarget: "test.txt",
			expectedErrMsg: "symlinks and hardlinks not allowed in bundle: hardlink.txt -> test.txt",
		},
		{
			name:           "hardlink to parent directory",
			hardlinkName:   "hardlink.txt",
			hardlinkTarget: "../test.txt",
			// Note: Path traversal is detected in the target file name BEFORE
			// the hardlink check, so we get "invalid tar path" error
			expectedErrMsg: "invalid tar path: ../test.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temporary directory for extraction
			tmpDir, err := os.MkdirTemp("", "test-extract-*")
			require.NoError(t, err)
			defer func() {
				_ = os.RemoveAll(tmpDir)
			}()

			// Create tar.gz with hardlink
			tarData := createTarGzWithHardlink(t, tt.hardlinkName, tt.hardlinkTarget)

			// Attempt extraction - should fail
			err = extractBundle(tarData, tmpDir)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErrMsg)

			// Verify the hardlink was NOT created
			hardlinkPath := filepath.Join(tmpDir, tt.hardlinkName)
			_, err = os.Lstat(hardlinkPath)
			assert.True(t, os.IsNotExist(err), "hardlink should not have been created")
		})
	}
}

func TestExtractBundleRejectsUnknownTarTypes(t *testing.T) {
	// Create a temporary directory for extraction
	tmpDir, err := os.MkdirTemp("", "test-extract-*")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	// Create tar.gz with unknown type
	tarData := createTarGzWithUnknownType(t)

	// Attempt extraction - should fail
	err = extractBundle(tarData, tmpDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported tar type")
	assert.Contains(t, err.Error(), "unknown.file")
}

func TestExtractBundleSucceedsWithValidBundle(t *testing.T) {
	// Create a temporary directory for extraction
	tmpDir, err := os.MkdirTemp("", "test-extract-*")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	// Create a valid tar.gz with just regular files and directories
	var buf bytes.Buffer
	gzWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzWriter)

	// Add a directory
	dirHeader := &tar.Header{
		Name:     "subdir/",
		Mode:     0o750,
		Typeflag: tar.TypeDir,
	}
	require.NoError(t, tarWriter.WriteHeader(dirHeader))

	// Add a regular file in the directory
	fileHeader := &tar.Header{
		Name:     "subdir/test.txt",
		Mode:     0o600,
		Size:     12,
		Typeflag: tar.TypeReg,
	}
	require.NoError(t, tarWriter.WriteHeader(fileHeader))
	_, err = tarWriter.Write([]byte("Hello, World"))
	require.NoError(t, err)

	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzWriter.Close())

	// Extract the bundle - should succeed
	err = extractBundle(buf.Bytes(), tmpDir)
	require.NoError(t, err)

	// Verify the file was created correctly
	filePath := filepath.Join(tmpDir, "subdir", "test.txt")
	content, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, "Hello, World", string(content))

	// Verify directory permissions
	dirInfo, err := os.Stat(filepath.Join(tmpDir, "subdir"))
	require.NoError(t, err)
	assert.True(t, dirInfo.IsDir())

	// Verify file permissions (on Unix-like systems)
	fileInfo, err := os.Stat(filePath)
	require.NoError(t, err)
	// File should have restrictive permissions (0600 or similar)
	mode := fileInfo.Mode()
	assert.False(t, mode&0o077 == 0o077, "file should not be world-readable/writable")
}
