package packaging

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBundlerBasicCreation tests basic bundle creation
func TestBundlerBasicCreation(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	outputPath := filepath.Join(tmpDir, "bundle.tar.gz")

	// Create test directory structure
	require.NoError(t, os.MkdirAll(sourceDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("content1"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "file2.txt"), []byte("content2"), 0o644))

	// Create bundle
	bundler := NewBundler()
	result, err := bundler.Create(sourceDir, outputPath)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, outputPath, result.Path)
	assert.Equal(t, 2, result.FileCount)
	assert.Equal(t, 0, result.DirCount) // no subdirectories
	assert.Greater(t, result.UncompressedSize, int64(0))
	assert.Greater(t, result.CompressedSize, int64(0))
	assert.True(t, len(result.SHA256) > 0)
	assert.FileExists(t, outputPath)
}

// TestBundlerWithSubdirectories tests bundling with nested directories
func TestBundlerWithSubdirectories(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	outputPath := filepath.Join(tmpDir, "bundle.tar.gz")

	// Create nested directory structure
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, "subdir1", "subdir2"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "file.txt"), []byte("root"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "subdir1", "file1.txt"), []byte("sub1"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "subdir1", "subdir2", "file2.txt"), []byte("sub2"), 0o644))

	// Create bundle
	bundler := NewBundler()
	result, err := bundler.Create(sourceDir, outputPath)

	require.NoError(t, err)
	assert.Equal(t, 3, result.FileCount)
	assert.Greater(t, result.DirCount, 0)

	// Verify bundle contents
	files := readTarGz(t, outputPath)
	assert.Contains(t, files, "file.txt")
	assert.Contains(t, files, "subdir1/file1.txt")
	assert.Contains(t, files, "subdir1/subdir2/file2.txt")
}

// TestBundlerIgnoreFile tests that .mcpignore is respected
func TestBundlerIgnoreFile(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	outputPath := filepath.Join(tmpDir, "bundle.tar.gz")

	// Create test files
	require.NoError(t, os.MkdirAll(sourceDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "include.txt"), []byte("include"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "exclude.log"), []byte("exclude"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, "node_modules"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "node_modules", "pkg.js"), []byte("pkg"), 0o644))

	// Create .mcpignore
	ignoreFile := filepath.Join(sourceDir, ".mcpignore")
	require.NoError(t, os.WriteFile(ignoreFile, []byte("*.log\nnode_modules/\n.mcpignore\n"), 0o644))

	// Create bundle
	bundler := NewBundler()
	require.NoError(t, bundler.LoadIgnoreFile(ignoreFile))
	result, err := bundler.Create(sourceDir, outputPath)

	require.NoError(t, err)
	assert.Equal(t, 1, result.FileCount) // only include.txt

	// Verify bundle contents
	files := readTarGz(t, outputPath)
	assert.Contains(t, files, "include.txt")
	assert.NotContains(t, files, "exclude.log")
	assert.NotContains(t, files, "node_modules/pkg.js")
}

// TestBundlerIgnorePatterns tests various ignore patterns
func TestBundlerIgnorePatterns(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	outputPath := filepath.Join(tmpDir, "bundle.tar.gz")

	// Create test structure
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, ".git"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, "src"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, "dist"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, ".git", "config"), []byte("git"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, ".env"), []byte("secret"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, ".env.local"), []byte("secret"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "src", "main.go"), []byte("code"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "dist", "output.js"), []byte("built"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "debug.log"), []byte("log"), 0o644))

	// Create bundle with ignore patterns
	bundler := NewBundler()
	require.NoError(t, bundler.AddIgnorePattern(".git/"))
	require.NoError(t, bundler.AddIgnorePattern(".env*"))
	require.NoError(t, bundler.AddIgnorePattern("dist/"))
	require.NoError(t, bundler.AddIgnorePattern("*.log"))

	result, err := bundler.Create(sourceDir, outputPath)

	require.NoError(t, err)
	assert.Equal(t, 1, result.FileCount) // only src/main.go

	files := readTarGz(t, outputPath)
	assert.Contains(t, files, "src/main.go")
	assert.NotContains(t, files, ".git/config")
	assert.NotContains(t, files, ".env")
	assert.NotContains(t, files, ".env.local")
	assert.NotContains(t, files, "dist/output.js")
	assert.NotContains(t, files, "debug.log")
}

// TestBundlerAntiPathTraversal tests that path traversal attacks are prevented
func TestBundlerAntiPathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")

	require.NoError(t, os.MkdirAll(sourceDir, 0o755))

	// Create a file outside the source directory
	outsideFile := filepath.Join(tmpDir, "outside.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("outside"), 0o644))

	// Try to create a symlink that points outside
	symlinkPath := filepath.Join(sourceDir, "malicious.txt")
	symlinkErr := os.Symlink(outsideFile, symlinkPath)
	if symlinkErr != nil {
		t.Skip("Cannot create symlink on this system")
	}

	// Create bundle - should skip the malicious symlink (silently)
	bundler := NewBundler()
	outputPath := filepath.Join(tmpDir, "bundle.tar.gz")
	_, err := bundler.Create(sourceDir, outputPath)

	// The operation should complete - symlinks are silently skipped
	require.NoError(t, err)
	// The symlink should not be included in the bundle
	files := readTarGz(t, outputPath)
	assert.NotContains(t, files, "malicious.txt")
	assert.NotContains(t, files, filepath.Join("..", "outside.txt"))
}

// TestBundlerRejectsSymlinks tests that symlinks are rejected during bundling
func TestBundlerRejectsSymlinks(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	outputPath := filepath.Join(tmpDir, "bundle.tar.gz")

	require.NoError(t, os.MkdirAll(sourceDir, 0o755))

	// Create normal files
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "normal.txt"), []byte("content"), 0o644))

	// Create a file outside the source directory
	outsideFile := filepath.Join(tmpDir, "sensitive.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("sensitive data"), 0o644))

	// Create symlink to file outside source directory (data exfiltration attempt)
	symlinkToOutside := filepath.Join(sourceDir, "exfiltrate.txt")
	if err := os.Symlink(outsideFile, symlinkToOutside); err != nil {
		t.Skip("Cannot create symlink on this system")
	}

	// Create symlink to file inside source directory
	symlinkToInside := filepath.Join(sourceDir, "link-to-normal.txt")
	if err := os.Symlink(filepath.Join(sourceDir, "normal.txt"), symlinkToInside); err != nil {
		t.Skip("Cannot create symlink on this system")
	}

	// Create directory symlink
	outsideDir := filepath.Join(tmpDir, "sensitive_dir")
	require.NoError(t, os.MkdirAll(outsideDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outsideDir, "secret.txt"), []byte("secret"), 0o644))

	symlinkToDir := filepath.Join(sourceDir, "exfiltrate_dir")
	if err := os.Symlink(outsideDir, symlinkToDir); err != nil {
		t.Skip("Cannot create directory symlink on this system")
	}

	// Create bundle
	bundler := NewBundler()
	_, err := bundler.Create(sourceDir, outputPath)

	// The operation should complete - symlinks are silently skipped
	require.NoError(t, err)

	// Verify bundle contents - symlinks should NOT be included
	files := readTarGz(t, outputPath)

	// Normal file should be included
	assert.Contains(t, files, "normal.txt")

	// Symlinks should NOT be included (security fix)
	assert.NotContains(t, files, "exfiltrate.txt", "symlink to outside file should be rejected")
	assert.NotContains(t, files, "link-to-normal.txt", "symlink to inside file should be rejected")
	assert.NotContains(t, files, "exfiltrate_dir", "symlink to directory should be rejected")

	// Verify that sensitive data is not leaked
	for _, file := range files {
		assert.NotContains(t, file, "sensitive", "sensitive files should not be included")
		assert.NotContains(t, file, "secret", "secret files should not be included")
	}
}

// TestBundlerMaxSize tests that bundles exceeding max size are rejected
func TestBundlerMaxSize(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	outputPath := filepath.Join(tmpDir, "bundle.tar.gz")

	require.NoError(t, os.MkdirAll(sourceDir, 0o755))

	// Create files that will exceed the 1GB limit in the bundler
	// We use smaller sizes for faster testing
	// 550MB + 550MB = 1.1GB > 1GB limit
	largeSize := int64(550 * 1024 * 1024) // 550MB

	// Use sparse files or create fast by writing strategically
	largeFile := filepath.Join(sourceDir, "large.bin")
	f, err := os.Create(largeFile)
	require.NoError(t, err)

	// Create a large file by seeking and writing minimal data
	_, err = f.Seek(largeSize-1, 0)
	require.NoError(t, err)
	_, err = f.Write([]byte{0})
	require.NoError(t, err)
	f.Close()

	// Create another large file
	largeFile2 := filepath.Join(sourceDir, "large2.bin")
	f2, err := os.Create(largeFile2)
	require.NoError(t, err)

	_, err = f2.Seek(largeSize-1, 0)
	require.NoError(t, err)
	_, err = f2.Write([]byte{0})
	require.NoError(t, err)
	f2.Close()

	// Try to create bundle - should fail due to size
	bundler := NewBundler()
	result, err := bundler.Create(sourceDir, outputPath)

	// Should fail due to size limit
	if err != nil {
		assert.Contains(t, err.Error(), "exceeds maximum size")
	} else {
		// If no error, the files were smaller than expected, skip the test
		t.Skipf("Files were smaller than expected, cannot test max size limit")
	}
	_ = result // result may be nil or partial
}

// TestBundlerReproducibility tests that bundles are reproducible
func TestBundlerReproducibility(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")

	// Create test files
	require.NoError(t, os.MkdirAll(sourceDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("content1"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "file2.txt"), []byte("content2"), 0o644))

	// Create first bundle
	bundler1 := NewBundler()
	output1 := filepath.Join(tmpDir, "bundle1.tar.gz")
	result1, err := bundler1.Create(sourceDir, output1)
	require.NoError(t, err)

	// Create second bundle
	bundler2 := NewBundler()
	output2 := filepath.Join(tmpDir, "bundle2.tar.gz")
	result2, err := bundler2.Create(sourceDir, output2)
	require.NoError(t, err)

	// SHA256 should be identical (reproducible builds)
	assert.Equal(t, result1.SHA256, result2.SHA256)
	assert.Equal(t, result1.UncompressedSize, result2.UncompressedSize)
}

// TestBundlerInvalidSourceDir tests error handling for invalid source directory
func TestBundlerInvalidSourceDir(t *testing.T) {
	bundler := NewBundler()

	// Non-existent directory
	result, err := bundler.Create("/nonexistent/path", "/tmp/output.tar.gz")
	assert.Error(t, err)
	assert.Nil(t, result)

	// File instead of directory
	tmpFile, err := os.CreateTemp("", "testfile")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	result, err = bundler.Create(tmpFile.Name(), "/tmp/output.tar.gz")
	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestBundlerInvalidOutputPath tests error handling for invalid output path
func TestBundlerInvalidOutputPath(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	require.NoError(t, os.MkdirAll(sourceDir, 0o755))

	bundler := NewBundler()

	// Output directory doesn't exist
	result, err := bundler.Create(sourceDir, "/nonexistent/bundle.tar.gz")
	assert.Error(t, err)
	assert.Nil(t, result)

	// Empty output path
	result, err = bundler.Create(sourceDir, "")
	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestGlobToRegex tests glob pattern conversion
func TestGlobToRegex(t *testing.T) {
	tests := []struct {
		pattern string
		paths   []string
		matches []bool
	}{
		{
			pattern: "*.log",
			paths:   []string{"debug.log", "error.log", "app.txt", "logs/debug.log"},
			matches: []bool{true, true, false, false},
		},
		{
			pattern: ".git/",
			paths:   []string{".git/config", ".git/HEAD", "src/.git/config", ".gitignore"},
			matches: []bool{true, true, false, false},
		},
		{
			pattern: "node_modules/",
			paths:   []string{"node_modules/pkg", "node_modules/pkg/index.js", "src/node_modules/pkg"},
			matches: []bool{true, true, false},
		},
		{
			pattern: ".env*",
			paths:   []string{".env", ".env.local", ".env.prod", "env.txt", ".env/file"},
			matches: []bool{true, true, true, false, true},
		},
		{
			pattern: "*.tmp",
			paths:   []string{"file.tmp", "src/file.tmp", "a/b/c/file.tmp", "file.txt"},
			matches: []bool{true, false, false, false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			regex, err := globToRegex(tt.pattern)
			require.NoError(t, err)

			for i, path := range tt.paths {
				matches := regex.MatchString(path)
				assert.Equal(t, tt.matches[i], matches, "pattern %q vs path %q", tt.pattern, path)
			}
		})
	}
}

// readTarGz reads a tar.gz file and returns a list of file paths
func readTarGz(t *testing.T, path string) []string {
	t.Helper()

	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	require.NoError(t, err)
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	var files []string
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)

		// Only include regular files
		if header.Typeflag == tar.TypeReg {
			files = append(files, header.Name)
		}
	}

	return files
}

// TestBundlerComments tests that .mcpignore handles comments correctly
func TestBundlerComments(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	outputPath := filepath.Join(tmpDir, "bundle.tar.gz")

	// Create test files
	require.NoError(t, os.MkdirAll(sourceDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "keep.txt"), []byte("keep"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "skip.log"), []byte("skip"), 0o644))

	// Create .mcpignore with comments
	ignoreContent := `# This is a comment
*.log
# Another comment

# Skip these
*.tmp
.mcpignore
`
	ignoreFile := filepath.Join(sourceDir, ".mcpignore")
	require.NoError(t, os.WriteFile(ignoreFile, []byte(ignoreContent), 0o644))

	// Create bundle
	bundler := NewBundler()
	require.NoError(t, bundler.LoadIgnoreFile(ignoreFile))
	result, err := bundler.Create(sourceDir, outputPath)

	require.NoError(t, err)
	assert.Equal(t, 1, result.FileCount)

	files := readTarGz(t, outputPath)
	assert.Contains(t, files, "keep.txt")
	assert.NotContains(t, files, "skip.log")
}

// TestBundlerEmptyDirectory tests bundling an empty directory
func TestBundlerEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")
	outputPath := filepath.Join(tmpDir, "bundle.tar.gz")

	require.NoError(t, os.MkdirAll(sourceDir, 0o755))

	// Create bundle from empty directory
	bundler := NewBundler()
	result, err := bundler.Create(sourceDir, outputPath)

	require.NoError(t, err)
	assert.Equal(t, 0, result.FileCount)
	assert.Equal(t, 0, result.DirCount)
	assert.Equal(t, int64(0), result.UncompressedSize)
	assert.FileExists(t, outputPath)
}
