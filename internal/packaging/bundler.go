package packaging

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// MaxBundleSize is the maximum uncompressed bundle size (1GB)
	MaxBundleSize = 1 * 1024 * 1024 * 1024 // 1GB

	// DefaultIgnoreFile is the default ignore file name
	DefaultIgnoreFile = ".mcpignore"

	// DefaultDirPerms are the default directory permissions (0750)
	DefaultDirPerms = 0o750

	// DefaultFilePerms are the default file permissions (0640)
	DefaultFilePerms = 0o640

	// NormalizedTime is the timestamp used for all files (reproducible builds)
	NormalizedTime = "2000-01-01T00:00:00Z"
)

var normalizedModTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

// Bundler creates reproducible tar.gz bundles from source directories
type Bundler struct {
	ignoreRules []*regexp.Regexp
}

// FileInfo represents information about a file to be bundled
type FileInfo struct {
	Path         string // relative path in bundle
	AbsPath      string // absolute path on disk
	Mode         os.FileMode
	IsDir        bool
	ModTime      time.Time
	Size         int64
	SHA256Digest string // only for files, not directories
}

// BundleResult contains the result of bundle creation
type BundleResult struct {
	Path             string // path to created bundle
	SHA256           string // SHA256 digest of bundle
	UncompressedSize int64  // uncompressed size in bytes
	CompressedSize   int64  // compressed size in bytes
	FileCount        int    // number of files bundled
	DirCount         int    // number of directories bundled
}

// NewBundler creates a new Bundler instance
func NewBundler() *Bundler {
	return &Bundler{
		ignoreRules: make([]*regexp.Regexp, 0),
	}
}

// LoadIgnoreFile loads ignore patterns from a .mcpignore file
func (b *Bundler) LoadIgnoreFile(ignoreFilePath string) error {
	if ignoreFilePath == "" {
		ignoreFilePath = DefaultIgnoreFile
	}

	file, err := os.Open(ignoreFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// It's OK if the file doesn't exist
			return nil
		}
		return fmt.Errorf("failed to open ignore file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Convert glob pattern to regex
		regex, err := globToRegex(line)
		if err != nil {
			return fmt.Errorf("invalid pattern on line %d: %w", lineNum, err)
		}

		b.ignoreRules = append(b.ignoreRules, regex)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading ignore file: %w", err)
	}

	return nil
}

// AddIgnorePattern adds an ignore pattern directly
func (b *Bundler) AddIgnorePattern(pattern string) error {
	if pattern == "" {
		return nil
	}

	regex, err := globToRegex(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}

	b.ignoreRules = append(b.ignoreRules, regex)
	return nil
}

// Create creates a tar.gz bundle from the source directory
func (b *Bundler) Create(sourceDir, outputPath string) (*BundleResult, error) {
	// Validate inputs
	if err := validateSourceDir(sourceDir); err != nil {
		return nil, fmt.Errorf("invalid source directory: %w", err)
	}

	if err := validateOutputPath(outputPath); err != nil {
		return nil, fmt.Errorf("invalid output path: %w", err)
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Create gzip writer
	gzipWriter := gzip.NewWriter(outFile)
	defer gzipWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Hash writer for SHA256 calculation
	hashWriter := sha256.New()
	multiWriter := io.MultiWriter(outFile, hashWriter)

	// Create gzip writer with hash
	gzipWriter = gzip.NewWriter(multiWriter)
	tarWriter = tar.NewWriter(gzipWriter)

	// Collect all files to bundle
	files, err := b.collectFiles(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to collect files: %w", err)
	}

	// Sort files for reproducible ordering
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	// Track sizes and counts
	var uncompressedSize int64
	var fileCount, dirCount int

	// Write files to tar archive
	for _, fileInfo := range files {
		if fileInfo.IsDir {
			if err := b.writeDirectory(tarWriter, fileInfo); err != nil {
				return nil, fmt.Errorf("failed to write directory %s: %w", fileInfo.Path, err)
			}
			dirCount++
		} else {
			n, err := b.writeFile(tarWriter, fileInfo)
			if err != nil {
				return nil, fmt.Errorf("failed to write file %s: %w", fileInfo.Path, err)
			}
			fileCount++
			uncompressedSize += n
		}

		// Check for decompression bomb
		if uncompressedSize > MaxBundleSize {
			return nil, fmt.Errorf("bundle exceeds maximum size of %d bytes", MaxBundleSize)
		}
	}

	// Close writers
	if err := tarWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}

	if err := gzipWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Get file info for sizes
	fileInfo, err := os.Stat(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat output file: %w", err)
	}

	compressedSize := fileInfo.Size()

	// Calculate final SHA256
	sha256Digest := fmt.Sprintf("sha256:%x", hashWriter.Sum(nil))

	return &BundleResult{
		Path:             outputPath,
		SHA256:           sha256Digest,
		UncompressedSize: uncompressedSize,
		CompressedSize:   compressedSize,
		FileCount:        fileCount,
		DirCount:         dirCount,
	}, nil
}

// collectFiles recursively collects all files from the source directory
func (b *Bundler) collectFiles(sourceDir string) ([]FileInfo, error) {
	var files []FileInfo

	err := filepath.Walk(sourceDir, func(absPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(sourceDir, absPath)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// Normalize path separators to forward slashes for consistent hashing
		relPath = filepath.ToSlash(relPath)

		// Skip root directory
		if relPath == "." {
			return nil
		}

		// Check if path should be ignored
		if b.shouldIgnore(relPath) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Avoid path traversal attacks
		if err := validatePathTraversal(sourceDir, absPath); err != nil {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		fileInfo := FileInfo{
			Path:    relPath,
			AbsPath: absPath,
			Mode:    info.Mode(),
			IsDir:   info.IsDir(),
			ModTime: info.ModTime(),
			Size:    info.Size(),
		}

		files = append(files, fileInfo)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

// writeDirectory writes a directory entry to the tar archive
func (b *Bundler) writeDirectory(tw *tar.Writer, fileInfo FileInfo) error {
	header := &tar.Header{
		Name:     fileInfo.Path + "/",
		Typeflag: tar.TypeDir,
		Mode:     int64(DefaultDirPerms),
		ModTime:  normalizedModTime,
	}

	return tw.WriteHeader(header)
}

// writeFile writes a file to the tar archive and returns the uncompressed size
func (b *Bundler) writeFile(tw *tar.Writer, fileInfo FileInfo) (int64, error) {
	file, err := os.Open(fileInfo.AbsPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	header := &tar.Header{
		Name:    fileInfo.Path,
		Mode:    int64(DefaultFilePerms),
		Size:    fileInfo.Size,
		ModTime: normalizedModTime,
		Typeflag: tar.TypeReg,
	}

	if err := tw.WriteHeader(header); err != nil {
		return 0, fmt.Errorf("failed to write header: %w", err)
	}

	n, err := io.Copy(tw, file)
	if err != nil {
		return 0, fmt.Errorf("failed to write file content: %w", err)
	}

	return n, nil
}

// shouldIgnore checks if a path matches any ignore rule
func (b *Bundler) shouldIgnore(path string) bool {
	for _, regex := range b.ignoreRules {
		if regex.MatchString(path) {
			return true
		}
	}
	return false
}

// globToRegex converts a glob pattern to a regular expression
// Supports patterns like:
// - *.log (matches files ending with .log)
// - .git/ (matches .git directory and contents)
// - node_modules/ (matches node_modules directory and contents)
// - **/*.tmp (matches .tmp files in any subdirectory)
// - **/node_modules/ (matches node_modules in any location)
func globToRegex(pattern string) (*regexp.Regexp, error) {
	// Escape special regex characters
	pattern = strings.TrimSpace(pattern)

	var regexPattern strings.Builder

	i := 0
	for i < len(pattern) {
		switch {
		case i+1 < len(pattern) && pattern[i:i+2] == "**":
			// ** matches any number of directories
			regexPattern.WriteString(".*")
			i += 2
			if i < len(pattern) && pattern[i] == '/' {
				regexPattern.WriteByte('/')
				i++
			}
		case pattern[i] == '*':
			// * matches anything except /
			regexPattern.WriteString("[^/]*")
			i++
		case pattern[i] == '?':
			// ? matches any single character except /
			regexPattern.WriteString("[^/]")
			i++
		case pattern[i] == '.':
			// . needs to be escaped in regex
			regexPattern.WriteString("\\.")
			i++
		case pattern[i] == '[':
			// [ starts a character class
			j := i + 1
			for j < len(pattern) && pattern[j] != ']' {
				j++
			}
			if j < len(pattern) {
				// Include the character class as-is
				regexPattern.WriteString(pattern[i : j+1])
				i = j + 1
			} else {
				// Unclosed bracket, treat as literal
				regexPattern.WriteString("\\[")
				i++
			}
		case pattern[i] == '/':
			regexPattern.WriteByte('/')
			i++
		case strings.ContainsAny(string(pattern[i]), "(){}+^$|\\"):
			// Escape other special regex characters
			regexPattern.WriteByte('\\')
			regexPattern.WriteByte(pattern[i])
			i++
		default:
			regexPattern.WriteByte(pattern[i])
			i++
		}
	}

	// Build the final pattern
	// If the pattern ends with /, match the directory and everything under it
	fullPattern := "^" + regexPattern.String()
	if strings.HasSuffix(pattern, "/") {
		// Match the directory itself or anything under it
		fullPattern = fullPattern + ".*"
	} else {
		// Match the exact pattern or with trailing slash
		fullPattern = fullPattern + "(/.*)?$"
	}
	fullPattern = fullPattern + "$"

	regex, err := regexp.Compile(fullPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid glob pattern: %w", err)
	}

	return regex, nil
}

// validateSourceDir validates that the source directory exists and is readable
func validateSourceDir(sourceDir string) error {
	info, err := os.Stat(sourceDir)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return fmt.Errorf("source path is not a directory")
	}

	// Check if we can read the directory
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	// At least one entry is recommended (but not required)
	_ = entries

	return nil
}

// validateOutputPath validates that the output path is valid
func validateOutputPath(outputPath string) error {
	if outputPath == "" {
		return fmt.Errorf("output path cannot be empty")
	}

	// Check that we can create the file in the parent directory
	parentDir := filepath.Dir(outputPath)
	if parentDir == "" {
		parentDir = "."
	}

	info, err := os.Stat(parentDir)
	if err != nil {
		return fmt.Errorf("output directory does not exist: %w", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("output parent path is not a directory")
	}

	// Check if output file already exists (warn but don't fail)
	if _, err := os.Stat(outputPath); err == nil {
		// File exists, it will be overwritten
		_ = err
	}

	return nil
}

// validatePathTraversal ensures a path doesn't escape the base directory
// SECURITY: Uses Lstat to NOT follow symlinks, preventing data exfiltration
func validatePathTraversal(baseDir, absPath string) error {
	// Use Lstat to NOT follow symlinks
	fi, err := os.Lstat(absPath)
	if err != nil {
		return fmt.Errorf("failed to stat path: %w", err)
	}

	// SECURITY: Reject symlinks to prevent data exfiltration
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlinks not allowed in source: %s", absPath)
	}

	// Clean paths without resolving symlinks
	cleanPath := filepath.Clean(absPath)
	cleanBase := filepath.Clean(baseDir)

	// Validate path is within base
	if !strings.HasPrefix(cleanPath+string(filepath.Separator), cleanBase+string(filepath.Separator)) {
		return fmt.Errorf("path traversal detected: %s escapes %s", absPath, baseDir)
	}

	return nil
}
