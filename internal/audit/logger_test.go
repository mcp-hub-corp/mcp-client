package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	logger, err := NewLogger(logFile)
	require.NoError(t, err)
	defer logger.Close() //nolint:errcheck // test cleanup

	assert.NotNil(t, logger)
	assert.NotNil(t, logger.file)
}

func TestNewLogger_EmptyPath(t *testing.T) {
	_, err := NewLogger("")
	assert.Error(t, err)
}

func TestNewLogger_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "subdir", "audit")
	logFile := filepath.Join(logDir, "audit.log")

	logger, err := NewLogger(logFile)
	require.NoError(t, err)
	defer logger.Close() //nolint:errcheck // test cleanup

	// Check directory was created
	assert.DirExists(t, logDir)
}

func TestLog_WritesJSON(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	logger, err := NewLogger(logFile)
	require.NoError(t, err)
	defer logger.Close() //nolint:errcheck // test cleanup

	event := Event{
		Type:    "start",
		Package: "acme/test",
		Version: "1.0.0",
	}

	err = logger.Log(event)
	require.NoError(t, err)

	// Read the file
	data, err := os.ReadFile(logFile)
	require.NoError(t, err)

	// Parse JSON
	var readEvent Event
	err = json.Unmarshal(data, &readEvent)
	require.NoError(t, err)

	assert.Equal(t, "start", readEvent.Type)
	assert.Equal(t, "acme/test", readEvent.Package)
	assert.Equal(t, "1.0.0", readEvent.Version)
}

func TestLog_MultipleEvents(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	logger, err := NewLogger(logFile)
	require.NoError(t, err)
	defer logger.Close() //nolint:errcheck // test cleanup

	event1 := Event{Type: "start", Package: "pkg1"}
	event2 := Event{Type: "end", Package: "pkg1", ExitCode: 0}

	err = logger.Log(event1)
	require.NoError(t, err)

	err = logger.Log(event2)
	require.NoError(t, err)

	// Read the file
	data, err := os.ReadFile(logFile)
	require.NoError(t, err)

	lines := string(data)
	// Should have two JSON events on separate lines
	assert.Contains(t, lines, `"start"`)
	assert.Contains(t, lines, `"end"`)
}

func TestLogStart(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	logger, err := NewLogger(logFile)
	require.NoError(t, err)
	defer logger.Close() //nolint:errcheck // test cleanup

	err = logger.LogStart("acme/test", "1.0.0", "sha256:abc", "./bin/server", "gitsha123")
	require.NoError(t, err)

	data, err := os.ReadFile(logFile)
	require.NoError(t, err)

	var event Event
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, "start", event.Type)
	assert.Equal(t, "acme/test", event.Package)
	assert.Equal(t, "1.0.0", event.Version)
	assert.Equal(t, "sha256:abc", event.Digest)
	assert.Equal(t, "./bin/server", event.Entrypoint)
	assert.Equal(t, "gitsha123", event.GitSHA)
}

func TestLogEnd(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	logger, err := NewLogger(logFile)
	require.NoError(t, err)
	defer logger.Close() //nolint:errcheck // test cleanup

	duration := 2 * time.Second
	err = logger.LogEnd("acme/test", "1.0.0", 0, duration, "success")
	require.NoError(t, err)

	data, err := os.ReadFile(logFile)
	require.NoError(t, err)

	var event Event
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, "end", event.Type)
	assert.Equal(t, "acme/test", event.Package)
	assert.Equal(t, "1.0.0", event.Version)
	assert.Equal(t, 0, event.ExitCode)
	assert.Equal(t, "success", event.Outcome)
	assert.Contains(t, event.Duration, "PT2")
}

func TestLogError(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	logger, err := NewLogger(logFile)
	require.NoError(t, err)
	defer logger.Close() //nolint:errcheck // test cleanup

	err = logger.LogError("acme/test", "1.0.0", "connection failed")
	require.NoError(t, err)

	data, err := os.ReadFile(logFile)
	require.NoError(t, err)

	var event Event
	err = json.Unmarshal(data, &event)
	require.NoError(t, err)

	assert.Equal(t, "error", event.Type)
	assert.Equal(t, "acme/test", event.Package)
	assert.Equal(t, "1.0.0", event.Version)
	assert.Equal(t, "connection failed", event.Error)
	assert.Equal(t, "error", event.Outcome)
}

func TestClose(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	logger, err := NewLogger(logFile)
	require.NoError(t, err)

	err = logger.Close()
	assert.NoError(t, err)

	// Closing again should succeed
	err = logger.Close()
	assert.NoError(t, err)
}

func TestLog_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	logger, err := NewLogger(logFile)
	require.NoError(t, err)
	defer logger.Close() //nolint:errcheck // test cleanup

	event := Event{Type: "test"}
	err = logger.Log(event)
	require.NoError(t, err)

	// Check file permissions (should be 0o600)
	info, err := os.Stat(logFile)
	require.NoError(t, err)
	// Check that only owner can read/write (skip on Windows — NTFS uses ACLs, not mode bits)
	if runtime.GOOS != "windows" {
		mode := info.Mode()
		assert.Equal(t, os.FileMode(0o600), mode&os.FileMode(0o777))
	}
}

func TestLog_Timestamp(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	logger, err := NewLogger(logFile)
	require.NoError(t, err)
	defer logger.Close() //nolint:errcheck // test cleanup

	before := time.Now().UTC()
	event := Event{Type: "test"}
	err = logger.Log(event)
	require.NoError(t, err)
	after := time.Now().UTC()

	data, err := os.ReadFile(logFile)
	require.NoError(t, err)

	var readEvent Event
	err = json.Unmarshal(data, &readEvent)
	require.NoError(t, err)

	assert.False(t, readEvent.Timestamp.IsZero())
	assert.True(t, readEvent.Timestamp.After(before.Add(-1*time.Second)))
	assert.True(t, readEvent.Timestamp.Before(after.Add(1*time.Second)))
}
