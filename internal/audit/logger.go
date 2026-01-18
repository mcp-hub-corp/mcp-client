package audit

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event represents an audit log event
type Event struct {
	Timestamp  time.Time         `json:"timestamp"`
	Type       string            `json:"type"` // "start", "end", "error"
	Package    string            `json:"package"`
	Version    string            `json:"version"`
	GitSHA     string            `json:"git_sha,omitempty"`
	Digest     string            `json:"digest,omitempty"`
	Entrypoint string            `json:"entrypoint,omitempty"`
	ExitCode   int               `json:"exit_code,omitempty"`
	Duration   string            `json:"duration,omitempty"` // ISO 8601 duration format
	Error      string            `json:"error,omitempty"`
	Outcome    string            `json:"outcome,omitempty"` // "success", "timeout", "killed", "error"
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Logger handles audit logging to a file in JSON format
type Logger struct {
	logFile string
	file    *os.File
	lock    sync.Mutex
	logger  *slog.Logger
}

// NewLogger creates a new audit logger
func NewLogger(logFile string) (*Logger, error) {
	if logFile == "" {
		return nil, fmt.Errorf("log file path cannot be empty")
	}

	// Ensure log directory exists
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file in append mode
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	return &Logger{
		logFile: logFile,
		file:    file,
		logger:  slog.Default(),
	}, nil
}

// Log writes an audit event to the log file
func (l *Logger) Log(event Event) error {
	if l.file == nil {
		return fmt.Errorf("logger file not initialized")
	}

	l.lock.Lock()
	defer l.lock.Unlock()

	// Set timestamp if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Marshal to JSON
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	// Write to file with newline
	if _, err := l.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write audit event: %w", err)
	}

	// Sync to ensure data is written to disk
	if err := l.file.Sync(); err != nil {
		l.logger.Warn("failed to sync audit log file", slog.String("error", err.Error()))
	}

	return nil
}

// LogStart logs the start of an MCP execution
func (l *Logger) LogStart(pkg, version, digest, entrypoint, gitSHA string) error {
	event := Event{
		Timestamp:  time.Now().UTC(),
		Type:       "start",
		Package:    pkg,
		Version:    version,
		GitSHA:     gitSHA,
		Digest:     digest,
		Entrypoint: entrypoint,
	}
	return l.Log(event)
}

// LogEnd logs the end of an MCP execution
func (l *Logger) LogEnd(pkg, version string, exitCode int, duration time.Duration, outcome string) error {
	// Convert duration to ISO 8601 format
	durationStr := fmt.Sprintf("PT%d.%09dS", int64(duration.Seconds()), duration.Nanoseconds()%1e9)

	event := Event{
		Timestamp: time.Now().UTC(),
		Type:      "end",
		Package:   pkg,
		Version:   version,
		ExitCode:  exitCode,
		Duration:  durationStr,
		Outcome:   outcome,
	}
	return l.Log(event)
}

// LogError logs an execution error
func (l *Logger) LogError(pkg, version, errMsg string) error {
	event := Event{
		Timestamp: time.Now().UTC(),
		Type:      "error",
		Package:   pkg,
		Version:   version,
		Error:     errMsg,
		Outcome:   "error",
	}
	return l.Log(event)
}

// Close closes the audit logger file
func (l *Logger) Close() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.file != nil {
		err := l.file.Close()
		l.file = nil // Mark as closed
		return err
	}
	return nil
}
