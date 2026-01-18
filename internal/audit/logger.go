package audit

import "time"

// Event represents an audit log event
type Event struct {
	Timestamp  time.Time         `json:"timestamp"`
	Type       string            `json:"type"` // start, end, error
	Package    string            `json:"package"`
	Version    string            `json:"version"`
	Digest     string            `json:"digest"`
	Entrypoint string            `json:"entrypoint"`
	ExitCode   int               `json:"exit_code,omitempty"`
	Duration   time.Duration     `json:"duration,omitempty"`
	Error      string            `json:"error,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// Logger handles audit logging
type Logger struct {
	logFile string
}

// NewLogger creates a new audit logger
func NewLogger(logFile string) *Logger {
	return &Logger{
		logFile: logFile,
	}
}

// Log writes an audit event
// TODO: Implement in Phase 10
func (l *Logger) Log(event Event) error {
	return nil
}

// LogStart logs the start of an MCP execution
// TODO: Implement in Phase 10
func (l *Logger) LogStart(pkg, version, digest, entrypoint string) error {
	return nil
}

// LogEnd logs the end of an MCP execution
// TODO: Implement in Phase 10
func (l *Logger) LogEnd(pkg, version string, exitCode int, duration time.Duration) error {
	return nil
}

// LogError logs an execution error
// TODO: Implement in Phase 10
func (l *Logger) LogError(pkg, version, errMsg string) error {
	return nil
}
