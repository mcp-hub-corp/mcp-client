package executor

// Executor defines the interface for executing MCP servers
type Executor interface {
	Execute(entrypoint string, args []string) error
	Stop() error
}

// STDIOExecutor executes MCP servers using STDIO transport
type STDIOExecutor struct{}

// NewSTDIOExecutor creates a new STDIO executor
// TODO: Implement in Phase 8
func NewSTDIOExecutor() *STDIOExecutor {
	return &STDIOExecutor{}
}

// Execute starts the MCP server process
// TODO: Implement in Phase 8
func (e *STDIOExecutor) Execute(entrypoint string, args []string) error {
	return nil
}

// Stop terminates the MCP server process
// TODO: Implement in Phase 8
func (e *STDIOExecutor) Stop() error {
	return nil
}

// HTTPExecutor executes MCP servers using HTTP transport
type HTTPExecutor struct{}

// NewHTTPExecutor creates a new HTTP executor
// TODO: Implement in Phase 8
func NewHTTPExecutor() *HTTPExecutor {
	return &HTTPExecutor{}
}

// Execute starts the MCP server process with HTTP transport
// TODO: Implement in Phase 8
func (e *HTTPExecutor) Execute(entrypoint string, args []string) error {
	return nil
}

// Stop terminates the MCP server process
// TODO: Implement in Phase 8
func (e *HTTPExecutor) Stop() error {
	return nil
}
