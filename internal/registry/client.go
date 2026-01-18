package registry

// Client handles communication with the MCP registry
type Client struct {
	baseURL string
	token   string
}

// NewClient creates a new registry client
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
	}
}

// Resolve resolves a package reference to manifest and bundle digests
// TODO: Implement in Phase 2
func (c *Client) Resolve(ref string) error {
	return nil
}

// DownloadManifest downloads a manifest by digest
// TODO: Implement in Phase 2
func (c *Client) DownloadManifest(digest string) error {
	return nil
}

// DownloadBundle downloads a bundle by digest
// TODO: Implement in Phase 2
func (c *Client) DownloadBundle(digest string) error {
	return nil
}
