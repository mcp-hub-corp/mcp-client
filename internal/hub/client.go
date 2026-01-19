package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Client is a client for the MCP Hub API
type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
}

// NewClient creates a new hub client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// SetToken sets the authentication token
func (c *Client) SetToken(token string) {
	c.token = token
}

// InitUploadRequest represents the upload init request
type InitUploadRequest struct {
	MCPName      string `json:"mcp_name"`
	MCPVersion   string `json:"mcp_version"`
	BundleDigest string `json:"bundle_digest"`
}

// InitUploadResponse represents the upload init response
type InitUploadResponse struct {
	UploadID        string `json:"upload_id"`
	BundleUploadURL string `json:"bundle_upload_url"`
	URLExpiresAt    string `json:"url_expires_at"`
}

// FinalizeUploadResponse represents the finalize response
type FinalizeUploadResponse struct {
	VersionID string `json:"version_id"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

// ErrorResponse represents an error response from the hub
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// InitUpload initializes an upload session
func (c *Client) InitUpload(ctx context.Context, req *InitUploadRequest) (*InitUploadResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}

	// Validate required fields
	if req.MCPName == "" || req.MCPVersion == "" || req.BundleDigest == "" {
		return nil, fmt.Errorf("mcp_name, mcp_version, and bundle_digest are required")
	}

	// Marshal request
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create request
	url := fmt.Sprintf("%s/api/v1/uploads/init", c.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	}

	// Send request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusCreated {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("hub error: %s (%s)", errResp.Message, errResp.Code)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var initResp InitUploadResponse
	if err := json.Unmarshal(respBody, &initResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &initResp, nil
}

// FinalizeUpload finalizes an upload session
func (c *Client) FinalizeUpload(ctx context.Context, uploadID string) (*FinalizeUploadResponse, error) {
	if uploadID == "" {
		return nil, fmt.Errorf("uploadID cannot be empty")
	}

	// Create request
	url := fmt.Sprintf("%s/api/v1/uploads/%s/finalize", c.baseURL, uploadID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	}

	// Send request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err == nil {
			return nil, fmt.Errorf("hub error: %s (%s)", errResp.Message, errResp.Code)
		}
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var finalizeResp FinalizeUploadResponse
	if err := json.Unmarshal(respBody, &finalizeResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &finalizeResp, nil
}

// UploadFile uploads a file to a presigned URL
func (c *Client) UploadFile(ctx context.Context, presignedURL string, filePath string, onProgress func(bytesUploaded, totalBytes int64)) error {
	if presignedURL == "" {
		return fmt.Errorf("presignedURL cannot be empty")
	}
	if filePath == "" {
		return fmt.Errorf("filePath cannot be empty")
	}

	// Get file size first
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	totalBytes := fileInfo.Size()

	// Open file
	file, err := openFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Create progress reader if callback provided
	var reader io.Reader = file
	if onProgress != nil {
		reader = &progressReader{
			reader:     file,
			totalBytes: totalBytes,
			onProgress: onProgress,
		}
	}

	// Create PUT request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, presignedURL, reader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/gzip")
	httpReq.ContentLength = totalBytes

	// Send request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// progressReader wraps an io.Reader and calls a progress callback
type progressReader struct {
	reader        io.Reader
	totalBytes    int64
	bytesRead     int64
	onProgress    func(bytesUploaded, totalBytes int64)
	lastReported  int64
	reportEveryKB int64
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.bytesRead += int64(n)

	// Report progress every 100KB to avoid too many updates
	if pr.reportEveryKB == 0 {
		pr.reportEveryKB = 100 * 1024 // 100KB
	}

	if pr.onProgress != nil && (pr.bytesRead-pr.lastReported >= pr.reportEveryKB || err == io.EOF) {
		pr.onProgress(pr.bytesRead, pr.totalBytes)
		pr.lastReported = pr.bytesRead
	}

	return n, err
}

// openFile is a helper to open a file (can be mocked in tests)
var openFile = func(path string) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return file, nil
}
