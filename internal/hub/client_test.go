package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitUpload(t *testing.T) {
	tests := []struct {
		name           string
		req            *InitUploadRequest
		serverResponse int
		serverBody     interface{}
		wantErr        bool
		errContains    string
	}{
		{
			name: "successful init",
			req: &InitUploadRequest{
				MCPName:      "test-mcp",
				MCPVersion:   "1.0.0",
				BundleDigest: "sha256:1234567890abcdef",
			},
			serverResponse: http.StatusCreated,
			serverBody: InitUploadResponse{
				UploadID:        "upload-123",
				BundleUploadURL: "https://s3.example.com/presigned",
				URLExpiresAt:    "2024-01-01T00:00:00Z",
			},
			wantErr: false,
		},
		{
			name:        "nil request",
			req:         nil,
			wantErr:     true,
			errContains: "cannot be nil",
		},
		{
			name: "missing mcp_name",
			req: &InitUploadRequest{
				MCPVersion:   "1.0.0",
				BundleDigest: "sha256:1234567890abcdef",
			},
			wantErr:     true,
			errContains: "required",
		},
		{
			name: "server error",
			req: &InitUploadRequest{
				MCPName:      "test-mcp",
				MCPVersion:   "1.0.0",
				BundleDigest: "sha256:1234567890abcdef",
			},
			serverResponse: http.StatusUnauthorized,
			serverBody: ErrorResponse{
				Error:   "unauthorized",
				Message: "authentication required",
				Code:    "AUTH_REQUIRED",
			},
			wantErr:     true,
			errContains: "authentication required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify method and path
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}
				if !strings.HasSuffix(r.URL.Path, "/api/v1/uploads/init") {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}

				// Write response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverResponse)
				json.NewEncoder(w).Encode(tt.serverBody)
			}))
			defer server.Close()

			// Create client
			client, cErr := NewClient(server.URL)
			if cErr != nil {
				t.Fatalf("failed to create client: %v", cErr)
			}

			// Call InitUpload
			resp, err := client.InitUpload(context.Background(), tt.req)

			// Check error
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error should contain %q, got: %v", tt.errContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify response
			if resp.UploadID == "" {
				t.Error("upload ID should not be empty")
			}
		})
	}
}

func TestFinalizeUpload(t *testing.T) {
	tests := []struct {
		name           string
		uploadID       string
		serverResponse int
		serverBody     interface{}
		wantErr        bool
		errContains    string
	}{
		{
			name:           "successful finalize",
			uploadID:       "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			serverResponse: http.StatusOK,
			serverBody: FinalizeUploadResponse{
				VersionID: "version-456",
				Status:    "ingested",
				Message:   "Version queued for analysis",
			},
			wantErr: false,
		},
		{
			name:        "empty upload ID",
			uploadID:    "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:           "not found",
			uploadID:       "b2c3d4e5-f6a7-8901-bcde-f12345678901",
			serverResponse: http.StatusNotFound,
			serverBody: ErrorResponse{
				Error:   "upload_not_found",
				Message: "Upload session not found",
				Code:    "UPLOAD_NOT_FOUND",
			},
			wantErr:     true,
			errContains: "Upload session not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify method
				if r.Method != http.MethodPost {
					t.Errorf("expected POST, got %s", r.Method)
				}

				// Write response
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.serverResponse)
				json.NewEncoder(w).Encode(tt.serverBody)
			}))
			defer server.Close()

			// Create client
			client, cErr := NewClient(server.URL)
			if cErr != nil {
				t.Fatalf("failed to create client: %v", cErr)
			}

			// Call FinalizeUpload
			resp, err := client.FinalizeUpload(context.Background(), tt.uploadID)

			// Check error
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error should contain %q, got: %v", tt.errContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify response
			if resp.VersionID == "" {
				t.Error("version ID should not be empty")
			}
		})
	}
}

func TestUploadFile(t *testing.T) {
	// Create a test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := []byte("hello world")
	if err := os.WriteFile(testFile, testContent, 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		filePath       string
		presignedURL   string
		serverResponse int
		wantErr        bool
		errContains    string
	}{
		{
			name:           "successful upload",
			filePath:       testFile,
			presignedURL:   "http://example.com/presigned",
			serverResponse: http.StatusOK,
			wantErr:        false,
		},
		{
			name:         "empty presigned URL",
			filePath:     testFile,
			presignedURL: "",
			wantErr:      true,
			errContains:  "cannot be empty",
		},
		{
			name:         "file not found",
			filePath:     "/nonexistent/file.txt",
			presignedURL: "http://example.com/presigned",
			wantErr:      true,
			errContains:  "failed to stat file",
		},
		{
			name:           "server error",
			filePath:       testFile,
			presignedURL:   "http://example.com/presigned",
			serverResponse: http.StatusForbidden,
			wantErr:        true,
			errContains:    "upload failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify method
				if r.Method != http.MethodPut {
					t.Errorf("expected PUT, got %s", r.Method)
				}

				// Read body
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}

				// Verify content
				if tt.serverResponse == http.StatusOK && !bytes.Equal(body, testContent) {
					t.Errorf("expected body %q, got %q", testContent, body)
				}

				w.WriteHeader(tt.serverResponse)
			}))
			defer server.Close()

			// Use server URL if presignedURL is not empty
			presignedURL := tt.presignedURL
			if presignedURL != "" && !tt.wantErr {
				presignedURL = server.URL
			}

			// Create client
			client, cErr := NewClient("http://localhost:8080")
			if cErr != nil {
				t.Fatalf("failed to create client: %v", cErr)
			}

			// Track progress
			var progressCalled bool
			onProgress := func(uploaded, total int64) {
				progressCalled = true
			}

			// Call UploadFile
			err := client.UploadFile(context.Background(), presignedURL, tt.filePath, onProgress)

			// Check error
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error should contain %q, got: %v", tt.errContains, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify progress was called
			if !progressCalled {
				t.Error("progress callback should have been called")
			}
		})
	}
}

func TestProgressReader(t *testing.T) {
	content := []byte("hello world")
	reader := strings.NewReader(string(content))

	var progressUpdates []struct {
		uploaded int64
		total    int64
	}

	pr := &progressReader{
		reader:        reader,
		totalBytes:    int64(len(content)),
		reportEveryKB: 1, // Report every byte for testing
		onProgress: func(uploaded, total int64) {
			progressUpdates = append(progressUpdates, struct {
				uploaded int64
				total    int64
			}{uploaded, total})
		},
	}

	// Read all content
	buf := make([]byte, 4) // Small buffer to trigger multiple reads
	for {
		_, err := pr.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verify progress updates
	if len(progressUpdates) == 0 {
		t.Fatal("expected progress updates, got none")
	}

	// Last update should have full size
	lastUpdate := progressUpdates[len(progressUpdates)-1]
	if lastUpdate.uploaded != int64(len(content)) {
		t.Errorf("expected final uploaded %d, got %d", len(content), lastUpdate.uploaded)
	}
	if lastUpdate.total != int64(len(content)) {
		t.Errorf("expected total %d, got %d", len(content), lastUpdate.total)
	}
}
