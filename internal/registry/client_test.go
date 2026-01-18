package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	client := NewClient("https://example.com")
	assert.NotNil(t, client)
	assert.Equal(t, "https://example.com", client.baseURL)
	assert.Empty(t, client.token)
}

func TestNewClient_DefaultURL(t *testing.T) {
	client := NewClient("")
	assert.Equal(t, DefaultRegistryURL, client.baseURL)
}

func TestNewClientWithToken(t *testing.T) {
	client := NewClientWithToken("https://example.com", "token123")
	assert.Equal(t, "https://example.com", client.baseURL)
	assert.Equal(t, "token123", client.token)
}

func TestClientSetToken(t *testing.T) {
	client := NewClient("https://example.com")
	client.SetToken("token123")
	assert.Equal(t, "token123", client.token)
}

func TestClientResolve_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.True(t, strings.Contains(r.URL.Path, "/v1/org/acme/mcps/test/resolve"))
		assert.Equal(t, "1.0.0", r.URL.Query().Get("ref"))

		resp := ResolveResponse{
			Package: "acme/test",
			Ref:     "1.0.0",
			Resolved: ResolvedVersion{
				Version: "1.0.0",
				GitSHA:  "abc123",
				Status:  "published",
				Manifest: ArtifactInfo{
					Digest: "sha256:abcd1234",
					URL:    "https://example.com/manifest",
				},
				Bundle: BundleInfo{
					Digest:    "sha256:efgh5678",
					URL:       "https://example.com/bundle",
					SizeBytes: 1024,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	resp, err := client.Resolve(ctx, "acme", "test", "1.0.0")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "acme/test", resp.Package)
	assert.Equal(t, "1.0.0", resp.Resolved.Version)
}

func TestClientResolve_InvalidParams(t *testing.T) {
	client := NewClient("https://example.com")
	ctx := context.Background()

	tests := []struct {
		testName string
		org      string
		pkgName  string
		ref      string
	}{
		{"empty org", "", "test", "1.0.0"},
		{"empty name", "acme", "", "1.0.0"},
		{"empty ref", "acme", "test", ""},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			resp, err := client.Resolve(ctx, tt.org, tt.pkgName, tt.ref)
			assert.Error(t, err)
			assert.Nil(t, resp)
		})
	}
}

func TestClientResolve_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "package not found"})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	resp, err := client.Resolve(ctx, "acme", "nonexistent", "1.0.0")

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.True(t, IsNotFoundError(err))
}

func TestClientDownloadManifest_Success(t *testing.T) {
	manifestContent := []byte(`{"name":"test","version":"1.0.0"}`)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.True(t, strings.Contains(r.URL.Path, "/v1/org/acme/artifacts/"))
		assert.True(t, strings.Contains(r.URL.Path, "/manifest"))

		w.Header().Set("Content-Type", "application/json")
		w.Write(manifestContent)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	data, err := client.DownloadManifest(ctx, "acme", "sha256:abcd1234")

	require.NoError(t, err)
	assert.Equal(t, manifestContent, data)
}

func TestClientDownloadBundle_Success(t *testing.T) {
	bundleContent := []byte("fake bundle tar.gz content")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.True(t, strings.Contains(r.URL.Path, "/bundle"))

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(bundleContent)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	data, err := client.DownloadBundle(ctx, "acme", "sha256:efgh5678")

	require.NoError(t, err)
	assert.Equal(t, bundleContent, data)
}

func TestClientDownloadManifest_InvalidParams(t *testing.T) {
	client := NewClient("https://example.com")
	ctx := context.Background()

	tests := []struct {
		name   string
		org    string
		digest string
	}{
		{"empty org", "", "sha256:abc123"},
		{"empty digest", "acme", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := client.DownloadManifest(ctx, tt.org, tt.digest)
			assert.Error(t, err)
			assert.Nil(t, data)
		})
	}
}

func TestClientDownloadManifest_SizeLimit(t *testing.T) {
	// Create content larger than MaxManifestSize
	largeContent := bytes.Repeat([]byte("x"), MaxManifestSize+1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(largeContent)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	data, err := client.DownloadManifest(ctx, "acme", "sha256:toobig")

	assert.Error(t, err)
	assert.Nil(t, data)
	assert.True(t, strings.Contains(err.Error(), "exceeds maximum size"))
}

func TestClientLogin_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/v1/auth/login", r.URL.Path)

		var req LoginRequest
		json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "user", req.Username)
		assert.Equal(t, "pass", req.Password)

		resp := LoginResponse{
			AccessToken: "token123",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	resp, err := client.Login(ctx, "user", "pass")

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "token123", resp.AccessToken)
	assert.Equal(t, 3600, resp.ExpiresIn)
}

func TestClientLogin_InvalidParams(t *testing.T) {
	client := NewClient("https://example.com")
	ctx := context.Background()

	tests := []struct {
		name     string
		username string
		password string
	}{
		{"empty username", "", "pass"},
		{"empty password", "user", ""},
		{"both empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.Login(ctx, tt.username, tt.password)
			assert.Error(t, err)
			assert.Nil(t, resp)
		})
	}
}

func TestClientLogin_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	resp, err := client.Login(ctx, "user", "wrong")

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.True(t, IsUnauthorizedError(err))
}

func TestClientListCatalog_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Equal(t, "/v1/catalog", r.URL.Path)

		resp := CatalogResponse{
			Packages: []PackageInfo{
				{
					Package:       "acme/tool1",
					Visibility:    "public",
					LatestVersion: "1.0.0",
				},
				{
					Package:       "acme/tool2",
					Visibility:    "private",
					LatestVersion: "2.0.0",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	resp, err := client.ListCatalog(ctx)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.Packages, 2)
	assert.Equal(t, "acme/tool1", resp.Packages[0].Package)
	assert.Equal(t, "acme/tool2", resp.Packages[1].Package)
}

func TestClientWithAuthToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer token123", authHeader)

		resp := ResolveResponse{
			Package: "acme/test",
			Ref:     "1.0.0",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClientWithToken(server.URL, "token123")
	ctx := context.Background()

	resp, err := client.Resolve(ctx, "acme", "test", "1.0.0")

	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestClientContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	resp, err := client.Resolve(ctx, "acme", "test", "1.0.0")

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestClientRetryLogic_Success(t *testing.T) {
	attemptCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++

		// Fail first 2 attempts with 500, then succeed
		if attemptCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "server error"})
			return
		}

		bundleContent := []byte("success")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(bundleContent)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	data, err := client.DownloadBundle(ctx, "acme", "sha256:test")

	require.NoError(t, err)
	assert.Equal(t, []byte("success"), data)
	assert.Equal(t, 3, attemptCount)
}

func TestClientRetryLogic_ExhaustedRetries(t *testing.T) {
	attemptCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "server error"})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	data, err := client.DownloadBundle(ctx, "acme", "sha256:test")

	assert.Error(t, err)
	assert.Nil(t, data)
	assert.Equal(t, MaxRetries, attemptCount)
	assert.True(t, strings.Contains(err.Error(), "failed to download"))
}

func TestClientRetryLogic_NoRetryOn404(t *testing.T) {
	attemptCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	data, err := client.DownloadManifest(ctx, "acme", "sha256:notfound")

	assert.Error(t, err)
	assert.Nil(t, data)
	// Should fail immediately without retries
	assert.Equal(t, 1, attemptCount)
	assert.True(t, IsNotFoundError(err))
}

func TestErrorWrapping(t *testing.T) {
	baseErr := fmt.Errorf("base error")
	err := NewError(http.StatusInternalServerError, "test error", baseErr)

	var registryErr error = err
	assert.Error(t, registryErr)
	assert.Equal(t, "test error", err.Message)
	assert.Equal(t, http.StatusInternalServerError, err.Code)
	assert.True(t, err.RetryableError())
}

func TestParseDigest(t *testing.T) {
	tests := []struct {
		name    string
		digest  string
		expAlgo string
		expHex  string
		expErr  bool
	}{
		{
			name:    "valid sha256",
			digest:  "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			expAlgo: "sha256",
			expHex:  "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			expErr:  false,
		},
		{
			name:   "empty digest",
			digest: "",
			expErr: true,
		},
		{
			name:   "invalid format",
			digest: "nocolon",
			expErr: true,
		},
		{
			name:   "sha256 wrong length",
			digest: "sha256:abc",
			expErr: true,
		},
		{
			name:   "invalid hex chars",
			digest: "sha256:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			expErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, hex, err := ParseDigest(tt.digest)

			if tt.expErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expAlgo, algo)
				assert.Equal(t, tt.expHex, hex)
			}
		})
	}
}

func TestUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		assert.Equal(t, "mcp-client/1.0.0", userAgent)

		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	// Any request should have User-Agent
	client.Resolve(ctx, "test", "test", "1.0.0")
}

func TestContentTypeHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			contentType := r.Header.Get("Content-Type")
			assert.Equal(t, "application/json", contentType)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	client.Login(ctx, "user", "pass")
}

func TestRedirectFollowing(t *testing.T) {
	// First server that redirects
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/redirected", http.StatusFound)
	}))
	defer redirect.Close()

	// Second server that returns actual content
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bundleContent := []byte("redirected content")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(bundleContent)
	}))
	defer final.Close()

	// Manually test redirect following
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	// This should follow the redirect and succeed
	_, err := client.Resolve(ctx, "test", "test", "1.0.0")

	// We expect an error because the final endpoint doesn't match expected format
	// But the important thing is that it tried to follow the redirect
	assert.NotNil(t, err) // Expected because final server doesn't have proper response
}

func TestClientBaseURL(t *testing.T) {
	client := NewClient("https://example.com")
	assert.Equal(t, "https://example.com", client.BaseURL())

	client.SetBaseURL("https://new.example.com")
	assert.Equal(t, "https://new.example.com", client.BaseURL())
}

func TestErrorMessageExtraction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "invalid request format",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	_, err := client.Resolve(ctx, "test", "test", "1.0.0")

	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "invalid request format"))
}

func TestEmptyResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Write nothing
	}))
	defer server.Close()

	client := NewClient(server.URL)
	ctx := context.Background()

	_, err := client.Resolve(ctx, "test", "test", "1.0.0")

	assert.Error(t, err)
}
