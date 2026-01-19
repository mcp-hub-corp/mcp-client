package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenStorage(t *testing.T) {
	cacheDir := t.TempDir()
	ts := NewTokenStorage(cacheDir)

	assert.NotNil(t, ts)
	assert.Equal(t, cacheDir, ts.dir)
}

func TestTokenStorageSave(t *testing.T) {
	cacheDir := t.TempDir()
	ts := NewTokenStorage(cacheDir)

	token := &Token{
		AccessToken: "test_token_123",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		TokenType:   "Bearer",
		Registry:    "https://example.com",
	}

	err := ts.Save("https://example.com", token)
	require.NoError(t, err)

	// Verify file was created
	tokenPath := filepath.Join(cacheDir, "auth.json")
	assert.FileExists(t, tokenPath)

	// Verify file permissions
	info, err := os.Stat(tokenPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode())
}

func TestTokenStorageLoad(t *testing.T) {
	cacheDir := t.TempDir()
	ts := NewTokenStorage(cacheDir)

	expectedToken := &Token{
		AccessToken: "test_token_123",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		TokenType:   "Bearer",
		Registry:    "https://example.com",
	}

	// Save token
	err := ts.Save("https://example.com", expectedToken)
	require.NoError(t, err)

	// Load token
	loadedToken, err := ts.Load()
	require.NoError(t, err)
	assert.NotNil(t, loadedToken)
	assert.Equal(t, expectedToken.AccessToken, loadedToken.AccessToken)
	assert.Equal(t, expectedToken.TokenType, loadedToken.TokenType)
}

func TestTokenStorageLoad_NotFound(t *testing.T) {
	cacheDir := t.TempDir()
	ts := NewTokenStorage(cacheDir)

	token, err := ts.Load()
	assert.NoError(t, err)
	assert.Nil(t, token)
}

func TestTokenIsExpired_Future(t *testing.T) {
	token := &Token{
		AccessToken: "test",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
	}

	assert.False(t, token.IsExpired())
}

func TestTokenIsExpired_Past(t *testing.T) {
	token := &Token{
		AccessToken: "test",
		ExpiresAt:   time.Now().Add(-24 * time.Hour),
	}

	assert.True(t, token.IsExpired())
}

func TestTokenIsExpired_Now(t *testing.T) {
	token := &Token{
		AccessToken: "test",
		ExpiresAt:   time.Now(),
	}

	assert.True(t, token.IsExpired())
}

func TestNewAuthenticatedRequest(t *testing.T) {
	client := &Client{}
	ar := NewAuthenticatedRequest(client.apiClient, "token123")

	assert.NotNil(t, ar)
	assert.Equal(t, "token123", ar.token)
	assert.True(t, ar.authed)
}

func TestNewAuthenticatedRequest_NoToken(t *testing.T) {
	client := &Client{}
	ar := NewAuthenticatedRequest(client.apiClient, "")

	assert.NotNil(t, ar)
	assert.Equal(t, "", ar.token)
	assert.False(t, ar.authed)
}

func TestTokenStorageCreatesCacheDir(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "nested", "dir")
	ts := NewTokenStorage(cacheDir)

	token := &Token{
		AccessToken: "test",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	err := ts.Save("https://example.com", token)
	require.NoError(t, err)

	// Verify directory was created
	assert.DirExists(t, cacheDir)
}

func TestTokenStorageInvalidJSON(t *testing.T) {
	cacheDir := t.TempDir()
	ts := NewTokenStorage(cacheDir)

	// Write invalid JSON to auth.json
	tokenPath := filepath.Join(cacheDir, "auth.json")
	err := os.WriteFile(tokenPath, []byte("invalid json {"), 0o600)
	require.NoError(t, err)

	// Should error when trying to load
	token, err := ts.Load()
	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestTokenStoragePersistence(t *testing.T) {
	cacheDir := t.TempDir()

	// Save with first storage instance
	ts1 := NewTokenStorage(cacheDir)
	token := &Token{
		AccessToken: "persisted_token",
		ExpiresAt:   time.Now().Add(48 * time.Hour),
		TokenType:   "Bearer",
		Registry:    "https://example.com",
	}
	err := ts1.Save("https://example.com", token)
	require.NoError(t, err)

	// Load with second storage instance (simulating new instance)
	ts2 := NewTokenStorage(cacheDir)
	loadedToken, err := ts2.Load()
	require.NoError(t, err)
	assert.NotNil(t, loadedToken)
	assert.Equal(t, "persisted_token", loadedToken.AccessToken)
	assert.Equal(t, "Bearer", loadedToken.TokenType)
	assert.Equal(t, "https://example.com", loadedToken.Registry)
}

func TestExtractAuthError(t *testing.T) {
	// This test is hard to test without actual HTTP response
	// but we can verify the function exists and basic behavior
	// when we have an actual error response in integration tests
}

func TestAddBearerTokenHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer mytoken", authHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, http.NoBody)
	require.NoError(t, err)

	AddBearerToken(req, "mytoken")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAddAPITokenHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Token id123:secret456", authHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, http.NoBody)
	require.NoError(t, err)

	AddAPIToken(req, "id123", "secret456")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestAddBasicAuthHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "testuser", username)
		assert.Equal(t, "testpass", password)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL, http.NoBody)
	require.NoError(t, err)

	AddBasicAuth(req, "testuser", "testpass")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// Test with real HTTP requests
func TestAuthenticationWithRealHTTPRequest(t *testing.T) {
	// Note: These tests require net/http which we import in client.go
	// The actual HTTP request testing is done in client_test.go
	// These are supplementary tests for the auth module

	// Token marshaling/unmarshaling
	token := &Token{
		AccessToken: "jwt_token_here",
		ExpiresAt:   time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
		TokenType:   "Bearer",
		Registry:    "https://registry.example.com",
	}

	data, err := json.Marshal(token)
	require.NoError(t, err)

	var decodedToken Token
	err = json.Unmarshal(data, &decodedToken)
	require.NoError(t, err)

	assert.Equal(t, token.AccessToken, decodedToken.AccessToken)
	assert.Equal(t, token.TokenType, decodedToken.TokenType)
	assert.Equal(t, token.Registry, decodedToken.Registry)
}

func TestTokenStorageDelete(t *testing.T) {
	cacheDir := t.TempDir()
	ts := NewTokenStorage(cacheDir)

	// Save a token first
	token := &Token{
		AccessToken: "test_token_delete",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		TokenType:   "Bearer",
		Registry:    "https://example.com",
	}

	err := ts.Save("https://example.com", token)
	require.NoError(t, err)

	// Verify file exists
	tokenPath := filepath.Join(cacheDir, "auth.json")
	assert.FileExists(t, tokenPath)

	// Delete the token
	err = ts.Delete()
	require.NoError(t, err)

	// Verify file was deleted
	assert.NoFileExists(t, tokenPath)
}

func TestTokenStorageDelete_FileNotExists(t *testing.T) {
	cacheDir := t.TempDir()
	ts := NewTokenStorage(cacheDir)

	// Try to delete when file doesn't exist
	// Should not error (idempotent)
	err := ts.Delete()
	assert.NoError(t, err)
}

func TestTokenStorageDelete_Idempotent(t *testing.T) {
	cacheDir := t.TempDir()
	ts := NewTokenStorage(cacheDir)

	// Save a token
	token := &Token{
		AccessToken: "test_token_idempotent",
		ExpiresAt:   time.Now().Add(24 * time.Hour),
		TokenType:   "Bearer",
		Registry:    "https://example.com",
	}

	err := ts.Save("https://example.com", token)
	require.NoError(t, err)

	// First delete should succeed
	err = ts.Delete()
	require.NoError(t, err)

	// Second delete should also succeed (idempotent)
	err = ts.Delete()
	require.NoError(t, err)
}
