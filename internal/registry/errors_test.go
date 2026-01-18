package registry

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewError(t *testing.T) {
	baseErr := fmt.Errorf("underlying error")
	err := NewError(http.StatusInternalServerError, "test error", baseErr)

	assert.NotNil(t, err)
	assert.Equal(t, http.StatusInternalServerError, err.Code)
	assert.Equal(t, "test error", err.Message)
	assert.Equal(t, baseErr, err.Err)
}

func TestErrorError_WithUnderlying(t *testing.T) {
	baseErr := fmt.Errorf("underlying error")
	err := NewError(http.StatusInternalServerError, "test error", baseErr)

	errorMsg := err.Error()
	assert.Contains(t, errorMsg, "[500]")
	assert.Contains(t, errorMsg, "test error")
	assert.Contains(t, errorMsg, "underlying error")
}

func TestErrorError_WithoutUnderlying(t *testing.T) {
	err := NewError(http.StatusNotFound, "not found", nil)

	errorMsg := err.Error()
	assert.Equal(t, "[404] not found", errorMsg)
}

func TestErrorUnwrap(t *testing.T) {
	baseErr := fmt.Errorf("underlying error")
	err := NewError(http.StatusInternalServerError, "test error", baseErr)

	unwrapped := err.Unwrap()
	assert.Equal(t, baseErr, unwrapped)
}

func TestErrorUnwrap_NoUnderlying(t *testing.T) {
	err := NewError(http.StatusNotFound, "not found", nil)

	unwrapped := err.Unwrap()
	assert.Nil(t, unwrapped)
}

func TestErrorNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected bool
	}{
		{"is 404", http.StatusNotFound, true},
		{"is 400", http.StatusBadRequest, false},
		{"is 500", http.StatusInternalServerError, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewError(tt.code, "test", nil)
			assert.Equal(t, tt.expected, err.NotFoundError())
		})
	}
}

func TestErrorUnauthorizedError(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected bool
	}{
		{"is 401", http.StatusUnauthorized, true},
		{"is 403", http.StatusForbidden, false},
		{"is 404", http.StatusNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewError(tt.code, "test", nil)
			assert.Equal(t, tt.expected, err.UnauthorizedError())
		})
	}
}

func TestErrorForbiddenError(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected bool
	}{
		{"is 403", http.StatusForbidden, true},
		{"is 401", http.StatusUnauthorized, false},
		{"is 400", http.StatusBadRequest, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewError(tt.code, "test", nil)
			assert.Equal(t, tt.expected, err.ForbiddenError())
		})
	}
}

func TestErrorRetryableError(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected bool
	}{
		{"500", http.StatusInternalServerError, true},
		{"502", http.StatusBadGateway, true},
		{"503", http.StatusServiceUnavailable, true},
		{"504", http.StatusGatewayTimeout, true},
		{"400", http.StatusBadRequest, false},
		{"401", http.StatusUnauthorized, false},
		{"403", http.StatusForbidden, false},
		{"404", http.StatusNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewError(tt.code, "test", nil)
			assert.Equal(t, tt.expected, err.RetryableError())
		})
	}
}

func TestIsError(t *testing.T) {
	err := NewError(http.StatusNotFound, "not found", nil)

	assert.True(t, IsError(err, http.StatusNotFound))
	assert.False(t, IsError(err, http.StatusInternalServerError))
}

func TestIsError_NonRegistryError(t *testing.T) {
	err := fmt.Errorf("generic error")

	assert.False(t, IsError(err, http.StatusNotFound))
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected bool
	}{
		{"500 is retryable", http.StatusInternalServerError, true},
		{"502 is retryable", http.StatusBadGateway, true},
		{"404 not retryable", http.StatusNotFound, false},
		{"401 not retryable", http.StatusUnauthorized, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewError(tt.code, "test", nil)
			assert.Equal(t, tt.expected, IsRetryableError(err))
		})
	}
}

func TestIsRetryableError_NonRegistryError(t *testing.T) {
	err := fmt.Errorf("generic error")
	assert.False(t, IsRetryableError(err))
}

func TestIsNotFoundError(t *testing.T) {
	err := NewError(http.StatusNotFound, "not found", nil)
	assert.True(t, IsNotFoundError(err))

	err2 := NewError(http.StatusInternalServerError, "error", nil)
	assert.False(t, IsNotFoundError(err2))
}

func TestIsNotFoundError_NonRegistryError(t *testing.T) {
	err := fmt.Errorf("generic error")
	assert.False(t, IsNotFoundError(err))
}

func TestIsUnauthorizedError(t *testing.T) {
	err := NewError(http.StatusUnauthorized, "unauthorized", nil)
	assert.True(t, IsUnauthorizedError(err))

	err2 := NewError(http.StatusForbidden, "forbidden", nil)
	assert.False(t, IsUnauthorizedError(err2))
}

func TestIsUnauthorizedError_NonRegistryError(t *testing.T) {
	err := fmt.Errorf("generic error")
	assert.False(t, IsUnauthorizedError(err))
}

func TestErrorStatusCodes(t *testing.T) {
	// Test all important HTTP status codes
	statusCodes := []int{
		http.StatusBadRequest,          // 400
		http.StatusUnauthorized,        // 401
		http.StatusForbidden,           // 403
		http.StatusNotFound,            // 404
		http.StatusConflict,            // 409
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout,      // 504
	}

	for _, code := range statusCodes {
		t.Run(fmt.Sprintf("status %d", code), func(t *testing.T) {
			err := NewError(code, "test error", nil)
			assert.Equal(t, code, err.Code)
		})
	}
}

func TestErrorMessageVariations(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		message string
		hasErr  bool
	}{
		{"normal error", http.StatusNotFound, "package not found", false},
		{"error with underlying", http.StatusInternalServerError, "failed to process", true},
		{"empty message", http.StatusBadRequest, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var baseErr error
			if tt.hasErr {
				baseErr = fmt.Errorf("underlying cause")
			}

			err := NewError(tt.code, tt.message, baseErr)
			assert.Equal(t, tt.code, err.Code)
			assert.Equal(t, tt.message, err.Message)
		})
	}
}

func TestErrorChainingBehavior(t *testing.T) {
	// Create a chain of errors
	originalErr := fmt.Errorf("original error")
	registryErr := NewError(http.StatusInternalServerError, "registry operation failed", originalErr)

	// Verify unwrap chain
	assert.Equal(t, originalErr, registryErr.Unwrap())
	assert.Equal(t, "original error", registryErr.Unwrap().Error())
}

func TestErrorInterface(t *testing.T) {
	// Verify Error implements the error interface
	var err error = NewError(http.StatusNotFound, "not found", nil)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestErrorComparison(t *testing.T) {
	// Test error equality
	err1 := NewError(http.StatusNotFound, "not found", nil)
	err2 := NewError(http.StatusNotFound, "not found", nil)

	// Note: Error structs won't be equal by reference, but their fields should match
	assert.Equal(t, err1.Code, err2.Code)
	assert.Equal(t, err1.Message, err2.Message)
}

func TestRetryableErrorBoundary(t *testing.T) {
	// Test boundary at 500
	err499 := NewError(499, "not retryable", nil)
	err500 := NewError(500, "retryable", nil)
	err501 := NewError(501, "retryable", nil)

	assert.False(t, err499.RetryableError())
	assert.True(t, err500.RetryableError())
	assert.True(t, err501.RetryableError())
}
