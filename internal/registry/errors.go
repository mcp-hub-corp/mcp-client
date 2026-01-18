package registry

import (
	"fmt"
	"net/http"
)

// Error represents a registry client error
type Error struct {
	Code    int
	Message string
	Err     error
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("[%d] %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *Error) Unwrap() error {
	return e.Err
}

// NotFoundError returns true if the error is a 404
func (e *Error) NotFoundError() bool {
	return e.Code == http.StatusNotFound
}

// UnauthorizedError returns true if the error is a 401
func (e *Error) UnauthorizedError() bool {
	return e.Code == http.StatusUnauthorized
}

// ForbiddenError returns true if the error is a 403
func (e *Error) ForbiddenError() bool {
	return e.Code == http.StatusForbidden
}

// RetryableError returns true if the error is retryable
func (e *Error) RetryableError() bool {
	return e.Code >= http.StatusInternalServerError
}

// NewError creates a new Error
func NewError(code int, message string, err error) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// IsError checks if an error is a registry.Error with a specific code
func IsError(err error, code int) bool {
	if regErr, ok := err.(*Error); ok {
		return regErr.Code == code
	}
	return false
}

// IsRetryableError checks if an error is retryable
func IsRetryableError(err error) bool {
	if regErr, ok := err.(*Error); ok {
		return regErr.RetryableError()
	}
	return false
}

// IsNotFoundError checks if an error is a 404
func IsNotFoundError(err error) bool {
	if regErr, ok := err.(*Error); ok {
		return regErr.NotFoundError()
	}
	return false
}

// IsUnauthorizedError checks if an error is a 401
func IsUnauthorizedError(err error) bool {
	if regErr, ok := err.(*Error); ok {
		return regErr.UnauthorizedError()
	}
	return false
}
