package registry

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// ValidateDigest validates that the provided data matches the expected digest
func ValidateDigest(data []byte, expectedDigest string) error {
	if expectedDigest == "" {
		return fmt.Errorf("digest validation: expected digest cannot be empty")
	}

	algorithm, expectedHex, err := ParseDigest(expectedDigest)
	if err != nil {
		return fmt.Errorf("digest validation: failed to parse expected digest: %w", err)
	}

	if algorithm != "sha256" {
		return fmt.Errorf("digest validation: unsupported algorithm %q (only sha256 supported)", algorithm)
	}

	actualDigest := ComputeSHA256(data)
	if actualDigest != expectedHex {
		return fmt.Errorf("digest validation failed: expected sha256:%s, got sha256:%s", expectedHex, actualDigest)
	}

	return nil
}

// ParseDigest parses a digest string and returns algorithm and hex value
// Expected format: "algorithm:hexvalue" (e.g., "sha256:abc123...")
func ParseDigest(digest string) (algorithm, hex string, err error) {
	if digest == "" {
		return "", "", fmt.Errorf("digest cannot be empty")
	}

	parts := strings.Split(digest, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid digest format, expected 'algorithm:hexvalue', got %q", digest)
	}

	algorithm = parts[0]
	hex = parts[1]

	if algorithm == "" || hex == "" {
		return "", "", fmt.Errorf("invalid digest format, algorithm and hex cannot be empty")
	}

	// Validate hex characters
	for _, char := range hex {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return "", "", fmt.Errorf("invalid digest format, hex contains non-hexadecimal character %q", char)
		}
	}

	// Validate length based on algorithm
	switch algorithm {
	case "sha256":
		if len(hex) != 64 {
			return "", "", fmt.Errorf("invalid sha256 digest length: expected 64 hex chars, got %d", len(hex))
		}
	case "sha512":
		if len(hex) != 128 {
			return "", "", fmt.Errorf("invalid sha512 digest length: expected 128 hex chars, got %d", len(hex))
		}
	default:
		return "", "", fmt.Errorf("unsupported digest algorithm %q", algorithm)
	}

	return algorithm, hex, nil
}

// ComputeSHA256 computes the SHA256 hash of data and returns the hex string
func ComputeSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}
