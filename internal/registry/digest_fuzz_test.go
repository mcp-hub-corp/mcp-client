package registry

import (
	"testing"
)

// Fuzz test for digest parsing - security critical input validation
func FuzzParseDigest(f *testing.F) {
	// Seed corpus with valid and edge case inputs
	f.Add("sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	f.Add("sha512:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	f.Add("sha256:")
	f.Add(":abc123")
	f.Add("sha256")
	f.Add("")
	f.Add("md5:abc123")
	f.Add("SHA256:ABCD1234")

	f.Fuzz(func(t *testing.T, input string) {
		// Should never panic, even with malicious input
		_, _, err := ParseDigest(input)

		// Either succeeds with valid format or returns error
		// But must not panic or hang
		_ = err
	})
}

// Fuzz test for digest validation
func FuzzValidateDigest(f *testing.F) {
	// Seed corpus
	f.Add([]byte("test data"), "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234")
	f.Add([]byte(""), "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	f.Add([]byte("hello"), "sha512:abc123")

	f.Fuzz(func(t *testing.T, data []byte, digest string) {
		// Should never panic
		err := ValidateDigest(data, digest)

		// Result is either valid or invalid, but no panic
		_ = err
	})
}
