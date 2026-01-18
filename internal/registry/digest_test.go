package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDigest_Success(t *testing.T) {
	data := []byte("test content")
	expectedDigest := "sha256:" + ComputeSHA256(data)

	err := ValidateDigest(data, expectedDigest)
	assert.NoError(t, err)
}

func TestValidateDigest_Mismatch(t *testing.T) {
	data := []byte("test content")
	wrongDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	err := ValidateDigest(data, wrongDigest)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

func TestValidateDigest_EmptyExpected(t *testing.T) {
	data := []byte("test content")

	err := ValidateDigest(data, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestValidateDigest_UnsupportedAlgorithm(t *testing.T) {
	data := []byte("test content")
	digest := "md5:abc123"

	err := ValidateDigest(data, digest)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

func TestParseDigest_ValidSHA256(t *testing.T) {
	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	algo, hex, err := ParseDigest(digest)

	require.NoError(t, err)
	assert.Equal(t, "sha256", algo)
	assert.Equal(t, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234", hex)
}

func TestParseDigest_ValidSHA512(t *testing.T) {
	digest := "sha512:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	algo, hex, err := ParseDigest(digest)

	require.NoError(t, err)
	assert.Equal(t, "sha512", algo)
	assert.Len(t, hex, 128)
}

func TestParseDigest_Empty(t *testing.T) {
	_, _, err := ParseDigest("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestParseDigest_InvalidFormat(t *testing.T) {
	tests := []string{
		"nocolon",
		"sha256",
		":",
		"sha256::",
		":abc123",
	}

	for _, digest := range tests {
		t.Run(digest, func(t *testing.T) {
			_, _, err := ParseDigest(digest)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid digest format")
		})
	}
}

func TestParseDigest_InvalidHexCharacters(t *testing.T) {
	// g, h, z are not valid hex characters
	digest := "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"

	_, _, err := ParseDigest(digest)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "non-hexadecimal character")
}

func TestParseDigest_SHA256_WrongLength(t *testing.T) {
	tests := []struct {
		name   string
		digest string
	}{
		{"too short", "sha256:abc"},
		// Create a valid-looking hex string that's too long
		{"too long", "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseDigest(tt.digest)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid sha256 digest length")
		})
	}
}

func TestParseDigest_SHA512_WrongLength(t *testing.T) {
	digest := "sha512:abc"

	_, _, err := ParseDigest(digest)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid sha512 digest length")
}

func TestParseDigest_UnsupportedAlgorithm(t *testing.T) {
	digest := "md5:abcd1234abcd1234abcd1234abcd1234"

	_, _, err := ParseDigest(digest)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported digest algorithm")
}

func TestComputeSHA256_Basic(t *testing.T) {
	data := []byte("test data")
	hash := ComputeSHA256(data)

	// SHA256 produces 64 hex characters
	assert.Len(t, hash, 64)

	// Verify all characters are valid hex
	for _, char := range hash {
		assert.True(t, (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f'))
	}
}

func TestComputeSHA256_Empty(t *testing.T) {
	data := []byte("")
	hash := ComputeSHA256(data)

	// SHA256 of empty string
	expected := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	assert.Equal(t, expected, hash)
}

func TestComputeSHA256_Consistency(t *testing.T) {
	data := []byte("consistency test")
	hash1 := ComputeSHA256(data)
	hash2 := ComputeSHA256(data)

	assert.Equal(t, hash1, hash2)
}

func TestComputeSHA256_DifferentInputs(t *testing.T) {
	hash1 := ComputeSHA256([]byte("data1"))
	hash2 := ComputeSHA256([]byte("data2"))

	assert.NotEqual(t, hash1, hash2)
}

func TestComputeSHA256_LargeData(t *testing.T) {
	// Create 10MB of data
	data := make([]byte, 10*1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	hash := ComputeSHA256(data)

	// Should still be a valid 64-char hex string
	assert.Len(t, hash, 64)
	for _, char := range hash {
		assert.True(t, (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f'))
	}
}

func TestValidateDigest_WithRealSHA256(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"simple string", []byte("hello world")},
		{"json data", []byte(`{"name":"test","version":"1.0.0"}`)},
		{"binary data", []byte{0x00, 0x01, 0x02, 0x03, 0xff}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash := ComputeSHA256(tc.data)
			digest := "sha256:" + hash

			// Should validate successfully
			err := ValidateDigest(tc.data, digest)
			assert.NoError(t, err)

			// Should fail with wrong data
			wrongData := append([]byte("wrong"), tc.data...)
			err = ValidateDigest(wrongData, digest)
			assert.Error(t, err)
		})
	}
}

func TestParseDigest_ValidFormats(t *testing.T) {
	testCases := []struct {
		name           string
		digest         string
		expectedAlgo   string
		expectedLength int
	}{
		{
			"valid sha256",
			"sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			"sha256",
			64,
		},
		{
			"valid sha512",
			"sha512:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
			"sha512",
			128,
		},
		{
			"lowercase hex",
			"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"sha256",
			64,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			algo, hex, err := ParseDigest(tc.digest)

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedAlgo, algo)
			assert.Len(t, hex, tc.expectedLength)
		})
	}
}
