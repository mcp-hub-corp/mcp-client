package registry

import (
	"crypto/rand"
	"testing"
)

// Benchmark digest validation - critical security path
func BenchmarkValidateDigest_SmallData(b *testing.B) {
	data := []byte("test data for validation")
	digest := "sha256:" + ComputeSHA256(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateDigest(data, digest)
	}
}

func BenchmarkValidateDigest_1MB(b *testing.B) {
	data := make([]byte, 1*1024*1024) // 1 MB
	_, _ = rand.Read(data)
	digest := "sha256:" + ComputeSHA256(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateDigest(data, digest)
	}
}

func BenchmarkValidateDigest_10MB(b *testing.B) {
	data := make([]byte, 10*1024*1024) // 10 MB (max manifest size)
	_, _ = rand.Read(data)
	digest := "sha256:" + ComputeSHA256(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateDigest(data, digest)
	}
}

func BenchmarkComputeSHA256_SmallData(b *testing.B) {
	data := []byte("test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeSHA256(data)
	}
}

func BenchmarkComputeSHA256_1MB(b *testing.B) {
	data := make([]byte, 1*1024*1024)
	_, _ = rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeSHA256(data)
	}
}

func BenchmarkComputeSHA256_100MB(b *testing.B) {
	data := make([]byte, 100*1024*1024) // 100 MB (max bundle size)
	_, _ = rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ComputeSHA256(data)
	}
}

func BenchmarkParseDigest(b *testing.B) {
	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseDigest(digest)
	}
}

func BenchmarkParseDigest_SHA512(b *testing.B) {
	digest := "sha512:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = ParseDigest(digest)
	}
}
