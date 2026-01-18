package cache

import (
	"crypto/rand"
	"fmt"
	"path/filepath"
	"testing"
)

func BenchmarkPutManifest_Small(b *testing.B) {
	store, _ := NewStore(b.TempDir())
	data := []byte(`{"schema_version":"1.0","package":{"id":"test/pkg"}}`)
	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.PutManifest(digest, data)
	}
}

func BenchmarkGetManifest_Cached(b *testing.B) {
	store, _ := NewStore(b.TempDir())
	data := []byte(`{"schema_version":"1.0"}`)
	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	// Pre-populate cache
	_ = store.PutManifest(digest, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.GetManifest(digest)
	}
}

func BenchmarkPutBundle_1MB(b *testing.B) {
	store, _ := NewStore(b.TempDir())
	data := make([]byte, 1*1024*1024)
	_, _ = rand.Read(data)
	digest := "sha256:def4567def4567def4567def4567def4567def4567def4567def4567def4567d"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.PutBundle(digest, data)
	}
}

func BenchmarkGetBundle_1MB(b *testing.B) {
	store, _ := NewStore(b.TempDir())
	data := make([]byte, 1*1024*1024)
	_, _ = rand.Read(data)
	digest := "sha256:def4567def4567def4567def4567def4567def4567def4567def4567def4567d"

	// Pre-populate
	_ = store.PutBundle(digest, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.GetBundle(digest)
	}
}

func BenchmarkExists(b *testing.B) {
	store, _ := NewStore(b.TempDir())
	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	// Pre-populate
	_ = store.PutManifest(digest, []byte("test"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.Exists(digest, "manifest")
	}
}

func BenchmarkList(b *testing.B) {
	store, _ := NewStore(b.TempDir())

	// Pre-populate with 100 artifacts
	for i := 0; i < 100; i++ {
		// Create unique digests
		digestSuffix := fmt.Sprintf("%d", i)
		if len(digestSuffix) == 1 {
			digestSuffix = "0" + digestSuffix
		}
		digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd12" + digestSuffix
		if i%2 == 0 {
			_ = store.PutManifest(digest, []byte("manifest"))
		} else {
			_ = store.PutBundle(digest, []byte("bundle"))
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.List()
	}
}

func BenchmarkCopyToPath(b *testing.B) {
	store, _ := NewStore(b.TempDir())
	data := make([]byte, 100*1024) // 100 KB
	_, _ = rand.Read(data)
	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	_ = store.PutBundle(digest, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dest := filepath.Join(b.TempDir(), "output")
		_ = store.CopyToPath(digest, "bundle", dest)
	}
}
