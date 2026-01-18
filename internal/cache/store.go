package cache

// Store manages the content-addressable cache
type Store struct {
	cacheDir string
}

// NewStore creates a new cache store
func NewStore(cacheDir string) *Store {
	return &Store{
		cacheDir: cacheDir,
	}
}

// GetManifest retrieves a manifest from cache by digest
// TODO: Implement in Phase 3
func (s *Store) GetManifest(digest string) ([]byte, error) {
	return nil, nil
}

// PutManifest stores a manifest in cache
// TODO: Implement in Phase 3
func (s *Store) PutManifest(digest string, data []byte) error {
	return nil
}

// GetBundle retrieves a bundle from cache by digest
// TODO: Implement in Phase 3
func (s *Store) GetBundle(digest string) (string, error) {
	return "", nil
}

// PutBundle stores a bundle in cache
// TODO: Implement in Phase 3
func (s *Store) PutBundle(digest, path string) error {
	return nil
}

// List lists all cached artifacts
// TODO: Implement in Phase 3
func (s *Store) List() ([]string, error) {
	return nil, nil
}

// Remove removes an artifact from cache
// TODO: Implement in Phase 3
func (s *Store) Remove(digest string) error {
	return nil
}
