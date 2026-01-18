package registry

// ResolveResponse represents the response from the resolve endpoint
type ResolveResponse struct {
	Package  string          `json:"package"`
	Ref      string          `json:"ref"`
	Resolved ResolvedVersion `json:"resolved"`
}

// ResolvedVersion contains the resolved package information
type ResolvedVersion struct {
	Version            string         `json:"version"`
	GitSHA             string         `json:"git_sha"`
	Status             string         `json:"status"`
	CertificationLevel int            `json:"certification_level"`
	Manifest           ArtifactInfo   `json:"manifest"`
	Bundle             BundleInfo     `json:"bundle"`
	Evidence           []EvidenceInfo `json:"evidence"`
}

// ArtifactInfo contains digest and URL for an artifact
type ArtifactInfo struct {
	Digest string `json:"digest"`
	URL    string `json:"url"`
}

// BundleInfo contains digest, URL, and size for a bundle
type BundleInfo struct {
	Digest    string `json:"digest"`
	URL       string `json:"url"`
	SizeBytes int64  `json:"size_bytes"`
}

// EvidenceInfo contains evidence information
type EvidenceInfo struct {
	Kind   string `json:"kind"`
	Digest string `json:"digest"`
	URL    string `json:"url"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents the response from login endpoint
type LoginResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// CatalogResponse represents the response from catalog endpoint
type CatalogResponse struct {
	Packages []PackageInfo `json:"packages"`
}

// PackageInfo represents a package in the catalog
type PackageInfo struct {
	Package       string `json:"package"`
	Visibility    string `json:"visibility"`
	LatestVersion string `json:"latest_version"`
}
