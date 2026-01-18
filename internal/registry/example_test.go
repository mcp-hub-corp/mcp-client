package registry_test

import (
	"fmt"
	"log"

	"github.com/security-mcp/mcp-client/internal/registry"
)

// Example of creating a registry client
func ExampleNewClient() {
	client := registry.NewClient("https://registry.mcp-hub.info")

	fmt.Printf("Client created for: %s\n", "registry.mcp-hub.info")
	_ = client
	// Output: Client created for: registry.mcp-hub.info
}

// Example of validating a digest
func ExampleValidateDigest() {
	data := []byte("test content")

	// Compute digest
	hash := registry.ComputeSHA256(data)
	expectedDigest := "sha256:" + hash

	// Validate
	err := registry.ValidateDigest(data, expectedDigest)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Digest validation successful")
	// Output: Digest validation successful
}

// Example of parsing a digest string
func ExampleParseDigest() {
	digest := "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"

	algo, hex, err := registry.ParseDigest(digest)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Algorithm: %s\n", algo)
	fmt.Printf("Hex length: %d\n", len(hex))
	// Output:
	// Algorithm: sha256
	// Hex length: 64
}

// Example of computing SHA256 hash
func ExampleComputeSHA256() {
	data := []byte("hello world")
	hash := registry.ComputeSHA256(data)

	fmt.Printf("SHA256 length: %d\n", len(hash))
	// Output: SHA256 length: 64
}
