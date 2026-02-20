// writefiles.go attempts to write to specified paths (used to test filesystem isolation).
// Usage: writefiles <path1> [path2] ...
// Exits with code 0 if all writes succeed, 1 if any fail.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: writefiles <path1> [path2] ...\n")
		os.Exit(1)
	}

	failed := 0
	for _, path := range os.Args[1:] {
		testFile := filepath.Join(path, "mcp-sandbox-test-write.tmp")
		err := os.WriteFile(testFile, []byte("sandbox write test"), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "DENIED: write to %s: %v\n", path, err)
			failed++
		} else {
			fmt.Fprintf(os.Stdout, "OK: wrote to %s\n", path)
			os.Remove(testFile)
		}
	}

	if failed > 0 {
		os.Exit(1)
	}
}
