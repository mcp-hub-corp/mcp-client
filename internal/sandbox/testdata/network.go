// network.go attempts an HTTP request (used to test network isolation).
// Usage: network <url>
// Exits with code 0 if request succeeds, 1 if it fails.
package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: network <url>\n")
		os.Exit(1)
	}

	url := os.Args[1]

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DENIED: network request to %s: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	fmt.Fprintf(os.Stdout, "OK: %s responded with %d\n", url, resp.StatusCode)
}
