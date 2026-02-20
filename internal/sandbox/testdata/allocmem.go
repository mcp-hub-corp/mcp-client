// allocmem.go allocates N megabytes of memory (used to test memory limits).
// Usage: allocmem <megabytes>
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: allocmem <megabytes>\n")
		os.Exit(1)
	}

	mb, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid megabytes: %s\n", os.Args[1])
		os.Exit(1)
	}

	// Allocate memory in 1MB chunks and touch each page to ensure real allocation
	size := mb * 1024 * 1024
	data := make([]byte, size)
	for i := 0; i < size; i += 4096 {
		data[i] = 1 // Touch each page
	}

	fmt.Fprintf(os.Stdout, "allocated %d MB\n", mb)

	// Keep alive briefly so the process can be inspected
	time.Sleep(1 * time.Second)

	_ = data
}
