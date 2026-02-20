// exitcode.go exits with the specified exit code (used to test basic execution).
// Usage: exitcode <code>
package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: exitcode <code>\n")
		os.Exit(1)
	}

	code, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid exit code: %s\n", os.Args[1])
		os.Exit(1)
	}

	os.Exit(code)
}
