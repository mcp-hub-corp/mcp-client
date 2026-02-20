// sleep.go sleeps for N seconds (used to test timeout enforcement).
// Usage: sleep <seconds>
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: sleep <seconds>\n")
		os.Exit(1)
	}

	seconds, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid seconds: %s\n", os.Args[1])
		os.Exit(1)
	}

	time.Sleep(time.Duration(seconds) * time.Second)
}
