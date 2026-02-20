// forkbomb.go spawns child processes in a loop (used to test PID limits).
// Usage: forkbomb <count>
// It spawns up to <count> child processes that each sleep briefly.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: forkbomb <count>\n")
		os.Exit(1)
	}

	count, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid count: %s\n", os.Args[1])
		os.Exit(1)
	}

	sleepCmd := "sleep"
	sleepArg := "10"
	if runtime.GOOS == "windows" {
		sleepCmd = "cmd"
		sleepArg = "/c timeout /t 10 /nobreak >nul"
	}

	spawned := 0
	for i := 0; i < count; i++ {
		cmd := exec.Command(sleepCmd, sleepArg)
		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "fork failed after %d processes: %v\n", spawned, err)
			os.Exit(2)
		}
		spawned++
	}

	fmt.Fprintf(os.Stdout, "spawned %d processes\n", spawned)

	// Wait a bit for limits to take effect
	time.Sleep(2 * time.Second)
}
