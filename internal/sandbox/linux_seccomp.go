//go:build linux

package sandbox

import (
	"os"
	"strings"
)

// detectSeccomp checks whether seccomp is available on the current system.
// It first tries to read /proc/self/status looking for a "Seccomp:" field,
// and falls back to checking for the existence of /proc/sys/kernel/seccomp.
func detectSeccomp() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Seccomp:") {
				return true
			}
		}
	}

	_, err = os.Stat("/proc/sys/kernel/seccomp")
	return err == nil
}
