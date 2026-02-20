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

// buildSeccompNotice returns an informational string describing the current
// seccomp availability. This is a detection-only module; actually applying
// seccomp-BPF filters to child processes from Go would require a helper
// binary approach since Go does not expose SysProcAttr.Seccomp.
func buildSeccompNotice() string {
	if detectSeccomp() {
		return "seccomp: available (detection only; enforcement requires helper binary)"
	}
	return "seccomp: not available on this system"
}
