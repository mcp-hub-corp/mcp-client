//go:build linux

package sandbox

import (
	"golang.org/x/sys/unix"
)

// Landlock syscall number (stable ABI since Linux 5.13, same on amd64 and arm64)
const sysLandlockCreateRuleset = 444

// landlockCreateRulesetFlagVersion is the flag passed to landlock_create_ruleset
// with a nil attr to query the supported ABI version.
const landlockCreateRulesetFlagVersion = 1 << 0

// detectLandlock probes the kernel for Landlock LSM support.
// Returns (true, abiVersion) if Landlock is available, (false, 0) otherwise.
func detectLandlock() (available bool, abiVersion int) {
	// Query the highest supported ABI version by calling landlock_create_ruleset
	// with a nil ruleset_attr pointer and size 0, plus the VERSION flag.
	// On success the return value is the ABI version number.
	r, _, errno := unix.Syscall(
		sysLandlockCreateRuleset,
		0, // attr = NULL
		0, // size = 0
		landlockCreateRulesetFlagVersion,
	)

	if errno != 0 {
		// ENOSYS  = syscall not implemented (kernel too old or Landlock disabled)
		// EOPNOTSUPP = Landlock compiled but disabled at boot
		return false, 0
	}

	return true, int(r)
}
