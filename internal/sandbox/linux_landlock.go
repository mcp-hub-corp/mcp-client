//go:build linux

package sandbox

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock syscall numbers (stable ABI since Linux 5.13, same on amd64 and arm64)
const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRule       = 445
	sysLandlockRestrictSelf  = 446
)

// Landlock ABI constants
const (
	// landlockCreateRulesetFlagVersion is the flag passed to landlock_create_ruleset
	// with a nil attr to query the supported ABI version.
	landlockCreateRulesetFlagVersion = 1 << 0
)

// Landlock access flags for filesystem rules (fs_access bit mask).
const (
	landlockAccessFSExecute    = 1 << 0
	landlockAccessFSWriteFile  = 1 << 1
	landlockAccessFSReadFile   = 1 << 2
	landlockAccessFSReadDir    = 1 << 3
	landlockAccessFSRemoveDir  = 1 << 4
	landlockAccessFSRemoveFile = 1 << 5
	landlockAccessFSMakeChar   = 1 << 6
	landlockAccessFSMakeDir    = 1 << 7
	landlockAccessFSMakeReg    = 1 << 8
	landlockAccessFSMakeSock   = 1 << 9
	landlockAccessFSMakeFifo   = 1 << 10
	landlockAccessFSMakeBlock  = 1 << 11
	landlockAccessFSMakeSym    = 1 << 12
	landlockAccessFSRefer      = 1 << 13 // ABI v2+
	landlockAccessFSTruncate   = 1 << 14 // ABI v3+
)

// Composite access masks used when building rulesets.
const (
	landlockAccessFSRead = landlockAccessFSReadFile | landlockAccessFSReadDir

	landlockAccessFSWrite = landlockAccessFSWriteFile |
		landlockAccessFSRemoveDir |
		landlockAccessFSRemoveFile |
		landlockAccessFSMakeChar |
		landlockAccessFSMakeDir |
		landlockAccessFSMakeReg |
		landlockAccessFSMakeSock |
		landlockAccessFSMakeFifo |
		landlockAccessFSMakeBlock |
		landlockAccessFSMakeSym |
		landlockAccessFSTruncate

	landlockAccessFSReadWrite = landlockAccessFSRead | landlockAccessFSWrite
)

// Landlock rule type constants.
const (
	landlockRulePathBeneath = 1
)

// landlockRulesetAttr is the struct passed to landlock_create_ruleset.
// It must match the kernel layout exactly (packed, no padding).
type landlockRulesetAttr struct {
	handledAccessFS uint64
}

// landlockPathBeneathAttr is the struct passed to landlock_add_rule
// with rule type LANDLOCK_RULE_PATH_BENEATH.
type landlockPathBeneathAttr struct {
	allowedAccess uint64
	parentFd      int32
	_             [4]byte // padding to align struct
}

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

// applyLandlock restricts the calling thread to only access the specified
// filesystem paths. Read-only paths get read access; read-write paths get
// full filesystem access. All other filesystem operations are denied after
// landlock_restrict_self succeeds.
//
// This function is irreversible for the calling thread and all future children.
func applyLandlock(allowedReadPaths, allowedReadWritePaths []string) error {
	available, abi := detectLandlock()
	if !available {
		return fmt.Errorf("landlock not available on this kernel")
	}

	// Build the handled_access_fs mask. We start with the base set (ABI v1)
	// and extend when higher ABIs are detected.
	handledAccess := uint64(
		landlockAccessFSExecute |
			landlockAccessFSWriteFile |
			landlockAccessFSReadFile |
			landlockAccessFSReadDir |
			landlockAccessFSRemoveDir |
			landlockAccessFSRemoveFile |
			landlockAccessFSMakeChar |
			landlockAccessFSMakeDir |
			landlockAccessFSMakeReg |
			landlockAccessFSMakeSock |
			landlockAccessFSMakeFifo |
			landlockAccessFSMakeBlock |
			landlockAccessFSMakeSym,
	)
	if abi >= 2 {
		handledAccess |= landlockAccessFSRefer
	}
	if abi >= 3 {
		handledAccess |= landlockAccessFSTruncate
	}

	// --- Step 1: create ruleset ---
	attr := landlockRulesetAttr{
		handledAccessFS: handledAccess,
	}
	rulesetFd, _, errno := unix.Syscall(
		sysLandlockCreateRuleset,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0, // flags = 0 (create, not query)
	)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset failed: %w", errno)
	}
	defer unix.Close(int(rulesetFd))

	// --- Step 2: add rules for allowed read-only paths ---
	for _, p := range allowedReadPaths {
		if err := landlockAddPathRule(int(rulesetFd), p, uint64(landlockAccessFSRead|landlockAccessFSExecute)); err != nil {
			return fmt.Errorf("landlock add read rule for %q: %w", p, err)
		}
	}

	// --- Step 3: add rules for allowed read-write paths ---
	rwAccess := handledAccess // full access within the ruleset scope
	for _, p := range allowedReadWritePaths {
		if err := landlockAddPathRule(int(rulesetFd), p, rwAccess); err != nil {
			return fmt.Errorf("landlock add read-write rule for %q: %w", p, err)
		}
	}

	// --- Step 4: enforce (no new privs required first) ---
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS) failed: %w", err)
	}

	_, _, errno = unix.Syscall(
		sysLandlockRestrictSelf,
		rulesetFd,
		0, // flags = 0
		0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_restrict_self failed: %w", errno)
	}

	return nil
}

// landlockAddPathRule opens the given path and adds a Landlock path-beneath rule
// to the ruleset identified by rulesetFd.
func landlockAddPathRule(rulesetFd int, path string, allowedAccess uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open path %q: %w", path, err)
	}
	defer unix.Close(fd)

	rule := landlockPathBeneathAttr{
		allowedAccess: allowedAccess,
		parentFd:      int32(fd),
	}

	_, _, errno := unix.Syscall6(
		sysLandlockAddRule,
		uintptr(rulesetFd),
		landlockRulePathBeneath,
		uintptr(unsafe.Pointer(&rule)),
		0,
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_add_rule failed for %q: %w", path, errno)
	}

	return nil
}
