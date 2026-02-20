//go:build windows

package sandbox

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32              = syscall.NewLazyDLL("advapi32.dll")
	procCreateRestrictedToken = modadvapi32.NewProc("CreateRestrictedToken")
)

// DISABLE_MAX_PRIVILEGE flag for CreateRestrictedToken.
// When set, all privileges in the new token are disabled (removed from the enabled state).
const disableMaxPrivilege = 0x1

// createRestrictedToken creates a restricted token from the current process token
// with DISABLE_MAX_PRIVILEGE, which removes all privileges from the token.
// The caller is responsible for closing the returned token handle.
func createRestrictedToken() (syscall.Token, error) {
	var processToken windows.Token

	// Open the current process token
	proc := windows.CurrentProcess()
	err := windows.OpenProcessToken(proc, windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY, &processToken)
	if err != nil {
		return 0, fmt.Errorf("failed to open process token: %w", err)
	}
	defer processToken.Close()

	var restrictedToken syscall.Token

	// Call CreateRestrictedToken with DISABLE_MAX_PRIVILEGE flag.
	// Parameters:
	//   ExistingTokenHandle - handle to the primary token
	//   Flags               - DISABLE_MAX_PRIVILEGE (0x1)
	//   DisableSidCount     - 0 (no SIDs to disable)
	//   SidsToDisable       - nil
	//   DeletePrivilegeCount - 0
	//   PrivilegesToDelete  - nil
	//   RestrictedSidCount  - 0
	//   SidsToRestrict      - nil
	//   NewTokenHandle      - pointer to receive the new token
	r1, _, callErr := procCreateRestrictedToken.Call(
		uintptr(processToken),
		uintptr(disableMaxPrivilege),
		0,
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&restrictedToken)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken failed: %w", callErr)
	}

	return restrictedToken, nil
}

// applyRestrictedToken creates a restricted token with DISABLE_MAX_PRIVILEGE
// and assigns it to the command's SysProcAttr so the child process runs
// with reduced privileges.
func applyRestrictedToken(cmd *exec.Cmd) error {
	token, err := createRestrictedToken()
	if err != nil {
		return fmt.Errorf("failed to create restricted token: %w", err)
	}

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Token = token

	return nil
}

// applyMitigationPolicies applies process mitigation policies to a command.
// If denySubprocess is true, it logs that child process creation mitigation
// would be applied. Full PROC_THREAD_ATTRIBUTE_LIST implementation requires
// STARTUPINFOEX which Go's os/exec does not directly support, so this is
// a best-effort placeholder.
//
// Note: To fully block child process creation, one would need to use
// UpdateProcThreadAttribute with PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY
// and PROCESS_CREATION_CHILD_PROCESS_RESTRICTED. This requires extending
// STARTUPINFO to STARTUPINFOEX, which is not natively supported by Go's
// exec.Cmd / SysProcAttr.
func applyMitigationPolicies(cmd *exec.Cmd, denySubprocess bool) {
	if !denySubprocess {
		return
	}

	// Best-effort: Log that child process creation mitigation would be applied.
	// Full implementation requires STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_LIST,
	// which Go does not directly support through exec.Cmd.
	//
	// In the future, this could be implemented by:
	// 1. Creating a STARTUPINFOEX structure manually
	// 2. Initializing a PROC_THREAD_ATTRIBUTE_LIST
	// 3. Setting PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY with
	//    PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
	// 4. Using CreateProcessW directly instead of exec.Cmd
	//
	// For now, subprocess restriction is enforced via Job Object
	// ActiveProcessLimit (set in setJobLimits) which limits the total
	// number of processes in the job.
	_ = cmd // Acknowledge cmd parameter for future use
}
