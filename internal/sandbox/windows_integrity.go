//go:build windows

package sandbox

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Well-known integrity level SIDs
var (
	// S-1-16-4096 = Low integrity level
	lowIntegritySID = "S-1-16-4096"
)

// TOKEN_MANDATORY_LABEL structure for SetTokenInformation
type tokenMandatoryLabel struct {
	Label windows.SIDAndAttributes
}

// setLowIntegrity creates a token with Low integrity level and assigns it
// to the command. Low integrity processes cannot write to higher-integrity
// objects (files, registry keys, etc.), providing defense-in-depth.
func setLowIntegrity(cmd *exec.Cmd) error {
	// Open the current process token
	var processToken windows.Token
	proc := windows.CurrentProcess()
	err := windows.OpenProcessToken(proc, windows.TOKEN_DUPLICATE|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &processToken)
	if err != nil {
		return fmt.Errorf("failed to open process token: %w", err)
	}
	defer processToken.Close()

	// Duplicate the token for modification
	var dupToken windows.Token
	err = windows.DuplicateTokenEx(
		processToken,
		windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_DUPLICATE,
		nil,
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&dupToken,
	)
	if err != nil {
		return fmt.Errorf("failed to duplicate token: %w", err)
	}

	// Convert the Low integrity SID string to a SID structure
	sid, err := windows.StringToSid(lowIntegritySID)
	if err != nil {
		dupToken.Close()
		return fmt.Errorf("failed to create Low integrity SID: %w", err)
	}

	// Set the token integrity level to Low
	tml := tokenMandatoryLabel{
		Label: windows.SIDAndAttributes{
			Sid:        sid,
			Attributes: 0x00000020, // SE_GROUP_INTEGRITY
		},
	}

	// TokenIntegrityLevel = 25
	const tokenIntegrityLevel = 25
	err = windows.SetTokenInformation(
		dupToken,
		tokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&tml)),
		uint32(unsafe.Sizeof(tml)),
	)
	if err != nil {
		dupToken.Close()
		return fmt.Errorf("failed to set token integrity level: %w", err)
	}

	// Assign the modified token to the command
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Token = syscall.Token(dupToken)

	return nil
}
