//go:build windows

package sandbox

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	moduserenv                         = syscall.NewLazyDLL("userenv.dll")
	procCreateAppContainerProfile      = moduserenv.NewProc("CreateAppContainerProfile")
	procDeleteAppContainerProfile      = moduserenv.NewProc("DeleteAppContainerProfile")
	procDeriveAppContainerSid          = moduserenv.NewProc("DeriveAppContainerSidFromAppContainerName")
)

// appContainerInfo holds information about a created AppContainer.
type appContainerInfo struct {
	name string
	sid  uintptr // PSID pointer
}

// createAppContainerProfile creates a new AppContainer profile with the given name.
// AppContainers provide strong process isolation on Windows 10+.
// The caller must call deleteAppContainerProfile when done.
//
// Note: AppContainers require Windows 10 version 1607+ or Windows Server 2016+.
// On older systems, this function will return an error.
func createAppContainerProfile(name string) (*appContainerInfo, error) {
	if name == "" {
		return nil, fmt.Errorf("AppContainer name cannot be empty")
	}

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, fmt.Errorf("invalid AppContainer name: %w", err)
	}

	// Display name and description (same as name for simplicity)
	displayNamePtr, _ := syscall.UTF16PtrFromString(name)
	descriptionPtr, _ := syscall.UTF16PtrFromString("MCP sandbox container")

	var sidPtr uintptr

	// CreateAppContainerProfile(
	//   PCWSTR pszAppContainerName,
	//   PCWSTR pszDisplayName,
	//   PCWSTR pszDescription,
	//   PSID_AND_ATTRIBUTES pCapabilities,
	//   DWORD dwCapabilityCount,
	//   PSID* ppSidAppContainerSid
	// )
	r1, _, callErr := procCreateAppContainerProfile.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(displayNamePtr)),
		uintptr(unsafe.Pointer(descriptionPtr)),
		0, // No capabilities
		0, // Zero capabilities count
		uintptr(unsafe.Pointer(&sidPtr)),
	)

	// HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) = 0x800700B7
	// If profile already exists, derive the SID instead
	if r1 != 0 {
		if r1 == 0x800700B7 {
			// Profile already exists, get SID
			sid, err := deriveAppContainerSid(name)
			if err != nil {
				return nil, fmt.Errorf("AppContainer profile exists but failed to get SID: %w", err)
			}
			return &appContainerInfo{name: name, sid: sid}, nil
		}
		return nil, fmt.Errorf("CreateAppContainerProfile failed (HRESULT: 0x%08X): %w", r1, callErr)
	}

	return &appContainerInfo{name: name, sid: sidPtr}, nil
}

// deriveAppContainerSid gets the SID for an existing AppContainer profile.
func deriveAppContainerSid(name string) (uintptr, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, fmt.Errorf("invalid AppContainer name: %w", err)
	}

	var sidPtr uintptr
	r1, _, callErr := procDeriveAppContainerSid.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&sidPtr)),
	)
	if r1 != 0 {
		return 0, fmt.Errorf("DeriveAppContainerSidFromAppContainerName failed (HRESULT: 0x%08X): %w", r1, callErr)
	}

	return sidPtr, nil
}

// deleteAppContainerProfile removes an AppContainer profile by name.
// This should be called during Cleanup to remove the AppContainer.
func deleteAppContainerProfile(name string) error {
	if name == "" {
		return nil
	}

	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("invalid AppContainer name: %w", err)
	}

	r1, _, callErr := procDeleteAppContainerProfile.Call(
		uintptr(unsafe.Pointer(namePtr)),
	)
	if r1 != 0 {
		return fmt.Errorf("DeleteAppContainerProfile failed (HRESULT: 0x%08X): %w", r1, callErr)
	}

	return nil
}

// generateAppContainerName generates a unique AppContainer name for an MCP execution.
func generateAppContainerName(prefix string, pid int) string {
	return fmt.Sprintf("mcp-%s-%d-%d", prefix, pid, os.Getpid())
}
