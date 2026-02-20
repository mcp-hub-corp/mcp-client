//go:build windows

package sandbox

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modkernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procSetInformationJobObject = modkernel32.NewProc("SetInformationJobObject")
)

// Job Object information classes
const (
	jobObjectExtendedLimitInformation   = 9
	jobObjectCPURateControlInformation  = 15
)

// Job Object limit flags
const (
	jobObjectLimitProcessMemory  = 0x00000100
	jobObjectLimitJobMemory      = 0x00000200
	jobObjectLimitActiveProcess  = 0x00000008
	jobObjectLimitKillOnJobClose = 0x00002000
)

// CPU rate control flags
const (
	jobObjectCPURateControlEnable      = 0x1
	jobObjectCPURateControlWeightBased = 0x2
	jobObjectCPURateControlHardCap     = 0x4
)

// jobObjectCPURateControlInfo mirrors JOBOBJECT_CPU_RATE_CONTROL_INFORMATION.
// CpuRate is a percentage of total CPU time * 100 (e.g., 5000 = 50%).
type jobObjectCPURateControlInfo struct {
	ControlFlags uint32
	CpuRate      uint32
}

// JOBOBJECT_BASIC_LIMIT_INFORMATION mirrors the Windows structure.
// We define our own to use with SetInformationJobObject since the
// golang.org/x/sys/windows package's structure may not include all fields.
type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInfo
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type jobObjectBasicLimitInfo struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

// setInformationJobObject calls the Windows API SetInformationJobObject.
func setInformationJobObject(jobHandle syscall.Handle, infoClass uint32, info unsafe.Pointer, infoLen uint32) error {
	r1, _, err := procSetInformationJobObject.Call(
		uintptr(jobHandle),
		uintptr(infoClass),
		uintptr(info),
		uintptr(infoLen),
	)
	if r1 == 0 {
		return fmt.Errorf("SetInformationJobObject failed: %w", err)
	}
	return nil
}
