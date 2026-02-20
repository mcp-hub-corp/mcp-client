//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// canUseUserNamespaces checks whether unprivileged user namespaces are enabled
// on the current Linux kernel. If the sysctl file does not exist (older kernels
// or kernels compiled without the knob), user namespaces are assumed available.
// If the file exists, its value must be "1" to allow unprivileged usage.
func canUseUserNamespaces() bool {
	data, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone")
	if err != nil {
		// File does not exist: kernel does not gate unprivileged user namespaces,
		// so they are available by default on most modern kernels.
		return true
	}

	return strings.TrimSpace(string(data)) == "1"
}

// setupUserNamespace configures cmd to run inside a new user namespace combined
// with a new network namespace. This enables network isolation without requiring
// root or CAP_NET_ADMIN by mapping the current uid/gid to container ID 0.
//
// The resulting process sees itself as root (uid 0 / gid 0) inside the namespace
// while remaining unprivileged on the host.
func setupUserNamespace(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	uid := os.Getuid()
	gid := os.Getgid()

	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET

	cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
		{
			ContainerID: 0,
			HostID:      uid,
			Size:        1,
		},
	}

	cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
		{
			ContainerID: 0,
			HostID:      gid,
			Size:        1,
		},
	}

	return nil
}
