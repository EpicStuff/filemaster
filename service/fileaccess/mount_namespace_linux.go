//go:build linux

package fileaccess

import "os"

// fanotify mount marks apply to a vfsmount, so marks taken in a private mount
// namespace (systemd's ProtectHome, PrivateTmp, ...) enforce nothing for the
// rest of the system. An unreadable link is not treated as isolation.
func mountNamespaceIsolated() bool {
	self, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return false
	}
	init, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		return false
	}
	return self != init
}
