//go:build linux && filemaster_test

package fileaccess

import "os"

func newPlatformSource(log logger) (Source, error) {
	if path := os.Getenv("FM_FAKE_SOCKET"); path != "" {
		return newSocketSource(path, log)
	}
	return newFanotifySource(resolveWatchPaths(), log)
}
