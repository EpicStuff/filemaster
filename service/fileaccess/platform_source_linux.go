//go:build linux && !filemaster_test

package fileaccess

// newPlatformSource returns the production Linux event source. The registered
// daemon config is authoritative, including when its value is empty.
func newPlatformSource(log logger) (Source, error) {
	return newFanotifySource(resolveWatchPaths(), log)
}
