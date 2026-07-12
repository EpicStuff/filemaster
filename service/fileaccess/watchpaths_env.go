package fileaccess

import (
	"os"
	"strings"
)

const envWatchPaths = "FM_WATCH_PATHS"

// watchPathsFromEnv parses FM_WATCH_PATHS as a colon-separated list.
// It is used only by standalone tools whose instance does not expose
// the daemon config module.
func watchPathsFromEnv() []string {
	raw := os.Getenv(envWatchPaths)
	if raw == "" {
		return nil
	}

	var paths []string
	for _, path := range strings.Split(raw, ":") {
		if path = strings.TrimSpace(path); path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}
