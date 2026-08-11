package profile

// filemaster-specific: file-access rule seeds for the special profiles.
// createSpecialProfile (profile creation) and the UI "reset to default" action
// both derive their rule lists from SeededRuleDefaults here, so there is one
// source of truth. Adding a new seeded profile is a single fileAccessSeeds entry.

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	filemasterSeedPathsMu sync.RWMutex
	filemasterSeedPaths   filemasterFileAccessSeeds
)

// filemasterFileAccessSeeds separates user-facing File Access from Execute
// locations, keeping the seeded policy easy to review and edit.
type filemasterFileAccessSeeds struct {
	access []string
	exec   []string
}

// filemasterUIAppDirs are the desktop's runtime state directories, relative to a
// user's home. Without them the desktop blocks on its own storage in prompt
// mode: the prompt that would decide the access is rendered by the process the
// access is blocking. WebKitGTK derives its directory names from the binary
// name, Tauri from the bundle identifier, hence both.
var filemasterUIAppDirs = []string{
	".config/filemaster",      // window state
	".local/share/filemaster", // mediakeys, storage
	".local/share/filemaster", // WebKit HSTS store
	".cache/filemaster",       // WebKitCache, CacheStorage
	// Shared GTK/GPU runtime caches. Not Filemaster's, but the desktop cannot
	// render without them, and a prompt for them cannot be answered.
	".cache/mesa_shader_cache",
	".cache/dconf",
}

// filemasterUISeedPaths expands filemasterUIAppDirs across the home directories
// the desktop can run from. Rule patterns match literal prefixes, so per-user
// paths cannot be expressed as a wildcard and have to be enumerated.
func filemasterUISeedPaths() []string {
	var paths []string
	for _, home := range userHomeDirsFunc() {
		for _, dir := range filemasterUIAppDirs {
			paths = append(paths, filepath.Join(home, dir))
		}
	}
	return paths
}

// userHomeDirsFunc is swapped in tests to keep seed expectations off the host's
// real accounts.
var userHomeDirsFunc = userHomeDirs

// userHomeDirs returns the home directories of accounts that can run the
// desktop, limited to /home and /root to keep the seed off system accounts.
// Directories under /home are included even without a passwd entry, so that
// directory-service accounts (LDAP, SSSD) are covered too.
func userHomeDirs() []string {
	seen := make(map[string]struct{})
	var homes []string
	add := func(home string) {
		home = filepath.Clean(home)
		if home != "/root" && !strings.HasPrefix(home, "/home/") {
			return
		}
		if _, ok := seen[home]; ok {
			return
		}
		seen[home] = struct{}{}
		homes = append(homes, home)
	}

	if contents, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, line := range strings.Split(string(contents), "\n") {
			if fields := strings.Split(line, ":"); len(fields) >= 6 {
				add(fields[5])
			}
		}
	}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				add(filepath.Join("/home", entry.Name()))
			}
		}
	}
	return homes
}

// SetFilemasterSeedPaths supplies the stable runtime directories used when a
// Filemaster special profile is first created. binDir, dataDir and the desktop's
// per-user state directories are granted File Access; only the executable and
// binDir are executable. Existing profiles are left untouched: during
// development, delete the profile database to recreate them with new seed values.
func SetFilemasterSeedPaths(binDir, dataDir string) {
	paths := append([]string{binDir, dataDir}, filemasterUISeedPaths()...)
	seen := make(map[string]struct{}, len(paths))
	access := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		path = filepath.Clean(path)
		if path == "." || path == "/" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		access = append(access, path)
	}

	filemasterSeedPathsMu.Lock()
	filemasterSeedPaths = filemasterFileAccessSeeds{access: access}
	if binDir != "" {
		binDir = filepath.Clean(binDir)
		if binDir != "." && binDir != "/" {
			filemasterSeedPaths.exec = []string{binDir}
		}
	}
	filemasterSeedPathsMu.Unlock()
}

func filemasterFileAccessRules(executablePath string) []string {
	seen := make(map[string]struct{})
	rules := make([]string, 0, 4)

	addFile := func(path string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if _, ok := seen["file:"+path]; ok {
			return
		}
		seen["file:"+path] = struct{}{}
		rules = append(rules, "+ "+path)
	}
	addDir := func(path string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if path == "." || path == "/" {
			return
		}
		if _, ok := seen["dir:"+path]; ok {
			return
		}
		seen["dir:"+path] = struct{}{}
		rules = append(rules, "+ "+path+"/**")
	}

	addFile(executablePath)
	addDir(filepath.Dir(executablePath))

	filemasterSeedPathsMu.RLock()
	paths := append([]string(nil), filemasterSeedPaths.access...)
	filemasterSeedPathsMu.RUnlock()
	for _, path := range paths {
		addDir(path)
	}

	return rules
}

func filemasterFileAccessExecRules(executablePath string) []string {
	seen := make(map[string]struct{})
	rules := make([]string, 0, 3)
	addFile := func(path string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if _, ok := seen["file:"+path]; ok {
			return
		}
		seen["file:"+path] = struct{}{}
		rules = append(rules, "+ "+path)
	}
	addDir := func(path string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if path == "." || path == "/" {
			return
		}
		if _, ok := seen["dir:"+path]; ok {
			return
		}
		seen["dir:"+path] = struct{}{}
		rules = append(rules, "+ "+path+"/**")
	}

	addFile(executablePath)
	addDir(filepath.Dir(executablePath))
	filemasterSeedPathsMu.RLock()
	paths := append([]string(nil), filemasterSeedPaths.exec...)
	filemasterSeedPathsMu.RUnlock()
	for _, path := range paths {
		addDir(path)
	}
	return rules
}

func systemdFileAccessRules() []string {
	paths := []string{
		"/run/systemd",
		"/run/dbus",
		"/var/lib/systemd",
		"/etc/systemd",
		"/usr/lib/systemd",
		"/lib/systemd",
		"/usr/lib64/systemd",
		"/lib64/systemd",
		"/proc",
		"/sys",
		"/dev",
	}
	rules := make([]string, 0, len(paths))
	for _, path := range paths {
		rules = append(rules, "+ "+path+"/**")
	}
	return rules
}

// fileAccessSeed returns the seeded rule-list config for one special profile,
// given the profile's executable/presentation path. Only rule-list keys belong
// here; other seeded config (e.g. the default action) stays in
// createSpecialProfile.
type fileAccessSeed func(path string) map[string]interface{}

// fileAccessSeeds maps special profile IDs to their rule-list seed builders.
// To add a seeded profile: add one entry here (and set any non-rule seed config
// in createSpecialProfile). Profiles absent from this map have no seed, so their
// "reset to default" clears the per-app override and inherits the global rules.
var fileAccessSeeds = map[string]fileAccessSeed{
	SystemdProfileID: func(string) map[string]interface{} {
		rules := systemdFileAccessRules()
		return map[string]interface{}{
			CfgOptionFileAccessReadRulesKey: rules,
			CfgOptionFileAccessExecRulesKey: rules,
		}
	},
	PortmasterProfileID:         filemasterSelfSeed,
	PortmasterAppProfileID:      filemasterSelfSeed,
	PortmasterNotifierProfileID: filemasterSelfSeed,
}

// filemasterSelfSeed seeds Filemaster's own profiles: File Access covers the
// executable and the runtime directories (data dir and the desktop's per-user
// state included), while Execute is limited to the executable and the binary
// directory. Write rules stay unseeded because no runtime write event exists
// yet; FAN_OPEN_PERM covers opening for write and is governed by File Access.
func filemasterSelfSeed(path string) map[string]interface{} {
	return map[string]interface{}{
		CfgOptionFileAccessReadRulesKey: filemasterFileAccessRules(path),
		CfgOptionFileAccessExecRulesKey: filemasterFileAccessExecRules(path),
	}
}

// SeededRuleDefaults returns the seeded rule-list config for a profile, keyed by
// config option, or nil when the profile has no seed. It is the single source of
// truth for both profile creation and the UI "reset to default" action.
func SeededRuleDefaults(profileID, path string) map[string]interface{} {
	if seed, ok := fileAccessSeeds[profileID]; ok {
		return seed(path)
	}
	return nil
}
