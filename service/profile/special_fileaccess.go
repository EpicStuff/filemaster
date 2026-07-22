package profile

// filemaster-specific: file-access rule seeds for the special profiles.
// createSpecialProfile (profile creation) and the UI "reset to default" action
// both derive their rule lists from SeededRuleDefaults here, so there is one
// source of truth. Adding a new seeded profile is a single fileAccessSeeds entry.

import (
	"path/filepath"
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

// SetFilemasterSeedPaths supplies the stable runtime directories used when a
// Filemaster special profile is first created. binDir and dataDir are granted
// File Access; only the executable and binDir are executable. Existing
// profiles are left untouched: during development, delete the profile database
// to recreate them with new seed values.
func SetFilemasterSeedPaths(binDir, dataDir string) {
	paths := []string{binDir, dataDir}
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
// executable and the runtime directories (data dir included), while Execute is
// limited to the executable and the binary directory.
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
