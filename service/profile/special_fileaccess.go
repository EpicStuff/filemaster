package profile

// filemaster-specific: file-access rule seeds for the special profiles, defined
// in seeds.yaml. createSpecialProfile (profile creation) and the UI "reset to
// default" action both derive their rule lists from SeededRuleDefaults here, so
// there is one source of truth.

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed seeds.yaml
var seedsYAML []byte

// ruleSeeds maps special profile IDs to config option keys to rule templates.
var ruleSeeds map[string]map[string][]string

func init() {
	if err := yaml.Unmarshal(seedsYAML, &ruleSeeds); err != nil {
		panic(fmt.Sprintf("profile: parse seeds.yaml: %s", err))
	}
}

var seedPlaceholder = regexp.MustCompile(`\{[a-z]+\}`)

var (
	seedValuesMu sync.RWMutex
	seedValues   map[string][]string
)

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

// SetFilemasterSeedPaths supplies the values of the {bindir}, {datadir} and
// {home} placeholders. Existing profiles are left untouched: during
// development, delete the profile database to recreate them with new seed values.
func SetFilemasterSeedPaths(binDir, dataDir string) {
	values := map[string][]string{
		"{bindir}":  seedValue(binDir),
		"{datadir}": seedValue(dataDir),
	}
	for _, home := range userHomeDirsFunc() {
		values["{home}"] = append(values["{home}"], seedValue(home)...)
	}

	seedValuesMu.Lock()
	seedValues = values
	seedValuesMu.Unlock()
}

// seedValue returns the cleaned placeholder value of path, or none when path is
// unset or would widen a rule to the whole filesystem.
func seedValue(path string) []string {
	if path == "" {
		return nil
	}
	path = filepath.Clean(path)
	if path == "." || path == "/" {
		return nil
	}
	return []string{path}
}

// SeededRuleDefaults returns the seeded rule-list config for a profile, keyed by
// config option, or nil when the profile has no seed. path is the profile's
// executable/presentation path.
func SeededRuleDefaults(profileID, path string) map[string]interface{} {
	seed, ok := ruleSeeds[profileID]
	if !ok {
		return nil
	}

	values := map[string][]string{
		"{exe}":    seedValue(path),
		"{exedir}": seedValue(filepath.Dir(path)),
	}
	seedValuesMu.RLock()
	for name, value := range seedValues {
		values[name] = value
	}
	seedValuesMu.RUnlock()

	config := make(map[string]interface{}, len(seed))
	for key, templates := range seed {
		seen := make(map[string]struct{})
		rules := make([]string, 0, len(templates))
		for _, template := range templates {
			expanded := []string{template}
			for _, name := range seedPlaceholder.FindAllString(template, -1) {
				var next []string
				for _, rule := range expanded {
					for _, value := range values[name] {
						next = append(next, strings.Replace(rule, name, value, 1))
					}
				}
				expanded = next
			}
			for _, rule := range expanded {
				if _, ok := seen[rule]; !ok {
					seen[rule] = struct{}{}
					rules = append(rules, rule)
				}
			}
		}
		config[key] = rules
	}
	return config
}
