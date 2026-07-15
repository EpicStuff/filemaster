package profile

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/safing/portmaster/base/log"
)

const (
	// UnidentifiedProfileID is the profile ID used for unidentified processes.
	UnidentifiedProfileID = "_unidentified"
	// UnidentifiedProfileName is the name used for unidentified processes.
	UnidentifiedProfileName = "Other Connections"
	// UnidentifiedProfileDescription is the description used for unidentified processes.
	UnidentifiedProfileDescription = `Connections that could not be attributed to a specific app.

The Portmaster attributes connections (only TCP/UDP) to specific apps. When attribution for a connection fails, it ends up here.

Connections from unsupported protocols (like ICMP/"ping") are always collected here.
`

	// UnsolicitedProfileID is the profile ID used for unsolicited connections.
	UnsolicitedProfileID = "_unsolicited"
	// UnsolicitedProfileName is the name used for unsolicited connections.
	UnsolicitedProfileName = "Network Noise"
	// UnsolicitedProfileDescription is the description used for unsolicited connections.
	UnsolicitedProfileDescription = `Common connections coming from your Local Area Network.

Local Area Networks usually have quite a lot of traffic from applications that are trying to find things on the network. This might be a computer trying to find a printer, or a file sharing application searching for local peers. These network packets will automatically arrive at your device.

These connections - the "network noise" - can be found in this app.`

	// SystemProfileID is the profile ID used for the system/kernel.
	SystemProfileID = "_system"
	// SystemProfileName is the name used for the system/kernel.
	SystemProfileName = "Operating System"
	// SystemProfileDescription is the description used for the system/kernel.
	SystemProfileDescription = "This is the operation system itself."

	// SystemResolverProfileID is the profile ID used for the system's DNS resolver.
	SystemResolverProfileID = "_system-resolver"
	// SystemResolverProfileName is the name used for the system's DNS resolver.
	SystemResolverProfileName = "System DNS Client"
	// SystemResolverProfileDescription is the description used for the system's DNS resolver.
	SystemResolverProfileDescription = `The System DNS Client is a system service that requires special handling.

For regular network connections, the configured settings will apply as usual.

DNS Requests coming from the System DNS Client, however, could actually be coming from any other application on the system: The System DNS Client resolves domain names on behalf of other applications.

In order to correctly handle these, DNS Requests (not regular connections), do not take the globally configured Outgoing Rules into account.

Additionally, the settings for the System DNS Client are specially pre-configured. If you are having issues or want to revert to the default settings, please delete this profile below. It will be automatically recreated with the default settings.
`

	// SystemdProfileID is the profile ID used for systemd PID 1 and its helpers.
	SystemdProfileID = "_systemd"
	// SystemdProfileName is the name used for systemd services.
	SystemdProfileName = "systemd Services"
	// SystemdProfileDescription explains the intentionally narrow systemd seed rules.
	SystemdProfileDescription = "Editable allow rules seeded for systemd PID 1 and helpers. Requests outside these rules continue to use the normal default action."

	// PortmasterProfileID is the profile ID used for the Portmaster Core itself.
	PortmasterProfileID = "_portmaster"
	// PortmasterProfileName is the name used for the Portmaster Core itself.
	PortmasterProfileName = "Portmaster Core Service"
	// PortmasterProfileDescription is the description used for the Portmaster Core itself.
	PortmasterProfileDescription = `This is the Portmaster itself, which runs in the background as a system service. App specific settings have no effect.`

	// PortmasterAppProfileID is the profile ID used for the Portmaster App.
	PortmasterAppProfileID = "_portmaster-app"
	// PortmasterAppProfileName is the name used for the Portmaster App.
	PortmasterAppProfileName = "Portmaster User Interface"
	// PortmasterAppProfileDescription is the description used for the Portmaster App.
	PortmasterAppProfileDescription = `This is the Portmaster UI Windows.`

	// PortmasterNotifierProfileID is the profile ID used for the Portmaster Notifier.
	PortmasterNotifierProfileID = "_portmaster-notifier"
	// PortmasterNotifierProfileName is the name used for the Portmaster Notifier.
	PortmasterNotifierProfileName = "Portmaster Notifier"
	// PortmasterNotifierProfileDescription is the description used for the Portmaster Notifier.
	PortmasterNotifierProfileDescription = `This is the Portmaster UI Tray Notifier.`
)

var (
	filemasterSeedPathsMu sync.RWMutex
	filemasterSeedPaths   []string
)

// SetFilemasterSeedPaths supplies the stable runtime directories that are
// included when the Filemaster daemon profile is first created. Existing
// profiles are intentionally left untouched so users retain control.
func SetFilemasterSeedPaths(paths []string) {
	seen := make(map[string]struct{}, len(paths))
	cleaned := make([]string, 0, len(paths))
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
		cleaned = append(cleaned, path)
	}

	filemasterSeedPathsMu.Lock()
	filemasterSeedPaths = cleaned
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
	paths := append([]string(nil), filemasterSeedPaths...)
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

func isSpecialProfileID(id string) bool {
	switch id {
	case UnidentifiedProfileID,
		UnsolicitedProfileID,
		SystemProfileID,
		SystemResolverProfileID,
		SystemdProfileID,
		PortmasterProfileID,
		PortmasterAppProfileID,
		PortmasterNotifierProfileID:
		return true
	default:
		return false
	}
}

func updateSpecialProfileMetadata(profile *Profile, binaryPath string) (changed bool) {
	// Get new profile name and check if profile is applicable to special handling.
	var newProfileName, newDescription string
	switch profile.ID {
	case UnidentifiedProfileID:
		newProfileName = UnidentifiedProfileName
		newDescription = UnidentifiedProfileDescription
	case UnsolicitedProfileID:
		newProfileName = UnsolicitedProfileName
		newDescription = UnsolicitedProfileDescription
	case SystemProfileID:
		newProfileName = SystemProfileName
		newDescription = SystemProfileDescription
	case SystemResolverProfileID:
		newProfileName = SystemResolverProfileName
		newDescription = SystemResolverProfileDescription
	case SystemdProfileID:
		newProfileName = SystemdProfileName
		newDescription = SystemdProfileDescription
	case PortmasterProfileID:
		newProfileName = PortmasterProfileName
		newDescription = PortmasterProfileDescription
	case PortmasterAppProfileID:
		newProfileName = PortmasterAppProfileName
		newDescription = PortmasterAppProfileDescription
	case PortmasterNotifierProfileID:
		newProfileName = PortmasterNotifierProfileName
		newDescription = PortmasterNotifierProfileDescription
	default:
		return false
	}

	// Update profile name if needed.
	if profile.Name != newProfileName {
		profile.Name = newProfileName
		changed = true
	}

	// Update description if needed.
	if profile.Description != newDescription {
		profile.Description = newDescription
		changed = true
	}

	// Update PresentationPath to new value.
	if profile.PresentationPath != binaryPath {
		profile.PresentationPath = binaryPath
		changed = true
	}

	return changed
}

func createSpecialProfile(profileID string, path string) *Profile {
	switch profileID {
	case UnidentifiedProfileID:
		return New(&Profile{
			ID:               UnidentifiedProfileID,
			Source:           SourceLocal,
			PresentationPath: path,
		})

	case UnsolicitedProfileID:
		return New(&Profile{
			ID:               UnsolicitedProfileID,
			Source:           SourceLocal,
			PresentationPath: path,
		})

	case SystemProfileID:
		return New(&Profile{
			ID:               SystemProfileID,
			Source:           SourceLocal,
			PresentationPath: path,
		})

	case SystemResolverProfileID:
		return New(&Profile{
			ID:               SystemResolverProfileID,
			Source:           SourceLocal,
			PresentationPath: path,
			Config: map[string]interface{}{
				// Permit by default so the system resolver doesn't
				// prompt on every file access (DNS resolver is rarely
				// what users want to gate).
				CfgOptionDefaultActionKey: DefaultActionPermitValue,
			},
		})

	case SystemdProfileID:
		return New(&Profile{
			ID:               SystemdProfileID,
			Source:           SourceLocal,
			PresentationPath: path,
			Config: map[string]interface{}{
				CfgOptionFileAccessRulesKey: systemdFileAccessRules(),
			},
		})

	case PortmasterProfileID:
		return New(&Profile{
			ID:               PortmasterProfileID,
			Source:           SourceLocal,
			PresentationPath: path,
			Config: map[string]interface{}{
				CfgOptionDefaultActionKey:   DefaultActionPermitValue,
				CfgOptionFileAccessRulesKey: filemasterFileAccessRules(path),
			},
		})

	case PortmasterAppProfileID:
		return New(&Profile{
			ID:               PortmasterAppProfileID,
			Source:           SourceLocal,
			PresentationPath: path,
			Config: map[string]interface{}{
				// The UI process: tighten by default. File access
				// prompts surface through the UI itself, so denying
				// here lets us tighten the surface without breaking
				// the prompt loop.
				CfgOptionDefaultActionKey: DefaultActionBlockValue,
			},
			Internal: true,
		})

	case PortmasterNotifierProfileID:
		return New(&Profile{
			ID:               PortmasterNotifierProfileID,
			Source:           SourceLocal,
			PresentationPath: path,
			Config: map[string]interface{}{
				CfgOptionDefaultActionKey: DefaultActionBlockValue,
			},
			Internal: true,
		})

	default:
		return nil
	}
}

// specialProfileNeedsReset is used as a workaround until we can properly use
// profile layering in a way that it is also correctly handled by the UI. We
// check if the special profile has not been changed by the user and if not,
// check if the profile is outdated and can be upgraded.
func specialProfileNeedsReset(profile *Profile) bool {
	if profile == nil {
		return false
	}

	switch {
	case profile.Source != SourceLocal:
		// Special profiles live in the local scope only.
		return false
	case profile.LastEdited > 0:
		// Profile was edited - don't override user settings.
		return false
	}

	switch profile.ID {
	case SystemResolverProfileID:
		return canBeUpgraded(profile, "22.8.2023")
	case PortmasterProfileID:
		// Seed the editable Filemaster file-access rules for unmodified
		// installations. Edited profiles are preserved by the guard above.
		return canBeUpgraded(profile, "15.7.2026")
	case PortmasterAppProfileID:
		return canBeUpgraded(profile, "22.8.2023")
	default:
		// Not a special profile or no upgrade available yet.
		return false
	}
}

func canBeUpgraded(profile *Profile, upgradeDate string) bool {
	// Parse upgrade date.
	upgradeTime, err := time.Parse("2.1.2006", upgradeDate)
	if err != nil {
		log.Warningf("profile: failed to parse date %q: %s", upgradeDate, err)
		return false
	}

	// Check if the upgrade is applicable.
	if profile.Created < upgradeTime.Unix() {
		log.Infof("profile: upgrading special profile %s", profile.ScopedID())
		return true
	}

	return false
}
