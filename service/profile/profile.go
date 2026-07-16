package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tevino/abool"

	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/base/database/record"
	"github.com/safing/portmaster/base/log"
	"github.com/safing/portmaster/base/utils"
	"github.com/safing/portmaster/service/profile/binmeta"
)

// ProfileSource is the source of the profile.
type ProfileSource string //nolint:golint

// Profile Sources.
const (
	SourceLocal   ProfileSource = "local"   // local, editable
	SourceSpecial ProfileSource = "special" // specials (read-only)
)

// Default Action IDs.
const (
	DefaultActionNotSet uint8 = 0
	DefaultActionBlock  uint8 = 1
	DefaultActionAsk    uint8 = 2
	DefaultActionPermit uint8 = 3
)

// Profile is used to predefine a security profile for applications.
type Profile struct { //nolint:maligned // not worth the effort
	record.Base
	sync.RWMutex

	// ID is a unique identifier for the profile.
	ID string // constant
	// Source describes the source of the profile.
	Source ProfileSource // constant
	// Revision is the durable optimistic-concurrency token. It is incremented
	// only by the profile database hook while Controller.Put holds its record
	// transaction lock.
	Revision uint64
	// Name is a human readable name of the profile. It
	// defaults to the basename of the application.
	Name string
	// Description may hold an optional description of the
	// profile or the purpose of the application.
	Description string
	// Warning may hold an optional warning about this application.
	// It may be static or be added later on when the Portmaster detected an
	// issue with the application.
	Warning string
	// WarningLastUpdated holds the timestamp when the Warning field was last
	// updated.
	WarningLastUpdated time.Time
	// Homepage may refer to the website of the application
	// vendor.
	Homepage string

	// Deprecated: Icon holds the icon of the application. The value
	// may either be a filepath, a database key or a blob URL.
	// See IconType for more information.
	Icon string
	// Deprecated: IconType describes the type of the Icon property.
	IconType binmeta.IconType
	// Icons holds a list of icons to represent the application.
	Icons []binmeta.Icon

	// Deprecated: LinkedPath used to point to the executables this
	// profile was created for.
	// Until removed, it will be added to the Fingerprints as an exact path match.
	LinkedPath string // constant
	// PresentationPath holds the path of an executable that should be used for
	// get representative information from, like the name of the program or the icon.
	// Is automatically removed when the path does not exist.
	// Is automatically populated with the next match when empty.
	PresentationPath string
	// UsePresentationPath can be used to enable/disable fetching information
	// from the executable at PresentationPath. In some cases, this is not
	// desirable.
	UsePresentationPath bool
	// Fingerprints holds process matching information.
	Fingerprints []Fingerprint
	// Config holds profile specific setttings. It's a nested
	// object with keys defining the settings database path. All keys
	// until the actual settings value (which is everything that is not
	// an object) need to be concatenated for the settings database
	// path.
	Config map[string]interface{}

	// LastEdited holds the UTC timestamp in seconds when the profile was last
	// edited by the user. This is not set automatically, but has to be manually
	// set by the user interface.
	LastEdited int64
	// Created holds the UTC timestamp in seconds when the
	// profile has been created.
	Created int64

	// Internal is set to true if the profile is attributed to a
	// Portmaster internal process. Internal is set during profile
	// creation and may be accessed without lock.
	Internal bool

	// layeredProfile is a link to the layered profile with this profile as the
	// main profile.
	// All processes with the same binary should share the same instance of the
	// local profile and the associated layered profile.
	layeredProfile *LayeredProfile

	// Interpreted Data
	configPerspective *config.Perspective
	dataParsed        bool
	defaultAction     uint8

	// Lifecycle Management
	outdated   *abool.AtomicBool
	lastActive *int64

	// savedInternally is set to true for profiles that are saved internally.
	savedInternally bool

	// revisionCommitTarget receives the committed revision only after the
	// controller has completed durable storage for this detached candidate.
	revisionCommitTarget *Profile
}

func (profile *Profile) prepProfile() {
	// prepare configuration
	profile.outdated = abool.New()
	profile.lastActive = new(int64)

	// Migration of LinkedPath to PresentationPath
	if profile.PresentationPath == "" && profile.LinkedPath != "" {
		profile.PresentationPath = profile.LinkedPath
	}
}

func (profile *Profile) parseConfig() error {
	// Check if already parsed.
	if profile.dataParsed {
		return nil
	}

	// Create new perspective and marked as parsed.
	var err error
	profile.configPerspective, err = config.NewPerspective(profile.Config)
	if err != nil {
		return fmt.Errorf("failed to create config perspective: %w", err)
	}
	profile.dataParsed = true

	var lastErr error
	action, ok := profile.configPerspective.GetAsString(CfgOptionDefaultActionKey)
	profile.defaultAction = DefaultActionNotSet
	if ok {
		switch action {
		case DefaultActionPermitValue:
			profile.defaultAction = DefaultActionPermit
		case DefaultActionAskValue:
			profile.defaultAction = DefaultActionAsk
		case DefaultActionBlockValue:
			profile.defaultAction = DefaultActionBlock
		default:
			lastErr = fmt.Errorf(`default action "%s" invalid`, action)
		}
	}

	return lastErr
}

// New returns a new Profile.
// Optionally, you may supply custom configuration in the flat (key=value) form.
func New(profile *Profile) *Profile {
	// Create profile if none is given.
	if profile == nil {
		profile = &Profile{}
	}

	// Set default and internal values.
	profile.Created = time.Now().Unix()
	profile.savedInternally = true

	// Expand any given configuration.
	if profile.Config != nil {
		profile.Config = config.Expand(profile.Config)
	} else {
		profile.Config = make(map[string]interface{})
	}

	// Generate ID if none is given.
	if profile.ID == "" {
		if len(profile.Fingerprints) > 0 {
			// Derive from fingerprints.
			profile.ID = DeriveProfileID(profile.Fingerprints)
		} else {
			// Generate random ID as fallback.
			log.Warningf("profile: creating new profile without fingerprints to derive ID from")
			profile.ID = utils.RandomUUID("").String()
		}
	}

	// Make key from ID and source.
	profile.makeKey()

	// Prepare and parse initial profile config.
	profile.prepProfile()
	if err := profile.parseConfig(); err != nil {
		log.Errorf("profile: failed to parse new profile: %s", err)
	}

	return profile
}

// ScopedID returns the scoped ID (Source + ID) of the profile.
func (profile *Profile) ScopedID() string {
	return MakeScopedID(profile.Source, profile.ID)
}

// makeKey derives and sets the record Key from the profile attributes.
func (profile *Profile) makeKey() {
	profile.SetKey(MakeProfileKey(profile.Source, profile.ID))
}

// Save saves the profile to the database.
func (profile *Profile) Save() error {
	if profile.ID == "" {
		return errors.New("profile: tried to save profile without ID")
	}
	if profile.Source == "" {
		return fmt.Errorf("profile: profile %s does not specify a source", profile.ID)
	}

	return profileDB.Put(profile)
}

// delete deletes the profile from the database.
func (profile *Profile) delete() error {
	// Check if a key is set.
	if !profile.KeyIsSet() {
		return errors.New("key is not set")
	}

	// Delete from database.
	profile.Meta().Delete()
	err := profileDB.Put(profile)
	if err != nil {
		return err
	}

	// Post handling is done by the profile update feed.
	return nil
}

// MarkStillActive marks the profile as still active.
func (profile *Profile) MarkStillActive() {
	atomic.StoreInt64(profile.lastActive, time.Now().Unix())
}

// LastActive returns the unix timestamp when the profile was last marked as
// still active.
func (profile *Profile) LastActive() int64 {
	return atomic.LoadInt64(profile.lastActive)
}

// String returns a string representation of the Profile.
func (profile *Profile) String() string {
	return fmt.Sprintf("<%s %s/%s>", profile.Name, profile.Source, profile.ID)
}

// IsOutdated returns whether the this instance of the profile is marked as outdated.
func (profile *Profile) IsOutdated() bool {
	return profile.outdated.IsSet()
}

// GetFileAccessRules returns the per-profile file-access rule list as
// raw strings; parsing into PathRules lives in service/fileaccess.
// Requires the profile to be read-locked.
func (profile *Profile) GetFileAccessRules() []string {
	if profile.configPerspective == nil {
		return nil
	}
	list, ok := profile.configPerspective.GetAsStringArray(CfgOptionFileAccessRulesKey)
	if !ok {
		return nil
	}
	return list
}

// DefaultAction returns the profile's default action (DefaultActionNotSet,
// DefaultActionBlock, DefaultActionAsk, or DefaultActionPermit). Requires
// the profile to be read-locked.
func (profile *Profile) DefaultAction() uint8 {
	return profile.defaultAction
}

// AddFileAccessRule appends an entry (e.g. "+ /tmp/foo" or "- /etc/shadow")
// to the per-profile file-access rule list, saves the profile, and reloads
// the configuration. Duplicate entries are dropped.
func (profile *Profile) AddFileAccessRule(newEntry string) {
	if err := profile.PersistFileAccessRule(newEntry); err != nil {
		log.Warningf("profile: failed to save profile %s after add rule: %s", profile.ScopedID(), err)
	}
}

// PersistFileAccessRule prepends one canonical file-access rule and returns a
// storage failure to its caller. Filemaster's durable rule worker uses this
// instead of the fire-and-forget compatibility helper above.
func (profile *Profile) PersistFileAccessRule(newEntry string) error {
	return PersistCurrentFileAccessRule(profile.Source, profile.ID, newEntry, nil)
}

// PersistFileAccessRuleIfCurrent aborts before storage when the caller's
// profile authority changed while it prepared this update.
func (profile *Profile) PersistFileAccessRuleIfCurrent(newEntry string, current func() bool) error {
	return PersistCurrentFileAccessRule(profile.Source, profile.ID, newEntry, current)
}

// PersistCurrentFileAccessRule updates the current durable profile record, not
// a profile object retained by an earlier lookup. The profile write lock also
// serializes concurrent ordinary Profile.Save calls for this record.
func PersistCurrentFileAccessRule(source ProfileSource, id, newEntry string, current func() bool) error {
	if id == "" || source == "" {
		return errors.New("profile: file access rule requires a scoped profile ID")
	}
	if current != nil && !current() {
		return errors.New("profile: stale file access rule writer")
	}
	profile, err := getProfile(MakeScopedID(source, id))
	if err != nil {
		return err
	}
	profile.Lock()
	list, ok := profile.configPerspective.GetAsStringArray(CfgOptionFileAccessRulesKey)
	if !ok {
		list = []string{newEntry}
	} else {
		list = coalesceFileAccessRuleEntries(list, newEntry)
	}
	config.PutValueIntoHierarchicalConfig(profile.Config, CfgOptionFileAccessRulesKey, list)
	profile.dataParsed = false
	err = profile.parseConfig()
	profile.Unlock()
	if err != nil {
		return fmt.Errorf("profile: failed to parse file access rules: %w", err)
	}
	if current != nil && !current() {
		return errors.New("profile: stale file access rule writer")
	}
	return profileDB.Put(profile)
}

// addStringArrayEntry prepends an entry to a profile-stored StringArray
// option, persisting and reparsing the profile.
func (profile *Profile) addStringArrayEntry(cfgKey, newEntry string) error {
	return profile.persistStringArrayEntry(cfgKey, newEntry, nil)
}

func (profile *Profile) persistStringArrayEntry(cfgKey, newEntry string, current func() bool) error {
	// Lock the profile for editing.
	profile.Lock()

	// Get the current list and add the new entry.
	list, ok := profile.configPerspective.GetAsStringArray(cfgKey)
	if !ok {
		list = []string{newEntry}
	} else {
		list = coalesceFileAccessRuleEntries(list, newEntry)
	}

	// Save new value back to profile.
	config.PutValueIntoHierarchicalConfig(profile.Config, cfgKey, list)

	// Reload the profile manually so the newly added entry is parsed.
	profile.dataParsed = false
	err := profile.parseConfig()
	if err != nil {
		log.Errorf("profile: failed to parse %s config after adding rule: %s", profile, err)
	}
	profile.Unlock()
	if current != nil && !current() {
		return errors.New("profile: stale file access rule writer")
	}
	return profile.Save()
}

func coalesceFileAccessRuleEntries(list []string, newEntry string) []string {
	if sign, pattern, exact, valid := parseFileAccessRule(newEntry); valid {
		effectiveExact := false
		for _, entry := range list {
			entrySign, entryPattern, entryExact, entryValid := parseFileAccessRule(entry)
			if !entryValid || (entryExact && entryPattern != pattern) || (!entryExact && !fileAccessRuleMatches(entryPattern, pattern)) {
				continue
			}
			effectiveExact = entrySign == sign && entryExact == exact && entryPattern == pattern
			break
		}
		filtered := make([]string, 0, len(list)+1)
		keptExact := false
		for _, entry := range list {
			_, entryPattern, entryExact, entryValid := parseFileAccessRule(entry)
			if entryValid && entryExact == exact && entryPattern == pattern {
				if effectiveExact && !keptExact {
					keptExact = true
					filtered = append(filtered, entry)
				}
				continue
			}
			filtered = append(filtered, entry)
		}
		if !keptExact {
			filtered = append([]string{newEntry}, filtered...)
		}
		return filtered
	}
	return append([]string{newEntry}, list...)
}

func parseFileAccessRule(entry string) (sign byte, pattern string, exact bool, ok bool) {
	if len(entry) < 3 || entry[1] != ' ' || (entry[0] != '+' && entry[0] != '-') {
		return 0, "", false, false
	}
	payload := entry[2:]
	if strings.HasPrefix(payload, "@") {
		literal, err := strconv.Unquote(payload[1:])
		if err != nil {
			return 0, "", false, false
		}
		pattern = filepath.Clean(literal)
		return entry[0], pattern, true, filepath.IsAbs(pattern)
	}
	pattern = filepath.Clean(strings.TrimSpace(payload))
	return entry[0], pattern, false, filepath.IsAbs(pattern)
}

func fileAccessRuleMatches(rulePattern, path string) bool {
	if strings.HasSuffix(rulePattern, "/**") {
		prefix := filepath.Clean(strings.TrimSuffix(rulePattern, "/**"))
		return path == prefix || strings.HasPrefix(path, prefix+string(filepath.Separator))
	}
	matched, err := filepath.Match(rulePattern, path)
	return err == nil && matched
}

// LayeredProfile returns the layered profile associated with this profile.
func (profile *Profile) LayeredProfile() *LayeredProfile {
	profile.Lock()
	defer profile.Unlock()

	return profile.layeredProfile
}

// EnsureProfile ensures that the given record is a *Profile, and returns it.
func EnsureProfile(r record.Record) (*Profile, error) {
	// unwrap
	if r.IsWrapped() {
		// only allocate a new struct, if we need it
		newProfile := &Profile{}
		err := record.Unwrap(r, newProfile)
		if err != nil {
			return nil, err
		}
		return newProfile, nil
	}

	// or adjust type
	newProfile, ok := r.(*Profile)
	if !ok {
		return nil, fmt.Errorf("record not of type *Profile, but %T", r)
	}
	return newProfile, nil
}

func (profile *Profile) transactionalCopy() (*Profile, error) {
	data, err := json.Marshal(profile)
	if err != nil {
		return nil, fmt.Errorf("marshal profile transaction candidate: %w", err)
	}
	candidate := &Profile{}
	if err := json.Unmarshal(data, candidate); err != nil {
		return nil, fmt.Errorf("unmarshal profile transaction candidate: %w", err)
	}
	candidate.SetKey(profile.Key())
	if meta := profile.Meta(); meta != nil {
		candidate.SetMeta(meta.Duplicate())
	}
	candidate.revisionCommitTarget = profile
	return candidate, nil
}

// CommitRecordTransaction publishes a revision only after Controller.Put has
// committed the detached candidate. It intentionally does nothing on every
// validation or storage failure path.
func (profile *Profile) CommitRecordTransaction() {
	if profile.revisionCommitTarget == nil {
		return
	}
	target := profile.revisionCommitTarget
	target.Revision = profile.Revision
	target.PresentationPath = profile.PresentationPath
	target.configPerspective = profile.configPerspective
	target.dataParsed = profile.dataParsed
	target.defaultAction = profile.defaultAction
}

// updateMetadata updates meta data fields on the profile and returns whether
// the profile was changed.
func (profile *Profile) updateMetadata(binaryPath string) (changed bool) {
	// Check if this is a local profile, else warn and return.
	if profile.Source != SourceLocal {
		log.Warningf("tried to update metadata for non-local profile %s", profile.ScopedID())
		return false
	}

	// Set PresentationPath if unset.
	if profile.PresentationPath == "" && binaryPath != "" {
		profile.PresentationPath = binaryPath
		changed = true
	}

	// Migrate LinkedPath to PresentationPath.
	// TODO: Remove in v1.5
	if profile.PresentationPath == "" && profile.LinkedPath != "" {
		profile.PresentationPath = profile.LinkedPath
		changed = true
	}

	// Set Name if unset.
	if profile.Name == "" && profile.PresentationPath != "" {
		// Generate a default profile name from path.
		profile.Name = binmeta.GenerateBinaryNameFromPath(profile.PresentationPath)
		changed = true
	}

	// Migrate to Fingerprints.
	// TODO: Remove in v1.5
	if len(profile.Fingerprints) == 0 && profile.LinkedPath != "" {
		profile.Fingerprints = []Fingerprint{
			{
				Type:      FingerprintTypePathID,
				Operation: FingerprintOperationEqualsID,
				Value:     profile.LinkedPath,
			},
		}
		changed = true
	}

	// UI Backward Compatibility:
	// Fill LinkedPath with PresentationPath
	// TODO: Remove in v1.1
	if profile.LinkedPath == "" && profile.PresentationPath != "" {
		profile.LinkedPath = profile.PresentationPath
		changed = true
	}

	return changed
}

// updateMetadataFromSystem updates the profile metadata with data from the
// operating system and saves it afterwards.
func (profile *Profile) updateMetadataFromSystem(ctx context.Context, md MatchingData) error {
	var changed bool

	// This function is only valid for local profiles.
	if profile.Source != SourceLocal || profile.PresentationPath == "" {
		return fmt.Errorf("tried to update metadata for non-local or non-path profile %s", profile.ScopedID())
	}

	// Get home from ENV.
	var home string
	if env := md.Env(); env != nil {
		home = env["HOME"]
	}

	// Get binary icon and name.
	newIcon, newName, err := binmeta.GetIconAndName(ctx, profile.PresentationPath, home)
	switch {
	case err == nil:
		// Continue
	case errors.Is(err, binmeta.ErrIconIgnored):
		newIcon = nil
		// Continue
	default:
		log.Warningf("profile: failed to get binary icon/name for %s: %s", profile.PresentationPath, err)
	}

	// Apply new data to profile.
	func() {
		// Lock profile for applying metadata.
		profile.Lock()
		defer profile.Unlock()

		// Apply new name if it changed.
		if newName != "" && profile.Name != newName {
			profile.Name = newName
			changed = true
		}

		// Apply new icon if found.
		if newIcon != nil && !profile.iconExists(newIcon) {
			if len(profile.Icons) == 0 {
				profile.Icons = []binmeta.Icon{*newIcon}
			} else {
				profile.Icons = append(profile.Icons, *newIcon)
				profile.Icons = binmeta.SortAndCompactIcons(profile.Icons)
			}
			changed = true
		}
	}()

	// If anything changed, save the profile.
	// profile.Lock must not be held!
	if changed {
		err := profile.Save()
		if err != nil {
			log.Warningf("profile: failed to save %s after metadata update: %s", profile.ScopedID(), err)
		}
	}

	return nil
}

// Checks if the given icon already assigned to the profile.
func (profile *Profile) iconExists(newIcon *binmeta.Icon) bool {
	for _, icon := range profile.Icons {
		if icon.Value == newIcon.Value && icon.Type == newIcon.Type && icon.Source == newIcon.Source {
			return true
		}
	}
	return false
}
