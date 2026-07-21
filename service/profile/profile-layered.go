package profile

import (
	"sync"
	"sync/atomic"

	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/base/database/record"
	"github.com/safing/portmaster/base/log"
	"github.com/safing/portmaster/base/runtime"
)

// LayeredProfile combines multiple Profiles.
type LayeredProfile struct {
	record.Base
	sync.RWMutex

	localProfile *Profile
	layers       []*Profile

	LayerIDs           []string
	RevisionCounter    uint64
	globalValidityFlag *config.ValidityFlag

	securityLevel *uint32

	// These functions give layered access to configuration options and require
	// the layered profile to be read locked.
	//
	// The network-flavored options (Block*/Filter*/UseSPN/etc.) were removed
	// during the filemaster strip; only profile-wide settings that still make
	// sense for the file-access prompt loop remain.
}

// NewLayeredProfile returns a new layered profile based on the given local profile.
func NewLayeredProfile(localProfile *Profile) *LayeredProfile {
	var securityLevelVal uint32

	lp := &LayeredProfile{
		localProfile:       localProfile,
		layers:             make([]*Profile, 0, 1),
		LayerIDs:           make([]string, 0, 1),
		globalValidityFlag: config.NewValidityFlag(),
		RevisionCounter:    1,
		securityLevel:      &securityLevelVal,
	}

	lp.LayerIDs = append(lp.LayerIDs, localProfile.ScopedID())
	lp.layers = append(lp.layers, localProfile)

	// TODO: Load additional profiles.

	lp.CreateMeta()
	lp.SetKey(runtime.DefaultRegistry.DatabaseName() + ":" + revisionProviderPrefix + localProfile.ScopedID())

	// Inform database subscribers about the new layered profile.
	lp.Lock()
	defer lp.Unlock()

	pushLayeredProfile(lp)

	return lp
}

// LockForUsage locks the layered profile, including all layers individually.
func (lp *LayeredProfile) LockForUsage() {
	lp.RLock()
	for _, layer := range lp.layers {
		layer.RLock()
	}
}

// UnlockForUsage unlocks the layered profile, including all layers individually.
func (lp *LayeredProfile) UnlockForUsage() {
	lp.RUnlock()
	for _, layer := range lp.layers {
		layer.RUnlock()
	}
}

// LocalProfile returns the local profile associated with this layered profile.
func (lp *LayeredProfile) LocalProfile() *Profile {
	if lp == nil {
		return nil
	}

	lp.RLock()
	defer lp.RUnlock()

	return lp.localProfile
}

// LocalProfileWithoutLocking returns the local profile associated with this
// layered profile, but without locking the layered profile.
// This method my only be used when the caller already has a lock on the layered profile.
func (lp *LayeredProfile) LocalProfileWithoutLocking() *Profile {
	if lp == nil {
		return nil
	}

	return lp.localProfile
}

// increaseRevisionCounter increases the revision counter and pushes the
// layered profile to listeners.
func (lp *LayeredProfile) increaseRevisionCounter(lock bool) (revisionCounter uint64) { //nolint:unparam // This is documentation.
	if lp == nil {
		return 0
	}

	if lock {
		lp.Lock()
		defer lp.Unlock()
	}

	// Increase the revision counter.
	lp.RevisionCounter++
	// Push the increased counter to the UI.
	pushLayeredProfile(lp)

	return lp.RevisionCounter
}

// RevisionCnt returns the current profile revision counter.
func (lp *LayeredProfile) RevisionCnt() (revisionCounter uint64) {
	if lp == nil {
		return 0
	}

	lp.RLock()
	defer lp.RUnlock()

	return lp.RevisionCounter
}

// MarkStillActive marks all the layers as still active.
func (lp *LayeredProfile) MarkStillActive() {
	if lp == nil {
		return
	}

	lp.RLock()
	defer lp.RUnlock()

	for _, layer := range lp.layers {
		layer.MarkStillActive()
	}
}

// NeedsUpdate checks for outdated profiles.
func (lp *LayeredProfile) NeedsUpdate() (outdated bool) {
	lp.RLock()
	defer lp.RUnlock()

	// Check global config state.
	if !lp.globalValidityFlag.IsValid() {
		return true
	}

	// Check config in layers.
	for _, layer := range lp.layers {
		if layer.outdated.IsSet() {
			return true
		}
	}

	return false
}

// Update checks for and replaces any outdated profiles.
func (lp *LayeredProfile) Update(md MatchingData, createProfileCallback func() *Profile) (revisionCounter uint64) {
	lp.Lock()
	defer lp.Unlock()

	var changed bool
	for i, layer := range lp.layers {
		if layer.outdated.IsSet() {
			// Check for unsupported sources.
			if layer.Source != SourceLocal {
				log.Warningf("profile: updating profiles outside of local source is not supported: %s", layer.ScopedID())
				layer.outdated.UnSet()
				continue
			}

			// Update layer.
			changed = true
			newLayer, err := GetLocalProfile(layer.ID, md, createProfileCallback)
			if err != nil {
				log.Errorf("profiles: failed to update profile %s: %s", layer.ScopedID(), err)
			} else {
				lp.layers[i] = newLayer
			}

			// Update local profile reference.
			if i == 0 {
				lp.localProfile = newLayer
			}
		}
	}
	if !lp.globalValidityFlag.IsValid() {
		changed = true
	}

	if changed {
		// get global config validity flag
		lp.globalValidityFlag.Refresh()

		// bump revision counter
		lp.increaseRevisionCounter(false)
	}

	return lp.RevisionCounter
}

// SecurityLevel returns the highest security level of all layered profiles. This function is atomic and does not require any locking.
func (lp *LayeredProfile) SecurityLevel() uint8 {
	return uint8(atomic.LoadUint32(lp.securityLevel))
}

// DefaultAction returns the active default action ID. This functions requires the layered profile to be read locked.
func (lp *LayeredProfile) DefaultAction() uint8 {
	for _, layer := range lp.layers {
		if layer.defaultAction > 0 {
			return layer.defaultAction
		}
	}

	cfgLock.RLock()
	defer cfgLock.RUnlock()
	return cfgDefaultAction
}

// EffectiveDefaultAction returns the profile's per-app default action, falling
// back to the current global configuration when the local profile leaves it
// unset. It acquires the layered and profile locks required by DefaultAction.
func (profile *Profile) EffectiveDefaultAction() uint8 {
	layeredProfile := profile.LayeredProfile()
	if layeredProfile == nil {
		profile.RLock()
		defer profile.RUnlock()
		return profile.DefaultAction()
	}

	layeredProfile.LockForUsage()
	defer layeredProfile.UnlockForUsage()
	return layeredProfile.DefaultAction()
}

// GetProfileSource returns the database key of the first profile in the
// layers that has the given configuration key set. If it returns an empty
// string, the global profile can be assumed to have been effective.
func (lp *LayeredProfile) GetProfileSource(configKey string) string {
	for _, layer := range lp.layers {
		if layer.configPerspective.Has(configKey) {
			return layer.Key()
		}
	}

	// Global Profile
	return ""
}
