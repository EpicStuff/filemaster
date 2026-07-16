package profile

import (
	"errors"
	"fmt"
	"strings"

	"github.com/safing/portmaster/base/config"
	"github.com/safing/portmaster/base/database"
	"github.com/safing/portmaster/base/database/query"
	"github.com/safing/portmaster/base/database/record"
	"github.com/safing/portmaster/base/log"
	"github.com/safing/portmaster/service/mgr"
)

// Database paths:
// core:profiles/<scope>/<id>
// cache:profiles/index/<identifier>/<value>

// ProfilesDBPath is the base database path for profiles.
const ProfilesDBPath = "core:profiles/"

var profileDB = database.NewInterface(&database.Options{
	Local:    true,
	Internal: true,
})

// ErrProfileRevisionConflict means a profile write was based on a stale
// durable record. Callers must reload before applying their change again.
var ErrProfileRevisionConflict = errors.New("profile revision conflict")

// MakeScopedID returns a scoped profile ID.
func MakeScopedID(source ProfileSource, id string) string {
	return string(source) + "/" + id
}

// MakeProfileKey returns a profile key.
func MakeProfileKey(source ProfileSource, id string) string {
	return ProfilesDBPath + string(source) + "/" + id
}

func registerValidationDBHook() (err error) {
	_, err = database.RegisterHook(query.New(ProfilesDBPath), &databaseHook{})
	return
}

func startProfileUpdateChecker() error {
	module.mgr.Go("update active profiles", func(ctx *mgr.WorkerCtx) (err error) {
		profilesSub, err := profileDB.Subscribe(query.New(ProfilesDBPath))
		if err != nil {
			return err
		}
		defer func() {
			err := profilesSub.Cancel()
			if err != nil {
				log.Warningf("profile: failed to cancel subscription for updating active profiles: %s", err)
			}
		}()

	profileFeed:
		for {
			select {
			case r := <-profilesSub.Feed:
				// Check if subscription was canceled.
				if r == nil {
					return errors.New("subscription canceled")
				}

				scopedID := strings.TrimPrefix(r.Key(), ProfilesDBPath)

				// Check if fingerprints changed such that the profile ID needs to be
				// re-derived. This must run before the activeProfile lookup so that it
				// also applies when the app is not currently running.
				if !r.Meta().IsDeleted() {
					if receivedProfile, parseErr := EnsureProfile(r); parseErr == nil && !receivedProfile.savedInternally {
						if len(receivedProfile.Fingerprints) > 0 &&
							DeriveProfileID(receivedProfile.Fingerprints) != receivedProfile.ID {
							if renameErr := migrateProfileOnFingerprintChange(receivedProfile); renameErr != nil {
								log.Errorf("profile: failed to rename profile %s after fingerprint change: %s", scopedID, renameErr)
							}
							// The rename saves a new profile and deletes the old one, each of
							// which produces its own feed event. Skip further processing here.
							continue profileFeed
						}
					}
				}

				// Get active profile.
				activeProfile := getActiveProfile(scopedID)
				if activeProfile == nil {
					// Check if profile is being deleted.
					if r.Meta().IsDeleted() {
						meta.MarkDeleted(scopedID)
					}

					// Don't do any additional actions if the profile is not active.
					continue profileFeed
				}

				// Always increase the revision counter of the layer profile.
				// This marks previous connections in the UI as decided with outdated settings.
				if activeProfile.layeredProfile != nil {
					activeProfile.layeredProfile.increaseRevisionCounter(true)
				}

				// Always mark as outdated if the record is being deleted.
				if r.Meta().IsDeleted() {
					activeProfile.outdated.Set()

					meta.MarkDeleted(scopedID)
					module.EventDelete.Submit(scopedID)
					continue
				}

				// If the profile is saved externally (eg. via the API), have the
				// next one to use it reload the profile from the database.
				receivedProfile, err := EnsureProfile(r)
				if err != nil || !receivedProfile.savedInternally {
					activeProfile.outdated.Set()
					module.EventConfigChange.Submit(scopedID)
				}
			case <-ctx.Done():
				return nil
			}
		}
	})

	return nil
}

type databaseHook struct {
	database.HookBase
}

// UsesPrePut implements the Hook interface and returns true.
func (h *databaseHook) UsesPrePut() bool {
	return true
}

// PrePut implements the Hook interface.
func (h *databaseHook) PrePut(r record.Record) (record.Record, error) {
	// Do not intervene with metadata key.
	if r.Key() == profilesMetadataKey {
		return r, nil
	}

	// convert
	profile, err := EnsureProfile(r)
	if err != nil {
		return nil, err
	}
	// Controller.Put holds this record's transaction lock while hooks run and
	// storage commits. Compare against the durable profile revision here so all
	// interfaces, including generic database/API writes, reject stale objects.
	current, currentErr := getProfile(MakeScopedID(profile.Source, profile.ID))
	if currentErr != nil {
		if !errors.Is(currentErr, database.ErrNotFound) {
			return nil, currentErr
		}
		if profile.Revision != 0 {
			return nil, fmt.Errorf("%w: profile %s expected revision %d, record is absent", ErrProfileRevisionConflict, profile.ScopedID(), profile.Revision)
		}
		profile.Revision = 1
	} else {
		if profile.Revision != current.Revision {
			return nil, fmt.Errorf("%w: profile %s expected revision %d, current revision %d", ErrProfileRevisionConflict, profile.ScopedID(), profile.Revision, current.Revision)
		}
		profile.Revision = current.Revision + 1
	}

	// clean config
	config.CleanHierarchicalConfig(profile.Config)

	// prepare profile
	profile.prepProfile()

	// Validate fingerprints: reject saves with unparseable fingerprints (e.g. bad regex)
	// to prevent a profile from being saved in a state where it can never match.
	_, fpErr := ParseFingerprints(profile.Fingerprints, profile.LinkedPath)
	if fpErr != nil {
		return nil, fmt.Errorf("invalid fingerprint: %w", fpErr)
	}

	// parse config
	err = profile.parseConfig()
	if err != nil {
		// error here, warning when loading
		return nil, err
	}

	return profile, nil
}
