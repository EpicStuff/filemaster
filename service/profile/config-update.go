package profile

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/safing/portmaster/base/database"
	"github.com/safing/portmaster/service/mgr"
)

var (
	cfgLock sync.RWMutex

	cfgDefaultAction uint8
)

func registerGlobalConfigProfileUpdater() error {
	module.instance.Config().EventConfigChange.AddCallback("update global config profile", func(wc *mgr.WorkerCtx, s struct{}) (cancel bool, err error) {
		return false, updateGlobalConfigProfile(wc.Ctx())
	})

	return nil
}

const globalConfigProfileErrorID = "profile:global-profile-error"

// updateGlobalConfigProfile is called on every config change. It maps
// the global config option values into a "global-config" Profile so
// LayeredProfile lookups can fall back to them consistently. The
// network-rule fields are gone post-strip; only DefaultAction remains
// here for now.
// prepareGlobalConfigProfileForSave preserves the durable revision of the
// generated global configuration profile so it can replace an existing record.
func prepareGlobalConfigProfileForSave(profile *Profile) error {
	existing, err := getProfile(MakeScopedID(SourceSpecial, profile.ID))
	if err == nil {
		profile.Revision = existing.Revision
		return nil
	}
	if errors.Is(err, database.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("load existing global config profile: %w", err)
}

func updateGlobalConfigProfile(_ context.Context) error {
	cfgLock.Lock()
	defer cfgLock.Unlock()

	var lastErr error

	action := cfgOptionDefaultAction()
	switch action {
	case DefaultActionPermitValue:
		cfgDefaultAction = DefaultActionPermit
	case DefaultActionAskValue:
		cfgDefaultAction = DefaultActionAsk
	case DefaultActionBlockValue:
		cfgDefaultAction = DefaultActionBlock
	default:
		lastErr = fmt.Errorf(`default action "%s" invalid`, action)
		cfgDefaultAction = DefaultActionBlock // safe-by-default
	}

	// Build config.
	newConfig := make(map[string]interface{})
	for key, value := range cfgStringOptions {
		newConfig[key] = value()
	}
	for key, value := range cfgStringArrayOptions {
		newConfig[key] = value()
	}
	for key, value := range cfgIntOptions {
		newConfig[key] = value()
	}
	for key, value := range cfgBoolOptions {
		newConfig[key] = value()
	}

	// Build global profile for reference.
	profile := New(&Profile{
		ID:       "global-config",
		Source:   SourceSpecial,
		Name:     "Global Configuration",
		Config:   newConfig,
		Internal: true,
	})

	if err := prepareGlobalConfigProfileForSave(profile); err != nil {
		lastErr = err
	}

	if lastErr == nil {
		if err := profile.Save(); err != nil {
			lastErr = err
		}
	}

	if lastErr == nil {
		module.states.Remove(globalConfigProfileErrorID)
	} else {
		_ = module.mgr.Delay("retry updating global config profile", 15*time.Second,
			func(w *mgr.WorkerCtx) error {
				return updateGlobalConfigProfile(w.Ctx())
			})

		module.states.Add(mgr.State{
			ID:      globalConfigProfileErrorID,
			Name:    "Internal Settings Failure",
			Message: fmt.Sprintf("Some global settings might not be applied correctly. You can try restarting the daemon to resolve this problem. Error: %s", lastErr),
			Type:    mgr.StateTypeWarning,
		})
	}

	return lastErr
}
