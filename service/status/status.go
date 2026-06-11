package status

import (
	"slices"
	"strings"
	"sync"

	"github.com/safing/portmaster/base/database/record"
	"github.com/safing/portmaster/base/runtime"
	"github.com/safing/portmaster/service/mgr"
)

// SystemStatusRecord describes the overall status of filemaster.
// It's a read-only record exposed via runtime:system/status.
//
// The upstream record carried OnlineStatus and CaptivePortal fields fed by
// the netenv package; both are gone in this fork.
type SystemStatusRecord struct {
	record.Base
	sync.Mutex

	Modules    []mgr.StateUpdate
	WorstState struct {
		Module string
		mgr.State
	}
}

func (s *Status) handleModuleStatusUpdate(_ *mgr.WorkerCtx, update mgr.StateUpdate) (cancel bool, err error) {
	s.statesLock.Lock()
	defer s.statesLock.Unlock()

	s.states[update.Module] = update
	s.deriveNotificationsFromStateUpdate(update)
	s.triggerPublishStatus()

	return false, nil
}

func (s *Status) triggerPublishStatus() {
	select {
	case s.triggerUpdate <- struct{}{}:
	default:
	}
}

func (s *Status) statusPublisher(w *mgr.WorkerCtx) error {
	for {
		select {
		case <-w.Done():
			return nil
		case <-s.triggerUpdate:
			s.publishSystemStatus()
		}
	}
}

func (s *Status) setupRuntimeProvider() (err error) {
	// register the system status getter
	statusProvider := runtime.SimpleValueGetterFunc(func(_ string) ([]record.Record, error) {
		return []record.Record{s.buildSystemStatus()}, nil
	})
	s.publishUpdate, err = runtime.Register("system/status", statusProvider)
	if err != nil {
		return err
	}

	return nil
}

// buildSystemStatus build a new system status record.
func (s *Status) buildSystemStatus() *SystemStatusRecord {
	s.statesLock.Lock()
	defer s.statesLock.Unlock()

	status := &SystemStatusRecord{
		Modules: make([]mgr.StateUpdate, 0, len(s.states)),
	}
	for _, newStateUpdate := range s.states {
		// Deep copy state.
		newStateUpdate.States = append([]mgr.State(nil), newStateUpdate.States...)
		status.Modules = append(status.Modules, newStateUpdate)

		// Check if state is worst so far.
		for _, state := range newStateUpdate.States {
			if state.Type.Severity() > status.WorstState.Type.Severity() {
				s.mgr.Error("new worst state", "state", state)
				status.WorstState.State = state
				status.WorstState.Module = newStateUpdate.Module
			}
		}
	}
	slices.SortFunc(status.Modules, func(a, b mgr.StateUpdate) int {
		return strings.Compare(a.Module, b.Module)
	})

	status.CreateMeta()
	status.SetKey("runtime:system/status")
	return status
}

// publishSystemStatus pushes a new system status via
// the runtime database.
func (s *Status) publishSystemStatus() {
	if s.publishUpdate == nil {
		return
	}

	record := s.buildSystemStatus()
	record.Lock()
	defer record.Unlock()

	s.publishUpdate(record)
}
