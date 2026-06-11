package process

import (
	"context"
	"errors"

	"github.com/safing/portmaster/base/api"
	"github.com/safing/portmaster/base/log"
)

// GetProcessWithProfile returns the process, including the profile.
// Always returns valid data.
// Errors are logged and returned for information or special handling purposes.
func GetProcessWithProfile(ctx context.Context, pid int) (process *Process, err error) {
	if !enableProcessDetection() {
		log.Tracer(ctx).Tracef("process: process detection disabled")
		return GetUnidentifiedProcess(ctx), nil
	}

	process, err = GetOrFindProcess(ctx, pid)
	if err != nil {
		log.Tracer(ctx).Debugf("process: failed to find process with PID: %s", err)
		return GetUnidentifiedProcess(ctx), err
	}

	err = process.FindProcessGroupLeader(ctx)
	if err != nil {
		log.Warningf("process: failed to get process group leader for %s: %s", process, err)
	}

	changed, err := process.GetProfile(ctx)
	if err != nil {
		log.Tracer(ctx).Errorf("process: failed to get profile for process %s: %s", process, err)
	}

	if changed {
		process.Save()
	}

	return process, nil
}

// GetProcessByRequestOrigin is a stub left in place for the API layer.
// The previous network-based implementation used socket-table lookups to map
// the connecting peer back to a PID; that path no longer exists in this fork.
func GetProcessByRequestOrigin(ar *api.Request) (*Process, error) {
	return nil, errors.New("GetProcessByRequestOrigin: not implemented in this fork")
}
