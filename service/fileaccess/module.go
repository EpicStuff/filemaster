// Package fileaccess intercepts file-access syscalls and (eventually)
// turns them into per-app prompts. Phase 1 is a hard-coded scaffold
// proving the kernel plumbing works; rules and prompts come later.
package fileaccess

import (
	"errors"
	"sync/atomic"

	"github.com/safing/portmaster/service/mgr"
)

// FileAccess is the file-access interception module.
type FileAccess struct {
	mgr      *mgr.Manager
	instance instance

	fan *fanotifyHandle
}

// Manager returns the module manager.
func (fa *FileAccess) Manager() *mgr.Manager {
	return fa.mgr
}

// Start starts the module.
func (fa *FileAccess) Start() error {
	return fa.startFanotify()
}

// Stop stops the module.
func (fa *FileAccess) Stop() error {
	return fa.stopFanotify()
}

var (
	module     *FileAccess
	shimLoaded atomic.Bool
)

// New returns a new FileAccess module.
func New(instance instance) (*FileAccess, error) {
	if !shimLoaded.CompareAndSwap(false, true) {
		return nil, errors.New("only one instance allowed")
	}
	m := mgr.New("FileAccess")
	module = &FileAccess{
		mgr:      m,
		instance: instance,
	}
	return module, nil
}

type instance interface{}
