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

	source  Source
	handler Handler
}

// Manager returns the module manager.
func (fa *FileAccess) Manager() *mgr.Manager {
	return fa.mgr
}

// Start starts the module: build the platform source and run it under a
// worker. The phase-1 default handler logs and allows every event.
func (fa *FileAccess) Start() error {
	src, err := newPlatformSource(fa.mgr)
	if err != nil {
		return err
	}
	fa.source = src

	fa.mgr.Go("file-access source", func(w *mgr.WorkerCtx) error {
		return fa.source.Run(w.Ctx(), fa.handler)
	})
	return nil
}

// Stop stops the module by closing the source. The Run goroutine
// unwinds via either ctx.Done (from the worker manager) or EBADF
// (from the closed fd), whichever lands first.
func (fa *FileAccess) Stop() error {
	if fa.source == nil {
		return nil
	}
	err := fa.source.Close()
	fa.source = nil
	return err
}

// SetHandler swaps the verdict handler. Intended for tests and for the
// phase-3 wiring where the profile/prompt path takes over from allowAll.
// Must be called before Start.
func (fa *FileAccess) SetHandler(h Handler) {
	fa.handler = h
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
		handler:  allowAll,
	}
	return module, nil
}

type instance interface{}
