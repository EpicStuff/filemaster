//go:build linux

package fileaccess

import (
	"errors"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/mgr"
	"github.com/safing/portmaster/service/process"
)

type structuralBackend = bpflsm.Enforcer

// structuralApplyMu serializes compile-and-publish, so a slower compile of an
// older mount table or policy can never be published after a newer one.
var structuralApplyMu sync.Mutex

// startStructuralEnforcement attaches the BPF LSM backend in the configured
// mode and follows live profile/config/mode changes. It runs only in the
// daemon, which is the instance that carries configuration.
func (fa *FileAccess) startStructuralEnforcement() {
	cfg, ok := fa.instance.(configAccessor)
	if !ok {
		return
	}
	var apply func()
	fa.labeller = newStructuralLabeller(fa, func() { apply() })
	process.SetIdentityCaptureProvider(fa.labeller.capture)
	fa.structural = bpflsm.NewEnforcerWithOptions(bpflsm.Options{
		Labelling: true,
		OnRecord:  fa.labeller.enqueue,
	})
	fa.labeller.enf = fa.structural
	apply = func() {
		structuralApplyMu.Lock()
		defer structuralApplyMu.Unlock()
		fa.structural.SetLabelWait(cfgOptionLabelWait())
		mode := bpflsm.Mode(cfgOptionStructural())
		if mode == bpflsm.ModeOff {
			if err := fa.structural.SetMode(mode); err != nil {
				fa.mgr.Warn("fileaccess: structural enforcement is not active", "mode", mode, "err", err)
			}
			return
		}
		table, warnings, err := fa.compileStructuralTable()
		fa.structural.SetCompileWarnings(warnings)
		if err != nil {
			fa.structural.SetPublishError(err)
			fa.mgr.Warn("fileaccess: failed to compile structural decision table", "mode", mode, "err", err)
			return
		}
		if err := fa.structural.SetModeWithTable(mode, table); err != nil {
			fa.mgr.Warn("fileaccess: structural enforcement is not active", "mode", mode, "err", err)
			return
		}
		fa.labeller.markPublished()
		// A new generation (startup or a live off -> on switch) has no records for
		// processes that predate it; seed and resolve them from /proc.
		if generation := fa.structural.Status().Generation; generation != "" && generation != fa.labeller.generation {
			fa.labeller.generation = generation
			fa.mgr.Go("file-access structural label seed", func(w *mgr.WorkerCtx) error {
				fa.labeller.seedRunning(w.Ctx())
				return nil
			})
		}
	}
	apply()
	fa.mgr.Go("file-access structural label resolver", func(w *mgr.WorkerCtx) error {
		fa.labeller.run(w)
		return nil
	})
	fa.registerStructuralProfilePublisher(apply)
	fa.mgr.Go("file-access structural mount watch", func(w *mgr.WorkerCtx) error {
		fa.watchStructuralMounts(w, apply)
		return nil
	})
	cfg.Config().EventConfigChange.AddCallback(
		"fileaccess structural enforcement mode",
		func(_ *mgr.WorkerCtx, _ struct{}) (bool, error) {
			if fa.lifecycle.IsRunning() {
				apply()
			}
			return false, nil
		},
	)
}

func (fa *FileAccess) closeStructuralEnforcement() {
	process.SetIdentityCaptureProvider(nil)
	if fa.labeller != nil {
		fa.labeller.stop()
	}
	if fa.structural != nil {
		fa.structural.Close()
	}
}

// watchStructuralMounts re-publishes when this namespace's mount table
// changes: mount roots are walk stops, and a new one is unregistered until the
// next publish. /proc/self/mountinfo reports a change as POLLPRI.
func (fa *FileAccess) watchStructuralMounts(w *mgr.WorkerCtx, apply func()) {
	fd, err := unix.Open("/proc/self/mountinfo", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		fa.mgr.Warn("fileaccess: cannot watch mounts for structural re-publish", "err", err)
		return
	}
	defer unix.Close(fd)
	for w.Ctx().Err() == nil {
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLPRI}}
		if _, err := unix.Poll(poll, 1000); err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			fa.mgr.Warn("fileaccess: structural mount watch stopped", "err", err)
			return
		}
		if poll[0].Revents&unix.POLLPRI == 0 || w.Ctx().Err() != nil {
			continue
		}
		if fa.lifecycle != nil && fa.lifecycle.IsRunning() && bpflsm.Mode(cfgOptionStructural()) != bpflsm.ModeOff {
			apply()
		}
	}
}
