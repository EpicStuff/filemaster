//go:build linux

package fileaccess

import (
	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/mgr"
)

type structuralBackend = bpflsm.Enforcer

// startStructuralEnforcement attaches the BPF LSM backend in the configured
// mode and follows live profile/config/mode changes. It runs only in the
// daemon, which is the instance that carries configuration.
func (fa *FileAccess) startStructuralEnforcement() {
	cfg, ok := fa.instance.(configAccessor)
	if !ok {
		return
	}
	fa.structural = bpflsm.NewEnforcer()
	apply := func() {
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
		}
	}
	apply()
	fa.registerStructuralProfilePublisher(apply)
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
	if fa.structural != nil {
		fa.structural.Close()
	}
}
