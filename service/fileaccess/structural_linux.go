//go:build linux

package fileaccess

import (
	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/mgr"
)

type structuralBackend = bpflsm.Enforcer

// startStructuralEnforcement attaches the BPF LSM backend in the configured
// mode and follows live mode changes. It runs only in the daemon, which is the
// instance that carries configuration.
func (fa *FileAccess) startStructuralEnforcement() {
	cfg, ok := fa.instance.(configAccessor)
	if !ok {
		return
	}
	fa.structural = bpflsm.NewEnforcer()
	apply := func() {
		mode := bpflsm.Mode(cfgOptionStructural())
		if err := fa.structural.SetMode(mode); err != nil {
			fa.mgr.Warn("fileaccess: structural enforcement is not active", "mode", mode, "err", err)
		}
	}
	apply()
	cfg.Config().EventConfigChange.AddCallback(
		"fileaccess structural enforcement mode",
		func(_ *mgr.WorkerCtx, _ struct{}) (bool, error) {
			if fa.lifecycle.IsRunning() && bpflsm.Mode(cfgOptionStructural()) != fa.structural.Status().Mode {
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
