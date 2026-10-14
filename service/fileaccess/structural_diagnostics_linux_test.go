package fileaccess

import (
	"testing"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
)

func TestBPFLSMUnavailableSeverityFollowsMode(t *testing.T) {
	for mode, want := range map[bpflsm.Mode]string{
		bpflsm.ModeAudit:   "warning",
		bpflsm.ModeEnforce: "error",
	} {
		var diagnostics FileAccessDiagnostics
		diagnostics.Structural = bpflsm.Status{Mode: mode, State: bpflsm.StateUnavailable}
		var got string
		for _, warning := range diagnosticsWarnings(diagnostics) {
			if warning.ID == "bpf-lsm-unavailable" {
				got = warning.Severity
			}
		}
		if got != want {
			t.Errorf("mode %s: severity %q, want %q", mode, got, want)
		}
	}
}
