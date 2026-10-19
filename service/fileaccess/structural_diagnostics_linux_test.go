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

func TestStructuralUndecidedAndOverflowWarnings(t *testing.T) {
	var diagnostics FileAccessDiagnostics
	diagnostics.Structural = bpflsm.Status{
		Mode:  bpflsm.ModeEnforce,
		State: bpflsm.StateActive,
		Undecided: []bpflsm.UndecidedCount{
			{Reason: bpflsm.ReasonUnreadable, Hook: "inode_unlink", Count: 2},
			{Reason: bpflsm.ReasonDepth, Hook: "inode_rename", Count: 1},
		},
		CompileWarnings: []bpflsm.CompileWarning{{ID: "context-rule-overflow", Patterns: []string{"/a"}}},
	}
	got := make(map[string]DegradedWarning)
	for _, warning := range diagnosticsWarnings(diagnostics) {
		got[warning.ID] = warning
	}
	for id, severity := range map[string]string{
		"bpf-lsm-undecided-unreadable":  "warning",
		"bpf-lsm-undecided-depth-limit": "warning",
		"bpf-lsm-context-rule-overflow": "error",
	} {
		if got[id].Severity != severity {
			t.Errorf("%s severity %q, want %q (warnings %v)", id, got[id].Severity, severity, got)
		}
	}
	if _, ok := got["bpf-lsm-undecided-path-too-long"]; ok {
		t.Error("zero counter produced a warning")
	}
}
