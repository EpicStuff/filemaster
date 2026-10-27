package fileaccess

import (
	"strings"
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

func TestStructuralCoverageWarnings(t *testing.T) {
	warningsOf := func(status bpflsm.Status) map[string]DegradedWarning {
		var diagnostics FileAccessDiagnostics
		diagnostics.Structural = status
		got := make(map[string]DegradedWarning)
		for _, warning := range diagnosticsWarnings(diagnostics) {
			got[warning.ID] = warning
		}
		return got
	}
	failed := warningsOf(bpflsm.Status{Mode: bpflsm.ModeEnforce, State: bpflsm.StateFailed, Error: "load BPF LSM object: verifier", Retained: []string{"42"}})
	if warning := failed["bpf-lsm-failed"]; !strings.Contains(warning.Message, "older generation") || !strings.Contains(warning.Details, "generations=42") {
		t.Errorf("failed start with a retained generation: %+v", warning)
	}
	if warning := warningsOf(bpflsm.Status{Mode: bpflsm.ModeEnforce, State: bpflsm.StateFailed})["bpf-lsm-failed"]; !strings.Contains(warning.Message, "unprotected") {
		t.Errorf("failed start without a retained generation: %+v", warning)
	}
	active := warningsOf(bpflsm.Status{
		Mode: bpflsm.ModeEnforce, State: bpflsm.StateActive, Generation: "7", Unpinned: true,
		CompileWarnings: []bpflsm.CompileWarning{{ID: "overlay-not-covered", Patterns: []string{"/srv/ovl (overlay)"}}},
	})
	if active["bpf-lsm-generation-unpinned"].Severity != "warning" {
		t.Errorf("unpinned generation: %+v", active)
	}
	if warning := active["bpf-lsm-overlay-not-covered"]; warning.Severity != "error" || !strings.Contains(warning.Details, "/srv/ovl (overlay)") {
		t.Errorf("overlay not covered: %+v", warning)
	}
}
