//go:build linux && !filemaster_test

package fileaccess

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
)

func TestStructuralObjectInputsUsesParsedWatchScope(t *testing.T) {
	root := t.TempDir()
	watch, err := parseWatchRules([]string{"+ " + root, "- " + filepath.Join(root, "excluded")})
	if err != nil {
		t.Fatal(err)
	}
	inputs, warnings := structuralObjectInputs(watch.ScopePaths, nil)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", warnings)
	}
	if len(inputs) != 1 || inputs[0].Path != root {
		t.Fatalf("scope inputs = %#v, want %q", inputs, root)
	}
}

func TestStructuralObjectInputsTreatsRecursiveRuleAsExact(t *testing.T) {
	root := t.TempDir()
	snapshot := &DecisionSnapshot{
		Write: PathRules{Rules: []PathRule{{
			Pattern: filepath.Join(root, "**"),
			Verdict: VerdictDeny,
		}}},
	}
	inputs, warnings := structuralObjectInputs([]string{root}, snapshot)
	if len(inputs) != 1 || inputs[0].Path != root {
		t.Fatalf("recursive inputs = %#v, want root %q", inputs, root)
	}
	if len(warnings) != 0 {
		t.Fatalf("recursive rule warnings = %#v, want none", warnings)
	}
}

func TestStructuralObjectInputsWarnsForSingleSegmentGlobAndSentinel(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "existing"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pattern := filepath.Join(root, "*")
	snapshot := &DecisionSnapshot{
		Write: PathRules{Rules: []PathRule{{Pattern: pattern, Verdict: VerdictDeny}}},
	}
	inputs, warnings := structuralObjectInputs([]string{root}, snapshot)
	if len(inputs) != 2 {
		t.Fatalf("glob inputs = %#v, want scope root and current match", inputs)
	}
	want := map[string]bool{"glob-future-match": false, "glob-matches-sentinel": false}
	for _, warning := range warnings {
		if _, ok := want[warning.ID]; ok && len(warning.Patterns) == 1 && warning.Patterns[0] == pattern {
			want[warning.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("missing %s warning for %q: %#v", id, pattern, warnings)
		}
	}
}

func TestStructuralObjectInputsWarnsForExactSentinelPath(t *testing.T) {
	root := t.TempDir()
	pattern := filepath.Join(root, bpflsm.SentinelName)
	if err := os.WriteFile(pattern, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := &DecisionSnapshot{
		Write: PathRules{Rules: []PathRule{{Pattern: pattern, Verdict: VerdictDeny}}},
	}
	_, warnings := structuralObjectInputs([]string{root}, snapshot)
	if len(warnings) != 1 || warnings[0].ID != "glob-matches-sentinel" || len(warnings[0].Patterns) != 1 || warnings[0].Patterns[0] != pattern {
		t.Fatalf("exact sentinel warnings = %#v", warnings)
	}
}

func TestStructuralDefaultVerdictIsProfileDefault(t *testing.T) {
	if got := structuralDefaultVerdict(LookupResult{}); got != bpflsm.VerdictDeny {
		t.Fatalf("Ask/default unset no-match = %v, want deny", got)
	}
}
