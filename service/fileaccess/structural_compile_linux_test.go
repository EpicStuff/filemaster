//go:build linux && !filemaster_test

package fileaccess

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/profile"
)

func TestStructuralPolicyKeepsWatchRuleOrderAndExclusions(t *testing.T) {
	root := t.TempDir()
	watch, err := parseWatchRules([]string{"- " + filepath.Join(root, "excluded"), "+ " + root})
	if err != nil {
		t.Fatal(err)
	}
	scopes := scopesFromWatchRules(watch)
	want := []bpflsm.ScopeInput{{Path: filepath.Join(root, "excluded"), Exclude: true}, {Path: root}}
	if !reflect.DeepEqual(scopes, want) {
		t.Fatalf("scopes = %#v, want %#v", scopes, want)
	}
	if policy := unidentifiedLabelPolicy(LookupResult{}); len(policy.Rules) != 0 || policy.DefaultAllow {
		t.Fatalf("nil snapshot policy = %#v, want no rules and the Ask default deny", policy)
	}
}

func TestStructuralPolicyFlattensListsInEngineOrder(t *testing.T) {
	snapshot := &DecisionSnapshot{
		DefaultAction: profile.DefaultActionPermit,
		Read:          PathRules{Rules: []PathRule{{Pattern: "/r/**", Verdict: VerdictAllow}}},
		Write: PathRules{Rules: []PathRule{
			{Pattern: "/w/a", Verdict: VerdictDeny, ObjectKind: ObjectKindFolder},
			{Pattern: "/w/*", Verdict: VerdictAllow, ObjectKind: ObjectKindFile},
		}},
		Exec: PathRules{Rules: []PathRule{{Pattern: "/x", Verdict: VerdictDeny}}},
	}
	policy := unidentifiedLabelPolicy(LookupResult{Snapshot: snapshot, DefaultAction: snapshot.DefaultAction})
	want := []bpflsm.RuleInput{
		{List: bpflsm.ListRead, Pattern: "/r/**", Allow: true, Kind: bpflsm.KindAny},
		{List: bpflsm.ListWrite, Pattern: "/w/a", Allow: false, Kind: bpflsm.KindFolder},
		{List: bpflsm.ListWrite, Pattern: "/w/*", Allow: true, Kind: bpflsm.KindFile},
		{List: bpflsm.ListExecute, Pattern: "/x", Allow: false, Kind: bpflsm.KindAny},
	}
	if !reflect.DeepEqual(policy.Rules, want) {
		t.Fatalf("rules = %#v, want %#v", policy.Rules, want)
	}
	if !policy.DefaultAllow {
		t.Fatal("Permit default did not become an allowing NOMATCH")
	}
}

func TestStructuralRuleKindsMatchObjectKinds(t *testing.T) {
	for kind, want := range map[ObjectKind]bpflsm.RuleKind{
		ObjectKindAny:    bpflsm.KindAny,
		ObjectKindFile:   bpflsm.KindFile,
		ObjectKindFolder: bpflsm.KindFolder,
	} {
		if bpflsm.RuleKind(kind) != want {
			t.Errorf("ObjectKind %d converts to %d, want %d", kind, bpflsm.RuleKind(kind), want)
		}
	}
}
