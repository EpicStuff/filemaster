//go:build linux

package fileaccess

import (
	"context"
	"fmt"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/mgr"
)

func (fa *FileAccess) compileStructuralTable() (bpflsm.Table, []bpflsm.CompileWarning, error) {
	if fa.profileHandler == nil || fa.profileHandler.lookup == nil {
		return bpflsm.Table{}, nil, fmt.Errorf("unidentified profile lookup is unavailable")
	}
	lookup, err := fa.profileHandler.lookup.Lookup(context.Background(), -1)
	if err != nil {
		return bpflsm.Table{}, nil, fmt.Errorf("look up unidentified profile: %w", err)
	}
	watchRules, err := parseWatchRules(resolveWatchPaths())
	if err != nil {
		return bpflsm.Table{}, nil, fmt.Errorf("parse structural watch paths: %w", err)
	}
	policy := bpflsm.Policy{Scopes: scopesFromWatchRules(watchRules)}
	unidentified := unidentifiedLabelPolicy(lookup)
	if fa.labeller != nil {
		policy.Labels = fa.labeller.labelPolicies(unidentified)
	} else {
		policy.Labels = []bpflsm.LabelPolicy{unidentified}
	}
	return bpflsm.Compile(policy)
}

// scopesFromWatchRules preserves the configured order and exclusions.
func scopesFromWatchRules(watchRules *watchRuleSnapshot) []bpflsm.ScopeInput {
	var scopes []bpflsm.ScopeInput
	for _, rule := range watchRules.Rules {
		scopes = append(scopes, bpflsm.ScopeInput{Path: rule.Path, Exclude: rule.Exclude})
	}
	return scopes
}

// unidentifiedLabelPolicy flattens the unidentified profile's snapshot, in
// engine order, into the BPF compiler's plain label input (label 0).
func unidentifiedLabelPolicy(lookup LookupResult) bpflsm.LabelPolicy {
	policy := bpflsm.LabelPolicy{
		Label:        bpflsm.LabelUnidentified,
		DefaultAllow: verdictFromDefaultAction(lookup.DefaultAction) == VerdictAllow,
	}
	if lookup.Snapshot == nil {
		return policy
	}
	for _, list := range []struct {
		list  bpflsm.RuleList
		rules PathRules
	}{
		{bpflsm.ListRead, lookup.Snapshot.Read},
		{bpflsm.ListWrite, lookup.Snapshot.Write},
		{bpflsm.ListExecute, lookup.Snapshot.Exec},
	} {
		for _, rule := range list.rules.Rules {
			policy.Rules = append(policy.Rules, bpflsm.RuleInput{
				List:    list.list,
				Pattern: rule.Pattern,
				Allow:   rule.Verdict == VerdictAllow,
				Kind:    bpflsm.RuleKind(rule.ObjectKind),
			})
		}
	}
	return policy
}

// registerStructuralProfilePublisher owns its callback separately from the
// snapshot observer. M2 must not alter profile_binding's single observer.
func (fa *FileAccess) registerStructuralProfilePublisher(apply func()) {
	profiles, ok := fa.instance.(profileAccessor)
	if !ok {
		return
	}
	profiles.Profile().EventConfigChange.AddCallback(
		"fileaccess structural decision-table publish",
		func(_ *mgr.WorkerCtx, _ string) (bool, error) {
			if fa.lifecycle != nil && fa.lifecycle.IsRunning() {
				apply()
			}
			return false, nil
		},
	)
}
