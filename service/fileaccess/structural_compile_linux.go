//go:build linux

package fileaccess

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
	evaluate := structuralEvaluator(lookup)
	watchRules, err := parseWatchRules(resolveWatchPaths())
	if err != nil {
		return bpflsm.Table{}, nil, fmt.Errorf("parse structural watch paths: %w", err)
	}
	inputs, warnings := structuralObjectInputs(watchRules.ScopePaths, lookup.Snapshot)
	table, err := bpflsm.Compile(inputs, evaluate, structuralDefaultVerdict(lookup))
	if err != nil {
		return bpflsm.Table{}, warnings, err
	}
	return table, warnings, nil
}

func structuralEvaluator(lookup LookupResult) bpflsm.Evaluator {
	return func(path string, operation bpflsm.Operation, isFolder bool) bpflsm.Verdict {
		var verdict Verdict
		if lookup.Snapshot == nil {
			// Lookup's documented no-profile fallback is DefaultActionAsk. Keep
			// using the engine helper rather than spelling out a second default.
			verdict = verdictFromDefaultAction(lookup.DefaultAction)
		} else {
			verdict = lookup.Snapshot.DecideOperation(path, structuralOperation(operation), isFolder)
		}
		return structuralBPFVerdict(verdict)
	}
}

func structuralDefaultVerdict(lookup LookupResult) bpflsm.Verdict {
	return structuralBPFVerdict(verdictFromDefaultAction(lookup.DefaultAction))
}

func structuralBPFVerdict(verdict Verdict) bpflsm.Verdict {
	if verdict == VerdictDeny {
		return bpflsm.VerdictDeny
	}
	return bpflsm.VerdictAllow
}

func structuralOperation(operation bpflsm.Operation) DecisionOp {
	switch operation {
	case bpflsm.OperationRead:
		return DecisionRead
	case bpflsm.OperationWrite:
		return DecisionWrite
	case bpflsm.OperationExecute:
		return DecisionExecute
	case bpflsm.OperationCreate:
		return DecisionCreate
	case bpflsm.OperationDelete:
		return DecisionDelete
	default:
		return DecisionRead
	}
}

func structuralObjectInputs(watchPaths []string, snapshot *DecisionSnapshot) ([]bpflsm.ObjectInput, []bpflsm.CompileWarning) {
	paths := make(map[string]struct{})
	warnings := newStructuralWarnings()
	addExisting := func(path, pattern string) {
		if path == "" {
			return
		}
		path = filepath.Clean(path)
		if _, err := os.Stat(path); err != nil {
			if pattern != "" {
				warnings.add("rule-no-existing-inode", pattern)
			}
			return
		}
		paths[path] = struct{}{}
	}
	for _, path := range watchPaths {
		addExisting(path, "")
	}
	if snapshot != nil {
		for _, rule := range structuralRules(snapshot) {
			base, glob := structuralRuleBase(rule.Pattern)
			addExisting(base, rule.Pattern)
			if structuralSentinelCollision(rule, base, glob) {
				warnings.add("glob-matches-sentinel", rule.Pattern)
			}
			if !glob {
				continue
			}
			warnings.add("glob-future-match", rule.Pattern)
			matches, err := filepath.Glob(rule.Pattern)
			if err != nil {
				warnings.add("rule-no-existing-inode", rule.Pattern)
				continue
			}
			if len(matches) == 0 {
				warnings.add("rule-no-existing-inode", rule.Pattern)
			}
			for _, match := range matches {
				addExisting(match, rule.Pattern)
			}
		}
	}
	result := make([]bpflsm.ObjectInput, 0, len(paths))
	for path := range paths {
		result = append(result, bpflsm.ObjectInput{Path: path})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, warnings.list()
}

func structuralRules(snapshot *DecisionSnapshot) []PathRule {
	rules := make([]PathRule, 0, len(snapshot.Read.Rules)+len(snapshot.Write.Rules)+len(snapshot.Exec.Rules))
	rules = append(rules, snapshot.Read.Rules...)
	rules = append(rules, snapshot.Write.Rules...)
	rules = append(rules, snapshot.Exec.Rules...)
	return rules
}

// structuralRuleBase returns the fixed, inode-resolvable prefix of a rule.
// A recursive pattern's base is its `/**` prefix and is exact in the finite
// relation table; a single-segment glob returns true for the second result.
func structuralRuleBase(pattern string) (string, bool) {
	if strings.HasSuffix(pattern, "/**") {
		return filepath.Clean(strings.TrimSuffix(pattern, "/**")), false
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return filepath.Clean(pattern), false
	}
	volume := filepath.VolumeName(pattern)
	rest := strings.TrimPrefix(pattern[len(volume):], string(filepath.Separator))
	components := strings.Split(rest, string(filepath.Separator))
	fixed := make([]string, 0, len(components))
	for _, component := range components {
		if strings.ContainsAny(component, "*?[") {
			break
		}
		fixed = append(fixed, component)
	}
	base := filepath.Join(fixed...)
	if filepath.IsAbs(pattern) {
		base = string(filepath.Separator) + base
	}
	if volume != "" {
		base = volume + base
	}
	if base == "" {
		base = string(filepath.Separator)
	}
	return filepath.Clean(base), true
}

func structuralSentinelPath(pattern, base string) string {
	if strings.HasSuffix(pattern, "/**") {
		return filepath.Join(base, bpflsm.SentinelName)
	}
	volume := filepath.VolumeName(pattern)
	rest := strings.TrimPrefix(pattern[len(volume):], string(filepath.Separator))
	components := strings.Split(rest, string(filepath.Separator))
	for index, component := range components {
		if strings.ContainsAny(component, "*?[") {
			components[index] = bpflsm.SentinelName
		}
	}
	path := filepath.Join(components...)
	if filepath.IsAbs(pattern) {
		path = string(filepath.Separator) + path
	}
	return volume + path
}

// structuralSentinelCollision detects a rule which could make a finite sample
// stand for more paths than it should. Recursive rules normally match their
// own descendant samples by design; they collide only if their fixed base
// itself contains the reserved sample name.
func structuralSentinelCollision(rule PathRule, base string, glob bool) bool {
	if glob {
		return rule.Matches(structuralSentinelPath(rule.Pattern, base))
	}
	if strings.HasSuffix(rule.Pattern, "/**") {
		return structuralHasSentinelSegment(base)
	}
	return structuralHasSentinelSegment(rule.Pattern)
}

func structuralHasSentinelSegment(path string) bool {
	for _, component := range strings.Split(filepath.Clean(path), string(filepath.Separator)) {
		if component == bpflsm.SentinelName {
			return true
		}
	}
	return false
}

type structuralWarnings map[string]map[string]struct{}

func newStructuralWarnings() structuralWarnings {
	return make(structuralWarnings)
}

func (warnings structuralWarnings) add(id, pattern string) {
	if pattern == "" {
		return
	}
	if warnings[id] == nil {
		warnings[id] = make(map[string]struct{})
	}
	warnings[id][pattern] = struct{}{}
}

func (warnings structuralWarnings) list() []bpflsm.CompileWarning {
	result := make([]bpflsm.CompileWarning, 0, len(warnings))
	for id, patterns := range warnings {
		list := make([]string, 0, len(patterns))
		for pattern := range patterns {
			list = append(list, pattern)
		}
		sort.Strings(list)
		result = append(result, bpflsm.CompileWarning{ID: id, Patterns: list})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
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
