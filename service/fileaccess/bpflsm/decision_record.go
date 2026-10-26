//go:build linux

package bpflsm

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	RecordDecision = 3

	DecisionDelete = 1
	DecisionCreate = 2
	DecisionRename = 3
	DecisionLink   = 4

	DecisionAllow     = 0
	DecisionDeny      = 1
	DecisionWouldDeny = 2

	DecisionRuleMatch      = 11
	DecisionProfileDefault = 12
	DecisionNoReason       = 13
)

type DecisionRecord struct {
	Operation     uint32
	Verdict       uint32
	Reason        uint32
	Label         uint32
	Bank          uint32
	SourceValid   bool
	TargetValid   bool
	Source        fileID
	Target        fileID
	SourceContext uint32
	TargetContext uint32
	SourcePath    string
	TargetPath    string
	Suppressed    uint32
}

func (e *Enforcer) DecisionPaths(record *DecisionRecord) (string, string, error) {
	if record == nil || record.Bank >= numBanks {
		return "", "", fmt.Errorf("invalid decision record bank")
	}
	e.mu.Lock()
	tables := append([]Table{e.tables[record.Bank]}, e.tableHistory[record.Bank]...)
	e.mu.Unlock()

	var lastErr error
	for _, table := range tables {
		lastErr = nil
		var paths [2]string
		files := [2]fileID{record.Source, record.Target}
		contexts := [2]uint32{record.SourceContext, record.TargetContext}
		relative := [2]string{record.SourcePath, record.TargetPath}
		valid := [2]bool{record.SourceValid, record.TargetValid}
		for side := range paths {
			if !valid[side] {
				continue
			}
			if int(contexts[side]) >= len(table.Contexts) {
				lastErr = fmt.Errorf("decision context %d is not in published bank %d", contexts[side], record.Bank)
				break
			}
			found := false
			for _, object := range table.Objects {
				if object.File == files[side] && contexts[side] >= object.FirstContext &&
					contexts[side]-object.FirstContext < object.ContextCount {
					found = true
					break
				}
			}
			if !found {
				lastErr = fmt.Errorf("decision object for context %d is not in published bank %d", contexts[side], record.Bank)
				break
			}
			if relative[side] != "" && !strings.HasPrefix(relative[side], "/") {
				lastErr = fmt.Errorf("decision path for context %d is not object-relative", contexts[side])
				break
			}
			base := table.Contexts[contexts[side]].Path
			path := filepath.Clean(base + relative[side])
			if !pathContains(base, path) {
				lastErr = fmt.Errorf("decision path escapes context %d", contexts[side])
				break
			}
			paths[side] = path
		}
		if lastErr == nil {
			return paths[0], paths[1], nil
		}
	}
	return "", "", lastErr
}

func decisionDropCount(collection *ebpf.Collection) (uint64, error) {
	if collection == nil || collection.Maps["DECISION_DROPS"] == nil {
		return 0, nil
	}
	values, err := perCPUValues()
	if err != nil {
		return 0, err
	}
	if err := collection.Maps["DECISION_DROPS"].Lookup(uint32(0), &values); err != nil {
		return 0, err
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return total, nil
}
