//go:build linux

package bpflsm

import (
	"fmt"
	"path/filepath"
)

// Operation is the Filemaster decision-engine operation encoded in the BPF table.
type Operation uint32

const (
	OperationRead Operation = iota
	OperationWrite
	OperationExecute
	OperationCreate
	OperationDelete
)

// TargetKind is the rule kind dimension retained by the BPF verdict ABI.
type TargetKind uint32

const (
	TargetFile   TargetKind = 1
	TargetFolder TargetKind = 2
)

// Relation is a target's dentry relationship to an inode-keyed object root.
type Relation uint32

const (
	RelationSelf Relation = iota
	RelationChild
	RelationDescendant
)

// Verdict is a complete Filemaster decision-engine result.
type Verdict uint32

const (
	VerdictDeny Verdict = iota
	VerdictAllow
)

// SentinelName is used to materialize one- and two-component descendants for
// the fixed BPF relation table. The structural compiler reports glob rules that
// would make this synthetic name misleading.
const SentinelName = "filemaster-bpf-sentinel"

// ObjectInput is one existing path whose inode anchors a BPF object table.
// Callers derive candidates from watch roots, rule bases, and current glob
// matches; this package deliberately receives plain data to avoid an import
// cycle with fileaccess.
type ObjectInput struct {
	Path string
}

// Evaluator delegates every semantic decision to Filemaster's existing engine.
// isFolder maps directly to DecisionSnapshot.DecideOperation's final argument.
type Evaluator func(path string, operation Operation, isFolder bool) Verdict

// CompiledObject is a resolved inode-keyed object in a compiled table.
type CompiledObject struct {
	ID   uint32
	Path string
	File fileID
}

// VerdictEntry is one covered-object lookup row. Label is deliberately absent:
// M2 has only UNIDENTIFIED and the publisher encodes its fixed ABI value.
type VerdictEntry struct {
	Object    uint32
	Operation Operation
	Relation  Relation
	Kind      TargetKind
	Verdict   Verdict
}

// NoMatchEntry answers an uncovered side of an otherwise covered multi-object
// operation. The kind remains necessary because Filemaster rules distinguish
// files from folders.
type NoMatchEntry struct {
	Operation Operation
	Kind      TargetKind
	Verdict   Verdict
}

// Table is the plain, complete input accepted by Enforcer.Publish.
type Table struct {
	Objects   []CompiledObject
	Verdicts  []VerdictEntry
	NoMatches []NoMatchEntry
}

// Compile resolves object inode identities and evaluates the finite table
// positions through the supplied existing-engine adapter. noMatch is the
// profile default derived by verdictFromDefaultAction: an unmatched side of a
// covered multi-object operation must not be evaluated against a synthetic
// pathname that a real rule could match. This function never implements
// Filemaster matching itself.
func Compile(inputs []ObjectInput, evaluate Evaluator, noMatch Verdict) (Table, error) {
	if evaluate == nil {
		return Table{}, fmt.Errorf("compile structural table: nil evaluator")
	}
	if noMatch != VerdictDeny && noMatch != VerdictAllow {
		return Table{}, fmt.Errorf("compile structural table: invalid no-match verdict %d", noMatch)
	}

	table := Table{}
	seen := make(map[fileID]struct{}, len(inputs))
	for _, input := range inputs {
		if input.Path == "" {
			continue
		}
		path := filepath.Clean(input.Path)
		id, err := pathFileID(path)
		if err != nil {
			return Table{}, fmt.Errorf("resolve structural object %q: %w", path, err)
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		if len(table.Objects) >= maxObjects {
			return Table{}, fmt.Errorf("compile structural table: more than %d inode objects", maxObjects)
		}
		seen[id] = struct{}{}
		table.Objects = append(table.Objects, CompiledObject{
			ID:   uint32(len(table.Objects)),
			Path: path,
			File: id,
		})
	}

	for _, object := range table.Objects {
		for _, sample := range relationSamples(object.Path) {
			for _, operation := range allOperations {
				for _, kind := range allKinds {
					table.Verdicts = append(table.Verdicts, VerdictEntry{
						Object:    object.ID,
						Operation: operation,
						Relation:  sample.relation,
						Kind:      kind,
						Verdict:   evaluate(sample.path, operation, kind == TargetFolder),
					})
				}
			}
		}
	}
	for _, operation := range allOperations {
		for _, kind := range allKinds {
			table.NoMatches = append(table.NoMatches, NoMatchEntry{
				Operation: operation,
				Kind:      kind,
				Verdict:   noMatch,
			})
		}
	}
	return table, nil
}

var allOperations = [...]Operation{
	OperationRead,
	OperationWrite,
	OperationExecute,
	OperationCreate,
	OperationDelete,
}

var allKinds = [...]TargetKind{TargetFile, TargetFolder}

type relationSample struct {
	relation Relation
	path     string
}

func relationSamples(root string) [3]relationSample {
	return [3]relationSample{
		{relation: RelationSelf, path: root},
		{relation: RelationChild, path: filepath.Join(root, SentinelName)},
		{relation: RelationDescendant, path: filepath.Join(root, SentinelName, SentinelName)},
	}
}
