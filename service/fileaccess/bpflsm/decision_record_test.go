package bpflsm

import "testing"

func TestDecisionPathsUsesRecentBankSnapshot(t *testing.T) {
	file := fileID{dev: 7, ino: 42}
	old := Table{
		Objects:  []CompiledObject{{File: file, FirstContext: 0, ContextCount: 1}},
		Contexts: []CompiledContext{{Path: "/old"}},
	}
	e := &Enforcer{}
	e.tables[0] = Table{Contexts: []CompiledContext{{Path: "/new"}}}
	e.tableHistory[0] = []Table{old}
	path, dest, err := e.DecisionPaths(&DecisionRecord{
		Bank: 0, SourceValid: true, TargetValid: true,
		Source: file, Target: file, SourcePath: "/source", TargetPath: "/target",
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/old/source" || dest != "/old/target" {
		t.Fatalf("paths = %q, %q; want old-bank paths", path, dest)
	}
}
