package bpflsm

import (
	"encoding/binary"
	"testing"
)

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

func TestDecodeSymlinkRecordKeepsTargetText(t *testing.T) {
	b := make([]byte, decisionRecordSize)
	binary.LittleEndian.PutUint32(b[0:], recordDecision)
	binary.LittleEndian.PutUint32(b[4:], DecisionSymlink)
	binary.LittleEndian.PutUint32(b[28:], decisionSourceValid|decisionTargetText|decisionTargetTruncated)
	binary.LittleEndian.PutUint32(b[96:], uint32(len("/link")))
	binary.LittleEndian.PutUint32(b[100:], uint32(len("../a/b")))
	copy(b[112:], "/link")
	copy(b[8304:], "../a/b")
	record, err := decodeRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	decision := record.Decision
	if decision.TargetValid || decision.TargetPath != "" || decision.TargetText != "../a/b" || !decision.TargetTruncated || decision.SourcePath != "/link" {
		t.Fatalf("decoded %+v; want source /link and only target text ../a/b, truncated", decision)
	}
}
