//go:build linux

package bpflsm

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileUsesExplicitNoMatchDefault(t *testing.T) {
	root := t.TempDir()
	var evaluated []string
	table, err := Compile(
		[]ObjectInput{{Path: root}, {Path: filepath.Clean(root)}},
		func(path string, _ Operation, _ bool) Verdict {
			evaluated = append(evaluated, path)
			// This mimics a rule which would match the compiler's synthetic
			// descendants. It must never influence NOMATCH.
			if strings.Contains(path, SentinelName) {
				return VerdictAllow
			}
			return VerdictDeny
		},
		VerdictDeny,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Objects) != 1 {
		t.Fatalf("objects = %d, want deduplicated 1", len(table.Objects))
	}
	if len(table.Verdicts) != 3*len(allOperations)*len(allKinds) {
		t.Fatalf("verdict rows = %d, want %d", len(table.Verdicts), 3*len(allOperations)*len(allKinds))
	}
	if len(evaluated) != len(table.Verdicts) {
		t.Fatalf("engine calls = %d, want only %d object rows", len(evaluated), len(table.Verdicts))
	}
	if len(table.NoMatches) != len(allOperations)*len(allKinds) {
		t.Fatalf("no-match rows = %d, want %d", len(table.NoMatches), len(allOperations)*len(allKinds))
	}
	for _, entry := range table.NoMatches {
		if entry.Verdict != VerdictDeny {
			t.Fatalf("NOMATCH %v/%v = %v, want profile default deny", entry.Operation, entry.Kind, entry.Verdict)
		}
	}
}

func TestCompileRejectsInvalidNoMatchDefault(t *testing.T) {
	_, err := Compile(nil, func(string, Operation, bool) Verdict { return VerdictAllow }, Verdict(99))
	if err == nil {
		t.Fatal("Compile accepted an invalid no-match verdict")
	}
}
