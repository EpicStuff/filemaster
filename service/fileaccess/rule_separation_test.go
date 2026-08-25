package fileaccess

import (
	"sync"
	"testing"

	"github.com/safing/portmaster/service/profile"
)

// recordingStore is a minimal RuleStore that records the operation each entry
// was routed to, for asserting the persistence side of the router.
type recordingStore struct {
	mu      sync.Mutex
	ops     []FileOp
	entries []string
}

func (s *recordingStore) ID() string { return "rec" }

func (s *recordingStore) AppendRule(op FileOp, entry string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ops = append(s.ops, op)
	s.entries = append(s.entries, entry)
	return nil
}

// This file covers the separated per-operation rule-list model: a DecisionSnapshot
// holds independent Access(/Read), Write and Execute lists sharing one default,
// and every decision routes through DecisionSnapshot to the list its operation
// selects. See docs/backend-features.md and rule_scope.go.

// snapshotOf builds a snapshot with the given per-operation stored rule strings
// and a Permit default (so an unmatched, supported operation resolves to Allow
// and the routing under test is what actually decides).
func snapshotOf(read, write, exec []string) *DecisionSnapshot {
	return newDecisionSnapshot("p", "local", profile.DefaultActionPermit, ruleLists{read: read, write: write, exec: exec}, 1)
}

// lookupVerdict resolves the effective verdict for a supported operation,
// applying the snapshot's Permit/Block default when no rule matched. It fails the
// test if the operation is reported unsupported.
func lookupVerdict(t *testing.T, s *DecisionSnapshot, path string, op FileOp, isDir bool) Verdict {
	t.Helper()
	verdict, matched, ok := s.Lookup(path, op, isDir)
	if !ok {
		t.Fatalf("operation %v unexpectedly unsupported", op)
	}
	if matched {
		return verdict
	}
	switch s.DefaultAction {
	case profile.DefaultActionBlock:
		return VerdictDeny
	default:
		return VerdictAllow
	}
}

func TestOperationListsAreIsolated(t *testing.T) {
	// A deny rule in exactly one list must not influence the other two operations.
	cases := []struct {
		name       string
		read       []string
		write      []string
		exec       []string
		denyOp     FileOp
		otherOps   []FileOp
		deniedPath string
	}{
		{"access-only", []string{`- /x`}, nil, nil, OpRead, []FileOp{OpWrite, OpExec}, "/x"},
		{"write-only", nil, []string{`- /x`}, nil, OpWrite, []FileOp{OpRead, OpExec}, "/x"},
		{"exec-only", nil, nil, []string{`- /x`}, OpExec, []FileOp{OpRead, OpWrite}, "/x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := snapshotOf(c.read, c.write, c.exec)
			if got := lookupVerdict(t, s, c.deniedPath, c.denyOp, false); got != VerdictDeny {
				t.Fatalf("%s: own operation got %v, want deny", c.name, got)
			}
			for _, op := range c.otherOps {
				if got := lookupVerdict(t, s, c.deniedPath, op, false); got != VerdictAllow {
					t.Fatalf("%s: operation %v got %v, want allow (rule must not cross lists)", c.name, op, got)
				}
			}
		})
	}
}

func TestOpenEventsUseAccessList(t *testing.T) {
	// OpOpen folds to the Read list (ruleScopeOp); a Read-list rule governs opens,
	// while Write/Exec rules for the same path do not.
	s := snapshotOf([]string{`- /secret`}, []string{`+ /secret`}, []string{`+ /secret`})
	if got := lookupVerdict(t, s, "/secret", OpOpen, false); got != VerdictDeny {
		t.Fatalf("open governed by access list: got %v, want deny", got)
	}
	if _, ok := s.rulesFor(OpOpen); !ok {
		t.Fatalf("OpOpen must route to a supported list")
	}
}

func TestUnknownOperationFailsClosed(t *testing.T) {
	s := snapshotOf([]string{`+ /**`}, []string{`+ /**`}, []string{`+ /**`})
	// Every router funnels through fileAccessListOp; all of them must fail closed
	// on an operation outside {read, write, exec} rather than picking a list.
	if _, ok := fileAccessListOp(FileOp(200)); ok {
		t.Fatalf("fileAccessListOp must fail closed on an unknown operation")
	}
	if _, _, ok := s.Lookup("/anything", FileOp(200), false); ok {
		t.Fatalf("unknown operation must be reported unsupported, not routed to a list")
	}
	if _, ok := s.rulesFor(FileOp(200)); ok {
		t.Fatalf("rulesFor must fail closed on an unknown operation")
	}
	// fileAccessRuleKey (the persistence-side router) must fail closed too.
	if _, ok := fileAccessRuleKey(FileOp(200)); ok {
		t.Fatalf("fileAccessRuleKey must fail closed on an unknown operation")
	}
}

func TestOverlayRejectsUnsupportedOperation(t *testing.T) {
	// A learned rule with an unsupported operation must not enter the overlay:
	// otherwise it would land in the read list and then loop forever in dirty
	// retries because storage rejects it.
	p := NewRulePersistence(nil, RulePersistenceOptions{})
	store := &recordingStore{}
	snap := newDecisionSnapshot("p", "local", profile.DefaultActionAsk, ruleLists{}, 1)
	merged := p.ApplyEvent(snap, store, "/x", FileOp(200), false, VerdictAllow)
	if merged != snap {
		t.Fatalf("unsupported-op overlay created a replacement snapshot")
	}
	for name, list := range map[string]PathRules{"read": merged.Read, "write": merged.Write, "exec": merged.Exec} {
		if _, ok := list.Lookup("/x"); ok {
			t.Fatalf("unsupported-op rule leaked into the %s list", name)
		}
	}
	if len(p.Diagnostics()) != 0 {
		t.Fatalf("unsupported-op rule created overlay state: %v", p.Diagnostics())
	}
}

func TestDecideOperationUsesSharedDefault(t *testing.T) {
	// On no match the non-prompt engine applies the shared profile default
	// resolved to a Verdict -- not a hardcoded allow. Permit allows; Block and
	// Ask (which cannot prompt here) fail closed to deny.
	block := newDecisionSnapshot("p", "local", profile.DefaultActionBlock, ruleLists{}, 1)
	if got := block.DecideOperation("/x", DecisionAccess, false); got != VerdictDeny {
		t.Fatalf("block default: DecideOperation = %v, want deny", got)
	}
	permit := newDecisionSnapshot("p", "local", profile.DefaultActionPermit, ruleLists{}, 1)
	if got := permit.DecideOperation("/x", DecisionExecute, false); got != VerdictAllow {
		t.Fatalf("permit default: DecideOperation = %v, want allow", got)
	}
	ask := newDecisionSnapshot("p", "local", profile.DefaultActionAsk, ruleLists{}, 1)
	if got := ask.DecideOperation("/x", DecisionWrite, false); got != VerdictDeny {
		t.Fatalf("ask default: DecideOperation = %v, want deny (fail closed)", got)
	}
}

func TestDecideOperationDefaultOnDirectlyConstructedSnapshot(t *testing.T) {
	// A snapshot built as a struct literal (profile_handler.go does this when no
	// parsed snapshot is available) has zero-value rule lists. The no-match
	// verdict must still come from DefaultAction; the zero Verdict is Allow, so
	// reading a per-list default here would silently fail open.
	block := &DecisionSnapshot{ProfileID: "p", Source: "local", DefaultAction: profile.DefaultActionBlock}
	for _, op := range []DecisionOp{DecisionAccess, DecisionRead, DecisionWrite, DecisionCreate, DecisionDelete, DecisionExecute} {
		if got := block.DecideOperation("/anything", op, false); got != VerdictDeny {
			t.Fatalf("block default, direct snapshot: DecideOperation(%s) = %v, want deny", op, got)
		}
	}
	ask := &DecisionSnapshot{ProfileID: "p", Source: "local", DefaultAction: profile.DefaultActionAsk}
	if got := ask.DecideOperation("/anything", DecisionAccess, false); got != VerdictDeny {
		t.Fatalf("ask default, direct snapshot: DecideOperation = %v, want deny (fail closed)", got)
	}
	permit := &DecisionSnapshot{ProfileID: "p", Source: "local", DefaultAction: profile.DefaultActionPermit}
	if got := permit.DecideOperation("/anything", DecisionAccess, false); got != VerdictAllow {
		t.Fatalf("permit default, direct snapshot: DecideOperation = %v, want allow", got)
	}
}

func TestUnknownDecisionOpFailsClosed(t *testing.T) {
	// An unrecognized DecisionOp must not inherit Access/Read policy: it has to
	// deny even where the read list holds a matching allow rule.
	s := newDecisionSnapshot("p", "local", profile.DefaultActionPermit,
		ruleLists{read: []string{`+ /secret`}, write: []string{`+ /secret`}, exec: []string{`+ /secret`}}, 1)
	for _, op := range []DecisionOp{DecisionOp(200), DecisionDelete + 1} {
		if _, ok := op.scopeOp(); ok {
			t.Fatalf("scopeOp(%d) reported a list for an unknown operation", op)
		}
		if got := s.DecideOperation("/secret", op, false); got != VerdictDeny {
			t.Fatalf("unknown DecisionOp(%d): DecideOperation = %v, want deny", op, got)
		}
	}
}

func TestEveryDecisionOpRoutesToAList(t *testing.T) {
	// The counterpart to the check above: every declared operation must map to a
	// list, so adding one without updating scopeOp fails here rather than
	// silently inheriting Access/Read policy.
	want := map[DecisionOp]FileOp{
		DecisionAccess:  OpRead,
		DecisionRead:    OpRead,
		DecisionWrite:   OpWrite,
		DecisionCreate:  OpWrite,
		DecisionDelete:  OpWrite,
		DecisionExecute: OpExec,
	}
	for op, expect := range want {
		got, ok := op.scopeOp()
		if !ok {
			t.Fatalf("scopeOp(%s) reported unsupported", op)
		}
		if got != expect {
			t.Fatalf("scopeOp(%s) = %v, want %v", op, got, expect)
		}
	}
	if op := DecisionOp(len(want)); op.String() != "unknown" {
		t.Fatalf("DecisionOp(%d) is declared but missing from this test", op)
	}
}

func TestFirstMatchWinsWithinList(t *testing.T) {
	// The earlier rule in a list decides even when a later rule also matches.
	s := snapshotOf([]string{`+ /x`, `- /x`}, nil, nil)
	if got := lookupVerdict(t, s, "/x", OpRead, false); got != VerdictAllow {
		t.Fatalf("first-match: got %v, want allow (earlier rule wins)", got)
	}
	s = snapshotOf([]string{`- /x`, `+ /x`}, nil, nil)
	if got := lookupVerdict(t, s, "/x", OpRead, false); got != VerdictDeny {
		t.Fatalf("first-match: got %v, want deny (earlier rule wins)", got)
	}
}

func TestPatternSemanticsWithinList(t *testing.T) {
	s := snapshotOf([]string{
		`- /exact/file`,     // literal path
		`+ /glob/*.txt`,     // single-segment glob
		`- /tree/**`,        // recursive
		`+ folder:/onlydir`, // folder-only literal
	}, nil, nil)

	if got := lookupVerdict(t, s, "/exact/file", OpRead, false); got != VerdictDeny {
		t.Fatalf("exact: got %v, want deny", got)
	}
	if got := lookupVerdict(t, s, "/exact/fileX", OpRead, false); got != VerdictAllow {
		t.Fatalf("exact must not match a longer path: got %v, want allow", got)
	}
	if got := lookupVerdict(t, s, "/glob/a.txt", OpRead, false); got != VerdictAllow {
		t.Fatalf("glob: got %v, want allow", got)
	}
	if got := lookupVerdict(t, s, "/glob/sub/a.txt", OpRead, false); got != VerdictAllow {
		t.Fatalf("single-segment glob must not cross a separator: got %v, want allow (default)", got)
	}
	if got := lookupVerdict(t, s, "/tree", OpRead, false); got != VerdictDeny {
		t.Fatalf("recursive must match the prefix itself: got %v, want deny", got)
	}
	if got := lookupVerdict(t, s, "/tree/deep/child", OpRead, false); got != VerdictDeny {
		t.Fatalf("recursive must match descendants: got %v, want deny", got)
	}
	if got := lookupVerdict(t, s, "/onlydir", OpRead, true); got != VerdictAllow {
		t.Fatalf("directory-only rule must apply to a directory event: got %v, want allow", got)
	}
	if got := lookupVerdict(t, s, "/onlydir", OpRead, false); got != VerdictAllow {
		// No rule matches a file event on /onlydir, so the Permit default applies.
		t.Fatalf("directory-only rule must not apply to a file event: got %v, want allow (default)", got)
	}
}

func TestSharedDefaultAcrossLists(t *testing.T) {
	// One default action governs every operation; there are no per-list defaults
	// that could diverge.
	block := newDecisionSnapshot("p", "local", profile.DefaultActionBlock, ruleLists{}, 1)
	for _, op := range []FileOp{OpRead, OpWrite, OpExec} {
		_, matched, ok := block.Lookup("/unmatched", op, false)
		if !ok || matched {
			t.Fatalf("op %v: expected supported no-match, got ok=%v matched=%v", op, ok, matched)
		}
		if got := lookupVerdict(t, block, "/unmatched", op, false); got != VerdictDeny {
			t.Fatalf("op %v: shared block default must deny, got %v", op, got)
		}
	}
}

func TestSnapshotReplacementIsAtomicPerList(t *testing.T) {
	// A replacement snapshot is a wholly new value; a reader holding the old one
	// never observes a mix of new Access rules with old Execute rules.
	old := snapshotOf([]string{`- /x`}, nil, []string{`- /y`})
	newSnap := snapshotOf([]string{`+ /x`}, nil, []string{`+ /y`})
	if got := lookupVerdict(t, old, "/x", OpRead, false); got != VerdictDeny {
		t.Fatalf("old snapshot access: got %v, want deny", got)
	}
	if got := lookupVerdict(t, old, "/y", OpExec, false); got != VerdictDeny {
		t.Fatalf("old snapshot exec: got %v, want deny", got)
	}
	if got := lookupVerdict(t, newSnap, "/x", OpRead, false); got != VerdictAllow {
		t.Fatalf("new snapshot access: got %v, want allow", got)
	}
	if got := lookupVerdict(t, newSnap, "/y", OpExec, false); got != VerdictAllow {
		t.Fatalf("new snapshot exec: got %v, want allow", got)
	}
}

func TestConcurrentReadsDuringSnapshotSwap(t *testing.T) {
	// Publishing is a pointer swap; readers race the swap but each reader only
	// ever sees one whole immutable snapshot. Run under -race.
	var current struct {
		mu sync.RWMutex
		s  *DecisionSnapshot
	}
	current.s = snapshotOf([]string{`- /x`}, nil, nil)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				current.mu.RLock()
				s := current.s
				current.mu.RUnlock()
				// Either the deny or the allow snapshot -- never a torn mix.
				if v, matched, ok := s.Lookup("/x", OpRead, false); !ok || !matched || (v != VerdictAllow && v != VerdictDeny) {
					t.Errorf("torn read: ok=%v matched=%v verdict=%v", ok, matched, v)
					return
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		swap := snapshotOf([]string{`+ /x`}, nil, nil)
		if i%2 == 0 {
			swap = snapshotOf([]string{`- /x`}, nil, nil)
		}
		current.mu.Lock()
		current.s = swap
		current.mu.Unlock()
	}
	close(stop)
	wg.Wait()
}

func TestSeededRulesRouteToTheirLists(t *testing.T) {
	// Seeded profile rules are stored untagged in per-operation config keys, so
	// they parse straight into the matching list. A seed granting Access to a
	// directory tree must not grant Execute unless it is also in the exec list.
	accessSeed := []string{"+ /opt/app/**"}
	execSeed := []string{"+ /opt/app/bin"}
	s := newDecisionSnapshot("p", "local", profile.DefaultActionBlock, ruleLists{read: accessSeed, exec: execSeed}, 1)

	if got := lookupVerdict(t, s, "/opt/app/data", OpOpen, false); got != VerdictAllow {
		t.Fatalf("seeded access: got %v, want allow", got)
	}
	// The access seed covers /opt/app/bin for opens, but execute is governed only
	// by the exec seed.
	if got := lookupVerdict(t, s, "/opt/app/bin", OpExec, false); got != VerdictAllow {
		t.Fatalf("seeded exec: got %v, want allow", got)
	}
	if got := lookupVerdict(t, s, "/opt/app/data", OpExec, false); got != VerdictDeny {
		t.Fatalf("access seed must not grant execute: got %v, want deny (block default)", got)
	}
}

func TestDecideOperationRoutesByOperation(t *testing.T) {
	// The future non-prompt engine routes through the snapshot too: a Write-list
	// rule governs Write/Create/Delete, an Exec-list rule governs Execute, and
	// neither leaks into Access.
	s := newDecisionSnapshot("p", "local", profile.DefaultActionPermit, ruleLists{
		write: []string{`- /w`},
		exec:  []string{`- /e`},
	}, 1)
	if got := s.DecideOperation("/w", DecisionWrite, false); got != VerdictDeny {
		t.Fatalf("write rule must govern write: got %v, want deny", got)
	}
	if got := s.DecideOperation("/w", DecisionAccess, false); got != VerdictAllow {
		t.Fatalf("write rule must not govern access: got %v, want allow", got)
	}
	if got := s.DecideOperation("/e", DecisionExecute, false); got != VerdictDeny {
		t.Fatalf("exec rule must govern execute: got %v, want deny", got)
	}
	if got := s.DecideOperation("/e", DecisionRead, false); got != VerdictAllow {
		t.Fatalf("exec rule must not govern read: got %v, want allow", got)
	}
}
