package fileaccess

import (
	"testing"

	"github.com/safing/portmaster/service/profile"
)

// literalRule builds a literal rule without glob metacharacters. The operation is no longer carried by the
// rule; it is carried by which list the rule is placed in.
func literalRule(v Verdict, pattern string) PathRule {
	return PathRule{Pattern: pattern, Verdict: v}
}

// globRule builds a glob rule (e.g. "/folder/**").
func globRule(v Verdict, pattern string) PathRule {
	return PathRule{Pattern: pattern, Verdict: v}
}

// decisionSnapshot assembles a snapshot from the three per-operation rule lists.
// Access/Read rules go in read, Write/Create/Delete rules in write, Execute
// rules in exec -- the same routing DecisionSnapshot.rulesFor performs. The
// no-match default is set on the snapshot, which is the only place decisions
// read it from.
func decisionSnapshot(def Verdict, read, write, exec []PathRule) *DecisionSnapshot {
	return &DecisionSnapshot{
		DefaultAction: defaultActionFor(def),
		Read:          PathRules{Rules: read},
		Write:         PathRules{Rules: write},
		Exec:          PathRules{Rules: exec},
	}
}

func defaultActionFor(v Verdict) uint8 {
	if v == VerdictAllow {
		return profile.DefaultActionPermit
	}
	return profile.DefaultActionBlock
}

// TestGlobalRulesStackBeneathProfileRules exercises the ordering scopedRuleLists
// produces: a profile's own rules first, then the globally-configured rules.
// Because evaluation is first-match-wins, the profile takes precedence, requests
// it doesn't match fall through to the global rules, and only then to the default
// action -- mirroring upstream Portmaster's LayeredProfile.MatchEndpoint (app
// layers, then the global rule list, then the default).
func TestGlobalRulesStackBeneathProfileRules(t *testing.T) {
	profileRead := []string{"- /shared/blocked"}
	globalRead := []string{"+ /shared/**", "+ /global/**"}

	// Same composition scopedRuleLists performs for the read list: profile rules,
	// then global. Drive it through a snapshot's read list.
	combined := append(append([]string(nil), profileRead...), globalRead...)
	snapshot := &DecisionSnapshot{Read: ParseRules(combined), DefaultAction: profile.DefaultActionBlock}

	// Profile rule wins over the conflicting global rule (first match): deny is
	// neither the global verdict (allow) nor the default (deny would be ambiguous,
	// so the global allow makes this unambiguous).
	if got := snapshot.DecideOperation("/shared/blocked", DecisionAccess, false); got != VerdictDeny {
		t.Errorf("/shared/blocked = %s, want deny (profile rule precedes global allow)", got)
	}
	// Global rule applies where the profile is silent (allow, distinct from the deny default).
	if got := snapshot.DecideOperation("/global/file", DecisionAccess, false); got != VerdictAllow {
		t.Errorf("/global/file = %s, want allow (global rule applies beneath profile)", got)
	}
	// No profile or global rule matches -> default action.
	if got := snapshot.DecideOperation("/elsewhere", DecisionAccess, false); got != VerdictDeny {
		t.Errorf("/elsewhere = %s, want deny (default)", got)
	}
}

func TestDecisionOpRuntimeObservable(t *testing.T) {
	observable := map[DecisionOp]bool{
		DecisionAccess:  true,
		DecisionExecute: true,
		DecisionRead:    false,
		DecisionWrite:   false,
		DecisionCreate:  false,
		DecisionDelete:  false,
	}
	for op, want := range observable {
		if got := op.RuntimeObservable(); got != want {
			t.Errorf("%s.RuntimeObservable() = %v, want %v", op, got, want)
		}
	}
}

// Section 3 / 9 / 10: with "Deny Write /folder" before "Allow Write
// /folder/file.txt", content writes to the file are allowed (the folder rule
// does not apply to modifying an existing file), but deleting the file is
// denied (deletion changes a folder entry, so the folder Deny applies first).
func TestDecideContentWriteVsDeleteFolderFirst(t *testing.T) {
	snapshot := decisionSnapshot(VerdictDeny, nil, []PathRule{
		literalRule(VerdictDeny, "/folder"),
		literalRule(VerdictAllow, "/folder/file.txt"),
	}, nil)

	if got := snapshot.DecideOperation("/folder/file.txt", DecisionWrite, false); got != VerdictAllow {
		t.Errorf("content write = %s, want allow (folder rule must not apply)", got)
	}
	if got := snapshot.DecideOperation("/folder/file.txt", DecisionDelete, false); got != VerdictDeny {
		t.Errorf("delete = %s, want deny (folder Deny applies first)", got)
	}
}

// Section 3 / 10: reversing the order so the file Allow comes first makes the
// delete allowed -- the first applicable matching rule decides.
func TestDecideDeleteFileRuleFirst(t *testing.T) {
	snapshot := decisionSnapshot(VerdictDeny, nil, []PathRule{
		literalRule(VerdictAllow, "/folder/file.txt"),
		literalRule(VerdictDeny, "/folder"),
	}, nil)
	if got := snapshot.DecideOperation("/folder/file.txt", DecisionDelete, false); got != VerdictAllow {
		t.Errorf("delete = %s, want allow (file Allow is first applicable rule)", got)
	}
}

// Section 9: a nonrecursive parent-folder rule does not apply to content writes,
// but a recursive "/folder/**" rule does.
func TestDecideContentWriteRecursiveVsNonrecursive(t *testing.T) {
	nonrecursive := decisionSnapshot(VerdictAllow, nil, []PathRule{literalRule(VerdictDeny, "/folder")}, nil)
	if got := nonrecursive.DecideOperation("/folder/file.txt", DecisionWrite, false); got != VerdictAllow {
		t.Errorf("content write with nonrecursive folder Deny = %s, want allow (rule must not apply)", got)
	}

	recursive := decisionSnapshot(VerdictAllow, nil, []PathRule{globRule(VerdictDeny, "/folder/**")}, nil)
	if got := recursive.DecideOperation("/folder/file.txt", DecisionWrite, false); got != VerdictDeny {
		t.Errorf("content write with recursive folder Deny = %s, want deny (rule applies)", got)
	}
}

// Section 11: creating an object can match an exact rule for the (nonexistent)
// destination path, or a rule for the destination folder.
func TestDecideCreate(t *testing.T) {
	literalDest := decisionSnapshot(VerdictDeny, nil, []PathRule{literalRule(VerdictAllow, "/destination/new-file.txt")}, nil)
	if got := literalDest.DecideOperation("/destination/new-file.txt", DecisionCreate, false); got != VerdictAllow {
		t.Errorf("create with exact destination rule = %s, want allow", got)
	}

	folderDest := decisionSnapshot(VerdictDeny, nil, []PathRule{literalRule(VerdictAllow, "/destination")}, nil)
	if got := folderDest.DecideOperation("/destination/new-file.txt", DecisionCreate, false); got != VerdictAllow {
		t.Errorf("create with destination folder rule = %s, want allow", got)
	}
}

// Section 3: when no applicable rule matches, the profile default decides.
func TestDecideDefaultFallback(t *testing.T) {
	snapshot := decisionSnapshot(VerdictDeny, nil, []PathRule{literalRule(VerdictAllow, "/other")}, nil)
	if got := snapshot.DecideOperation("/unmatched/path", DecisionCreate, false); got != VerdictDeny {
		t.Errorf("unmatched create = %s, want deny (default)", got)
	}
}

// Operation scoping: a Write-list rule must not decide an Access (Read-list)
// operation, and vice versa.
func TestDecideRespectsListScope(t *testing.T) {
	snapshot := decisionSnapshot(VerdictAllow, nil, []PathRule{literalRule(VerdictDeny, "/secret")}, nil)
	if got := snapshot.DecideOperation("/secret", DecisionAccess, false); got != VerdictAllow {
		t.Errorf("access decided by write-list rule = %s, want allow (default; write rule out of scope)", got)
	}
	if got := snapshot.DecideOperation("/secret", DecisionWrite, false); got != VerdictDeny {
		t.Errorf("write on /secret = %s, want deny", got)
	}
}

// Access and Execute are the current runtime operations and evaluate as plain
// direct-match, first-match-wins over the operation's list.
func TestDecideAccessAndExecute(t *testing.T) {
	snapshot := decisionSnapshot(VerdictDeny,
		[]PathRule{literalRule(VerdictAllow, "/home/user/doc.txt")},
		nil,
		[]PathRule{literalRule(VerdictDeny, "/usr/bin/danger")},
	)
	if got := snapshot.DecideOperation("/home/user/doc.txt", DecisionAccess, false); got != VerdictAllow {
		t.Errorf("access = %s, want allow", got)
	}
	if got := snapshot.DecideOperation("/usr/bin/danger", DecisionExecute, false); got != VerdictDeny {
		t.Errorf("execute = %s, want deny", got)
	}
	// Folder Access is opening the folder: a direct match on the folder path.
	folder := decisionSnapshot(VerdictAllow, []PathRule{literalRule(VerdictDeny, "/private")}, nil, nil)
	if got := folder.DecideOperation("/private", DecisionAccess, true); got != VerdictDeny {
		t.Errorf("folder access = %s, want deny", got)
	}
}

func TestDecideObjectKindsStayOperationScoped(t *testing.T) {
	snapshot := decisionSnapshot(VerdictDeny,
		[]PathRule{{Pattern: "/same", Verdict: VerdictAllow, ObjectKind: ObjectKindFile}},
		[]PathRule{{Pattern: "/same", Verdict: VerdictAllow, ObjectKind: ObjectKindFolder}},
		[]PathRule{{Pattern: "/same", Verdict: VerdictDeny, ObjectKind: ObjectKindFile}},
	)
	for _, c := range []struct {
		op    DecisionOp
		isDir bool
		want  Verdict
	}{
		{DecisionAccess, false, VerdictAllow},
		{DecisionAccess, true, VerdictDeny},
		{DecisionWrite, false, VerdictDeny},
		{DecisionWrite, true, VerdictAllow},
		{DecisionExecute, false, VerdictDeny},
		{DecisionExecute, true, VerdictDeny},
	} {
		if got := snapshot.DecideOperation("/same", c.op, c.isDir); got != c.want {
			t.Fatalf("DecideOperation(%s, dir=%t) = %v, want %v", c.op, c.isDir, got, c.want)
		}
	}
}

// Section 12: rename requires Source Delete AND Destination Create/Write; the
// first denying decision wins.
func TestDecideRename(t *testing.T) {
	// Source delete denied by the source's containing folder -> whole rename
	// denied even though the destination would be creatable.
	sourceDenied := decisionSnapshot(VerdictDeny, nil, []PathRule{
		literalRule(VerdictDeny, "/src"),
		literalRule(VerdictAllow, "/dst"),
	}, nil)
	if got := sourceDenied.DecideRename(RenameRequest{Source: "/src/a.txt", Dest: "/dst/a.txt"}); got != VerdictDeny {
		t.Errorf("rename with source-folder deny = %s, want deny", got)
	}

	// Both source delete and destination create allowed.
	allowed := decisionSnapshot(VerdictDeny, nil, []PathRule{
		literalRule(VerdictAllow, "/src/a.txt"),
		literalRule(VerdictAllow, "/dst"),
	}, nil)
	if got := allowed.DecideRename(RenameRequest{Source: "/src/a.txt", Dest: "/dst/a.txt"}); got != VerdictAllow {
		t.Errorf("rename allowed = %s, want allow", got)
	}

	// Replacing an existing destination: a Deny on the existing destination's own
	// Write blocks the rename even though the folders permit it.
	replaceBlocked := decisionSnapshot(VerdictDeny, nil, []PathRule{
		literalRule(VerdictAllow, "/src/a.txt"),
		literalRule(VerdictDeny, "/dst/a.txt"),
		literalRule(VerdictAllow, "/dst"),
	}, nil)
	if got := replaceBlocked.DecideRename(RenameRequest{Source: "/src/a.txt", Dest: "/dst/a.txt", DestExists: true}); got != VerdictDeny {
		t.Errorf("replace with destination Write deny = %s, want deny", got)
	}
}

// Links: a hard link needs full source access plus destination create; a symlink
// needs only destination create.
func TestDecideLinks(t *testing.T) {
	// Source is readable and executable but not writable -> hard link denied,
	// symlink still allowed (symlink needs no source access).
	snapshot := decisionSnapshot(VerdictDeny,
		[]PathRule{literalRule(VerdictAllow, "/src/a.txt")},
		[]PathRule{
			literalRule(VerdictDeny, "/src/a.txt"),
			literalRule(VerdictAllow, "/dst"),
		},
		[]PathRule{literalRule(VerdictAllow, "/src/a.txt")},
	)
	req := LinkRequest{Source: "/src/a.txt", Dest: "/dst/link.txt"}
	if got := snapshot.DecideHardLink(req); got != VerdictDeny {
		t.Errorf("hard link with source write deny = %s, want deny", got)
	}
	if got := snapshot.DecideSymlink(req); got != VerdictAllow {
		t.Errorf("symlink = %s, want allow (needs only destination create)", got)
	}
}
