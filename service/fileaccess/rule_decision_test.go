package fileaccess

import "testing"

// exactRule builds an operation-scoped exact rule, matching how stored file and
// folder rules parse (a literal absolute path scoped to one rule list).
func exactRule(v Verdict, op FileOp, pattern string) PathRule {
	return PathRule{Pattern: pattern, Verdict: v, Exact: true, Operation: op, OperationScoped: true}
}

// globRule builds an operation-scoped glob rule (e.g. "/folder/**").
func globRule(v Verdict, op FileOp, pattern string) PathRule {
	return PathRule{Pattern: pattern, Verdict: v, Operation: op, OperationScoped: true}
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
	rules := PathRules{
		Rules: []PathRule{
			exactRule(VerdictDeny, OpWrite, "/folder"),
			exactRule(VerdictAllow, OpWrite, "/folder/file.txt"),
		},
		Default: VerdictDeny,
	}

	if got := rules.DecideOperation("/folder/file.txt", DecisionWrite, false); got != VerdictAllow {
		t.Errorf("content write = %s, want allow (folder rule must not apply)", got)
	}
	if got := rules.DecideOperation("/folder/file.txt", DecisionDelete, false); got != VerdictDeny {
		t.Errorf("delete = %s, want deny (folder Deny applies first)", got)
	}
}

// Section 3 / 10: reversing the order so the file Allow comes first makes the
// delete allowed -- the first applicable matching rule decides.
func TestDecideDeleteFileRuleFirst(t *testing.T) {
	rules := PathRules{
		Rules: []PathRule{
			exactRule(VerdictAllow, OpWrite, "/folder/file.txt"),
			exactRule(VerdictDeny, OpWrite, "/folder"),
		},
		Default: VerdictDeny,
	}
	if got := rules.DecideOperation("/folder/file.txt", DecisionDelete, false); got != VerdictAllow {
		t.Errorf("delete = %s, want allow (file Allow is first applicable rule)", got)
	}
}

// Section 9: a nonrecursive parent-folder rule does not apply to content writes,
// but a recursive "/folder/**" rule does.
func TestDecideContentWriteRecursiveVsNonrecursive(t *testing.T) {
	nonrecursive := PathRules{
		Rules:   []PathRule{exactRule(VerdictDeny, OpWrite, "/folder")},
		Default: VerdictAllow,
	}
	if got := nonrecursive.DecideOperation("/folder/file.txt", DecisionWrite, false); got != VerdictAllow {
		t.Errorf("content write with nonrecursive folder Deny = %s, want allow (rule must not apply)", got)
	}

	recursive := PathRules{
		Rules:   []PathRule{globRule(VerdictDeny, OpWrite, "/folder/**")},
		Default: VerdictAllow,
	}
	if got := recursive.DecideOperation("/folder/file.txt", DecisionWrite, false); got != VerdictDeny {
		t.Errorf("content write with recursive folder Deny = %s, want deny (rule applies)", got)
	}
}

// Section 11: creating an object can match an exact rule for the (nonexistent)
// destination path, or a rule for the destination folder.
func TestDecideCreate(t *testing.T) {
	exactDest := PathRules{
		Rules:   []PathRule{exactRule(VerdictAllow, OpWrite, "/destination/new-file.txt")},
		Default: VerdictDeny,
	}
	if got := exactDest.DecideOperation("/destination/new-file.txt", DecisionCreate, false); got != VerdictAllow {
		t.Errorf("create with exact destination rule = %s, want allow", got)
	}

	folderDest := PathRules{
		Rules:   []PathRule{exactRule(VerdictAllow, OpWrite, "/destination")},
		Default: VerdictDeny,
	}
	if got := folderDest.DecideOperation("/destination/new-file.txt", DecisionCreate, false); got != VerdictAllow {
		t.Errorf("create with destination folder rule = %s, want allow", got)
	}
}

// Section 3: when no applicable rule matches, the profile default decides.
func TestDecideDefaultFallback(t *testing.T) {
	rules := PathRules{
		Rules:   []PathRule{exactRule(VerdictAllow, OpWrite, "/other")},
		Default: VerdictDeny,
	}
	if got := rules.DecideOperation("/unmatched/path", DecisionCreate, false); got != VerdictDeny {
		t.Errorf("unmatched create = %s, want deny (default)", got)
	}
}

// Operation scoping: a Write-list rule must not decide an Access (Read-list)
// operation, and vice versa.
func TestDecideRespectsListScope(t *testing.T) {
	rules := PathRules{
		Rules:   []PathRule{exactRule(VerdictDeny, OpWrite, "/secret")},
		Default: VerdictAllow,
	}
	if got := rules.DecideOperation("/secret", DecisionAccess, false); got != VerdictAllow {
		t.Errorf("access decided by write-list rule = %s, want allow (default; write rule out of scope)", got)
	}
	if got := rules.DecideOperation("/secret", DecisionWrite, false); got != VerdictDeny {
		t.Errorf("write on /secret = %s, want deny", got)
	}
}

// Access and Execute are the current runtime operations and evaluate as plain
// direct-match, first-match-wins over the shared list.
func TestDecideAccessAndExecute(t *testing.T) {
	rules := PathRules{
		Rules: []PathRule{
			exactRule(VerdictAllow, OpRead, "/home/user/doc.txt"),
			exactRule(VerdictDeny, OpExec, "/usr/bin/danger"),
		},
		Default: VerdictDeny,
	}
	if got := rules.DecideOperation("/home/user/doc.txt", DecisionAccess, false); got != VerdictAllow {
		t.Errorf("access = %s, want allow", got)
	}
	if got := rules.DecideOperation("/usr/bin/danger", DecisionExecute, false); got != VerdictDeny {
		t.Errorf("execute = %s, want deny", got)
	}
	// Folder Access is opening the folder: a direct match on the folder path.
	folderRules := PathRules{
		Rules:   []PathRule{exactRule(VerdictDeny, OpRead, "/private")},
		Default: VerdictAllow,
	}
	if got := folderRules.DecideOperation("/private", DecisionAccess, true); got != VerdictDeny {
		t.Errorf("folder access = %s, want deny", got)
	}
}

// Section 12: rename requires Source Delete AND Destination Create/Write; the
// first denying decision wins.
func TestDecideRename(t *testing.T) {
	// Source delete denied by the source's containing folder -> whole rename
	// denied even though the destination would be creatable.
	sourceDenied := PathRules{
		Rules: []PathRule{
			exactRule(VerdictDeny, OpWrite, "/src"),
			exactRule(VerdictAllow, OpWrite, "/dst"),
		},
		Default: VerdictDeny,
	}
	if got := sourceDenied.DecideRename(RenameRequest{Source: "/src/a.txt", Dest: "/dst/a.txt"}); got != VerdictDeny {
		t.Errorf("rename with source-folder deny = %s, want deny", got)
	}

	// Both source delete and destination create allowed.
	allowed := PathRules{
		Rules: []PathRule{
			exactRule(VerdictAllow, OpWrite, "/src/a.txt"),
			exactRule(VerdictAllow, OpWrite, "/dst"),
		},
		Default: VerdictDeny,
	}
	if got := allowed.DecideRename(RenameRequest{Source: "/src/a.txt", Dest: "/dst/a.txt"}); got != VerdictAllow {
		t.Errorf("rename allowed = %s, want allow", got)
	}

	// Replacing an existing destination: a Deny on the existing destination's own
	// Write blocks the rename even though the folders permit it.
	replaceBlocked := PathRules{
		Rules: []PathRule{
			exactRule(VerdictAllow, OpWrite, "/src/a.txt"),
			exactRule(VerdictDeny, OpWrite, "/dst/a.txt"),
			exactRule(VerdictAllow, OpWrite, "/dst"),
		},
		Default: VerdictDeny,
	}
	if got := replaceBlocked.DecideRename(RenameRequest{Source: "/src/a.txt", Dest: "/dst/a.txt", DestExists: true}); got != VerdictDeny {
		t.Errorf("replace with destination Write deny = %s, want deny", got)
	}
}

// Links: a hard link needs full source access plus destination create; a symlink
// needs only destination create.
func TestDecideLinks(t *testing.T) {
	// Source is readable and executable but not writable -> hard link denied,
	// symlink still allowed (symlink needs no source access).
	rules := PathRules{
		Rules: []PathRule{
			exactRule(VerdictAllow, OpRead, "/src/a.txt"),
			exactRule(VerdictAllow, OpExec, "/src/a.txt"),
			exactRule(VerdictDeny, OpWrite, "/src/a.txt"),
			exactRule(VerdictAllow, OpWrite, "/dst"),
		},
		Default: VerdictDeny,
	}
	req := LinkRequest{Source: "/src/a.txt", Dest: "/dst/link.txt"}
	if got := rules.DecideHardLink(req); got != VerdictDeny {
		t.Errorf("hard link with source write deny = %s, want deny", got)
	}
	if got := rules.DecideSymlink(req); got != VerdictAllow {
		t.Errorf("symlink = %s, want allow (needs only destination create)", got)
	}
}
