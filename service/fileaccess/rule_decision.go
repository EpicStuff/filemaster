package fileaccess

import "path/filepath"

// This file is the filemaster-specific rule-evaluation engine for the shared
// rule model in docs/backend-features.md. It is written ahead of future
// enforcement so a selected backend can wire enforcement to it without
// reworking rule matching. Only the two runtime-observable operations
// (Access and Execute) are produced by any current source; the rest are defined
// and unit-tested here but stay inactive until a supporting backend lands.
//
// It layers on the existing PathRule/PathRules matching (rule.go) rather than
// replacing it: the current runtime open/exec prompt path keeps using
// LookupEvent, while DecideOperation is the verdict-or-default engine future
// non-prompt enforcement (write, create, delete, rename, move, links) will call.

// RuleCategoryStatus describes a user-facing rule category and whether the
// current fanotify release actively enforces it. It is the single source of
// truth for clearly reporting which rules are active, so the API and UI need
// not hardcode the current-release scope.
type RuleCategoryStatus struct {
	Category string
	// Active reports whether the current runtime enforces this category. An
	// inactive category is still presented (or retained) but has no effect until
	// a supporting backend lands.
	Active bool
	Note   string
}

// CurrentRuleModel reports the rule categories the current release presents and
// whether each is actively enforced. Access (file and folder opens) and File
// Execute are enforced; Folder Execute is exposed but inactive; Write is hidden
// and inactive (retained storage only).
func CurrentRuleModel() []RuleCategoryStatus {
	return []RuleCategoryStatus{
		{"File Access", true, "Open a file for reading, writing, or both (FAN_OPEN_PERM)."},
		{"Folder Access", true, "Open the folder (FAN_OPEN_PERM). Listing and traversal are not enforced by the current backend."},
		{"File Execute", true, "Launch the file as a program (FAN_OPEN_EXEC_PERM)."},
		{"Folder Execute", false, "Exposed but inactive; becomes folder traversal with a supporting backend."},
		{"Write", false, "Hidden and retained only; the current backend has no runtime write event."},
	}
}

// DecisionOp is a logical file-access operation the rule engine evaluates. It is
// distinct from FileOp, which is the runtime perm-event kind the fanotify source
// decodes; the current backend only ever produces the Access and Execute
// operations. The remaining operations exist for future supporting backends and
// are never produced by a current runtime source.
type DecisionOp uint8

const (
	// DecisionAccess is opening a file or folder (FAN_OPEN_PERM). Runtime-active.
	DecisionAccess DecisionOp = iota
	// DecisionExecute is launching a file as a program (FAN_OPEN_EXEC_PERM).
	// Runtime-active for files. For folders it means traversal, which is exposed
	// but inactive until a supporting backend lands.
	DecisionExecute
	// DecisionRead is reading contents or metadata. Future backend only.
	DecisionRead
	// DecisionWrite is modifying an existing object's contents or metadata
	// (write, append, truncate, metadata change). Future backend only.
	DecisionWrite
	// DecisionCreate is adding a new entry to a folder. The target may not exist
	// yet. Future backend only.
	DecisionCreate
	// DecisionDelete is removing an entry from a folder. Future backend only.
	DecisionDelete
)

func (op DecisionOp) String() string {
	switch op {
	case DecisionAccess:
		return "access"
	case DecisionExecute:
		return "execute"
	case DecisionRead:
		return "read"
	case DecisionWrite:
		return "write"
	case DecisionCreate:
		return "create"
	case DecisionDelete:
		return "delete"
	default:
		return "unknown"
	}
}

// RuntimeObservable reports whether the current fanotify backend can produce
// this operation. Only Access and Execute are enforced today; every other
// operation is defined for a future supporting backend and must stay inactive at
// runtime.
func (op DecisionOp) RuntimeObservable() bool {
	return op == DecisionAccess || op == DecisionExecute
}

// scopeOp maps a logical operation to the FileOp scope of the rule list that
// governs it, so DecideOperation can reuse PathRule.MatchesEvent. Access and
// Read are governed by the Access (Read) list; Write, Create and Delete by the
// Write list; Execute by the Execute list. Every known operation is enumerated:
// ok is false for any other value so an unrecognized operation fails closed
// instead of inheriting Access/Read policy.
func (op DecisionOp) scopeOp() (FileOp, bool) {
	switch op {
	case DecisionExecute:
		return OpExec, true
	case DecisionWrite, DecisionCreate, DecisionDelete:
		return OpWrite, true
	case DecisionAccess, DecisionRead:
		return OpRead, true
	default:
		return 0, false
	}
}

// entryOp reports whether the operation adds or removes an entry within the
// containing folder. For those operations a rule on the containing folder also
// applies, because the folder entry itself is being changed. Read, Write
// (content), Access and Execute act on the object itself, so only a rule
// matching the object's own path applies -- a nonrecursive parent-folder rule
// does not.
func (op DecisionOp) entryOp() bool {
	return op == DecisionCreate || op == DecisionDelete
}

// ruleAppliesToDecision reports whether rule r governs op on path. The rule's
// list has already been selected for op's operation, so the operation itself is
// not re-checked here. A rule applies if it matches the object's own path, or --
// for entry operations -- if it matches the containing folder.
func ruleAppliesToDecision(r PathRule, path string, op DecisionOp, isDir bool) bool {
	if r.applies(path, isDir) {
		return true
	}
	if op.entryOp() {
		// Create/Delete modify an entry inside the containing folder, so a rule
		// on that folder applies too. The folder is always a directory.
		if r.applies(filepath.Dir(path), true) {
			return true
		}
	}
	return false
}

// DecideOperation returns the verdict for op on path, routing to the operation's
// own rule list and applying the shared matcher over it. On no match the
// snapshot's own DefaultAction decides; the per-list PathRules.Default is never
// consulted, so a directly constructed snapshot cannot fall through to the zero
// Verdict (Allow). An unsupported operation fails closed (Deny) rather than
// borrowing another list's policy.
func (s *DecisionSnapshot) DecideOperation(path string, op DecisionOp, isDir bool) Verdict {
	scope, ok := op.scopeOp()
	if !ok {
		return VerdictDeny
	}
	rules, ok := s.rulesFor(scope)
	if !ok {
		return VerdictDeny
	}
	if verdict, matched := rules.decideOperation(path, op, isDir); matched {
		return verdict
	}
	return verdictFromDefaultAction(s.DefaultAction)
}

// decideOperation evaluates op against this (already operation-selected) list.
// It reports (verdict, true) for the first rule that applies and (0, false) when
// none do; resolving no-match is the snapshot's job, never this list's. File and
// folder rules live in one ordered list and neither outranks the other by kind --
// only list order matters. The DecisionOp is used only for entry-operation
// parent-folder semantics.
func (rs PathRules) decideOperation(path string, op DecisionOp, isDir bool) (Verdict, bool) {
	for _, r := range rs.Rules {
		if ruleAppliesToDecision(r, path, op, isDir) {
			return r.Verdict, true
		}
	}
	return 0, false
}

// RenameRequest bundles the two decisions a rename or move needs. Future
// backend only.
type RenameRequest struct {
	Source      string
	SourceIsDir bool
	Dest        string
	DestIsDir   bool
	// DestExists selects how the destination is evaluated: a nonexistent
	// destination is a Create, an existing one is a Write (replacement).
	DestExists bool
}

// DecideRename evaluates a rename or move as Source Delete AND Destination
// Create-or-Write; both must allow, and the first denying decision determines
// the result.
//
// When the destination already exists the rename replaces it: this destroys the
// existing object's data and rewrites the folder entry, so it needs both the
// existing object's own Write (a parent-folder Allow does not by itself
// authorize destroying it) and the folder-entry replacement (a parent-folder
// Deny can still block it).
func (s *DecisionSnapshot) DecideRename(req RenameRequest) Verdict {
	if s.DecideOperation(req.Source, DecisionDelete, req.SourceIsDir) == VerdictDeny {
		return VerdictDeny
	}
	if !req.DestExists {
		return s.DecideOperation(req.Dest, DecisionCreate, req.DestIsDir)
	}
	if s.DecideOperation(req.Dest, DecisionWrite, req.DestIsDir) == VerdictDeny {
		return VerdictDeny
	}
	return s.DecideOperation(req.Dest, DecisionDelete, req.DestIsDir)
}

// LinkRequest bundles the decisions creating a link needs. Future backend only.
type LinkRequest struct {
	Source      string
	SourceIsDir bool
	Dest        string
	DestIsDir   bool
	DestExists  bool
}

// DecideHardLink evaluates creating a hard link. A hard link is a second name
// for the same inode, so the new name grants every access the source already
// has: it requires Source Read AND Write AND Execute, plus Destination Create
// (and Destination Delete first if the destination already exists). The first
// denying decision determines the result.
func (s *DecisionSnapshot) DecideHardLink(req LinkRequest) Verdict {
	for _, op := range [...]DecisionOp{DecisionRead, DecisionWrite, DecisionExecute} {
		if s.DecideOperation(req.Source, op, req.SourceIsDir) == VerdictDeny {
			return VerdictDeny
		}
	}
	return s.decideDestinationCreate(req)
}

// DecideSymlink evaluates creating a symbolic link. A symlink is an independent
// object that merely stores a path, so creating it grants no access to the
// target and needs only Destination Create (and Destination Delete first if the
// destination already exists). Access through the symlink is governed later by
// the rules for the resolved target path.
func (s *DecisionSnapshot) DecideSymlink(req LinkRequest) Verdict {
	return s.decideDestinationCreate(req)
}

// decideDestinationCreate is the shared destination decision for links: Delete
// the existing destination first if present, then Create.
func (s *DecisionSnapshot) decideDestinationCreate(req LinkRequest) Verdict {
	if req.DestExists {
		if s.DecideOperation(req.Dest, DecisionDelete, req.DestIsDir) == VerdictDeny {
			return VerdictDeny
		}
	}
	return s.DecideOperation(req.Dest, DecisionCreate, req.DestIsDir)
}
