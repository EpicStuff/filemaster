package fileaccess

// DecisionSnapshot is the immutable file-access policy used by a decision
// worker. It holds one parsed rule list per operation plus one shared default
// action. Rules are parsed while building the snapshot and must never be mutated
// after publication; a replacement snapshot is published atomically instead.
type DecisionSnapshot struct {
	ProfileID     string
	Source        string
	DefaultAction uint8

	// Read, Write and Exec are the parsed Access(/Read), Write and Execute rule
	// lists. The operation is carried by which list a rule lives in, not by the
	// rules inside it. Opens (OpOpen) are governed by Read (see ruleScopeOp).
	Read  PathRules
	Write PathRules
	Exec  PathRules

	Revision uint64
}

func newDecisionSnapshot(profileID, source string, defaultAction uint8, lists ruleLists, revision uint64) *DecisionSnapshot {
	return &DecisionSnapshot{
		ProfileID:     profileID,
		Source:        source,
		DefaultAction: defaultAction,
		Read:          ParseRules(lists.read),
		Write:         ParseRules(lists.write),
		Exec:          ParseRules(lists.exec),
		Revision:      revision,
	}
}

// rulesFor centralizes operation -> list routing. Every decision path selects
// its list through here, so an unsupported operation can never silently borrow
// another operation's rules: ok is false for anything that is not an Access,
// Write or Execute operation, and callers must fail closed on it.
func (s *DecisionSnapshot) rulesFor(op FileOp) (PathRules, bool) {
	switch ruleScopeOp(op) {
	case OpRead:
		return s.Read, true
	case OpWrite:
		return s.Write, true
	case OpExec:
		return s.Exec, true
	default:
		return PathRules{}, false
	}
}

// Lookup evaluates op against the operation's rule list using the shared
// matcher. ok is false when the operation is unsupported (the caller must fail
// closed). matched is false when the operation is supported but no rule applied
// (the caller applies the shared default action).
func (s *DecisionSnapshot) Lookup(path string, op FileOp, isDir bool) (verdict Verdict, matched, ok bool) {
	rules, ok := s.rulesFor(op)
	if !ok {
		return 0, false, false
	}
	verdict, matched = rules.match(path, isDir)
	return verdict, matched, true
}
