package fileaccess

// DecisionSnapshot is the immutable file-access policy used by a decision
// worker. Rules are parsed while building the snapshot and must never be
// mutated after publication.
type DecisionSnapshot struct {
	ProfileID     string
	Source        string
	DefaultAction uint8
	Rules         PathRules
	Revision      uint64
}

func newDecisionSnapshot(profileID, source string, defaultAction uint8, rawRules []string, revision uint64) *DecisionSnapshot {
	rules := ParseRules(append([]string(nil), rawRules...))
	rules.Rules = append([]PathRule(nil), rules.Rules...)
	return &DecisionSnapshot{
		ProfileID:     profileID,
		Source:        source,
		DefaultAction: defaultAction,
		Rules:         rules,
		Revision:      revision,
	}
}
