package fileaccess

import "github.com/safing/portmaster/service/profile"

// File-access rules are stored in three per-operation profile config lists
// (read / write / execute), mirroring how upstream Portmaster keeps separate
// incoming/outgoing rule lists. The list an entry lives in carries its
// operation, so stored patterns stay untagged and each list is parsed
// independently into its own PathRules (see DecisionSnapshot). This file holds
// the shared operation-to-list routing that every decision and persistence path
// funnels through, plus the assembly of a profile's lists with the global rules
// appended beneath them.

// ruleScopeOp folds a runtime operation to the operation whose rule list governs
// it. FAN_OPEN_PERM opens (OpOpen) are governed by the same Access(/Read) list
// as explicit reads, so both resolve to OpRead when matching or persisting.
func ruleScopeOp(op FileOp) FileOp {
	if op == OpOpen {
		return OpRead
	}
	return op
}

// fileAccessListOp folds an operation to the operation whose rule list governs
// it -- OpRead, OpWrite or OpExec -- reporting ok=false for anything else. It is
// the single routing primitive every decision and persistence path funnels
// through (DecisionSnapshot.rulesFor, fileAccessRuleKey, the fallback
// PromptHandler, and the permanent-rule overlay), so an unsupported operation
// can never silently select the Access, Write or Execute list by accident:
// callers must fail closed on ok=false rather than defaulting to a list.
func fileAccessListOp(op FileOp) (FileOp, bool) {
	switch ruleScopeOp(op) {
	case OpRead:
		return OpRead, true
	case OpWrite:
		return OpWrite, true
	case OpExec:
		return OpExec, true
	default:
		return 0, false
	}
}

// fileAccessRuleKey maps an operation to the profile config key whose rule list
// governs it. It is the persistence-side counterpart to
// DecisionSnapshot.rulesFor: both route through fileAccessListOp so an operation
// resolves to the same list on the decision and storage paths, and both fail
// closed (ok=false) rather than defaulting an unsupported operation to a list.
func fileAccessRuleKey(op FileOp) (string, bool) {
	listOp, ok := fileAccessListOp(op)
	if !ok {
		return "", false
	}
	switch listOp {
	case OpWrite:
		return profile.CfgOptionFileAccessWriteRulesKey, true
	case OpExec:
		return profile.CfgOptionFileAccessExecRulesKey, true
	default:
		return profile.CfgOptionFileAccessReadRulesKey, true
	}
}

// ruleLists gathers a profile's three per-operation rule lists in their untagged
// stored form, ready for snapshot construction.
type ruleLists struct {
	read  []string
	write []string
	exec  []string
}

// scopedRuleLists appends the globally-configured rules for each operation
// beneath the profile's own list for that operation. Because the decision engine
// matches first-to-last, the profile's rules take precedence; requests they
// don't match fall through to the global rules before hitting the profile's
// default action. Ported from upstream Portmaster's LayeredProfile.MatchEndpoint,
// which checks each profile layer and then falls back to the global rule list.
func scopedRuleLists(read, write, exec []string) ruleLists {
	globalRead, globalWrite, globalExec := profile.GlobalFileAccessRules()

	return ruleLists{
		read:  appendGlobalRules(read, globalRead),
		write: appendGlobalRules(write, globalWrite),
		exec:  appendGlobalRules(exec, globalExec),
	}
}

func appendGlobalRules(profileRules, globalRules []string) []string {
	combined := make([]string, 0, len(profileRules)+len(globalRules))
	combined = append(combined, profileRules...)
	combined = append(combined, globalRules...)
	return combined
}

func sameRuleLists(left, right ruleLists) bool {
	return sameRuleEntries(left.read, right.read) &&
		sameRuleEntries(left.write, right.write) &&
		sameRuleEntries(left.exec, right.exec)
}
