package fileaccess

import (
	"strconv"
	"strings"

	"github.com/safing/portmaster/service/profile"
)

// File-access rules are stored in three per-operation profile config lists
// (read / write / execute), mirroring how upstream Portmaster keeps separate
// incoming/outgoing rule lists. The list an entry lives in carries its
// operation, so stored patterns stay untagged and readable. Internally the
// decision engine still consumes a single operation-tagged rule list, so this
// file bridges the two representations: combineScopedRules stamps the operation
// onto each list on the way in, and splitScopedRuleEntry strips it back off when
// a learned Always rule is written to storage.

// ruleScopeOp folds the operation used for rule scoping. FAN_OPEN_PERM opens
// (OpOpen) are governed by the same read-rule list as explicit reads, so both
// resolve to OpRead when matching or persisting rules.
func ruleScopeOp(op FileOp) FileOp {
	if op == OpOpen {
		return OpRead
	}
	return op
}

// fileAccessRuleKey maps an operation to the profile config key whose rule list
// governs it.
func fileAccessRuleKey(op FileOp) string {
	switch ruleScopeOp(op) {
	case OpWrite:
		return profile.CfgOptionFileAccessWriteRulesKey
	case OpExec:
		return profile.CfgOptionFileAccessExecRulesKey
	default:
		return profile.CfgOptionFileAccessReadRulesKey
	}
}

// combineScopedRules stamps each per-operation list with the operation implied
// by the list it lives in and returns a single tagged rule list for parsing.
func combineScopedRules(read, write, exec []string) []string {
	combined := make([]string, 0, len(read)+len(write)+len(exec))
	for _, entry := range read {
		combined = append(combined, tagScopedRuleEntry(entry, OpRead))
	}
	for _, entry := range write {
		combined = append(combined, tagScopedRuleEntry(entry, OpWrite))
	}
	for _, entry := range exec {
		combined = append(combined, tagScopedRuleEntry(entry, OpExec))
	}
	return combined
}

// effectiveScopedRules stamps a profile's own per-operation rule lists, then
// appends the globally-configured rules beneath them. Because the decision
// engine matches first-to-last (PathRules.LookupEvent), the profile's rules
// take precedence; requests they don't match fall through to the global rules
// before hitting the profile's default action. Ported from upstream
// Portmaster's LayeredProfile.MatchEndpoint, which checks each profile layer
// and then falls back to the global rule list (cfgEndpoints).
func effectiveScopedRules(read, write, exec []string) []string {
	rules := combineScopedRules(read, write, exec)
	return append(rules, combineScopedRules(
		profile.GlobalFileAccessReadRules(),
		profile.GlobalFileAccessWriteRules(),
		profile.GlobalFileAccessExecRules(),
	)...)
}

// tagScopedRuleEntry rewrites an untagged stored entry ("<sign> <payload>") into
// the internal operation-tagged form parsed by ParseRule.
func tagScopedRuleEntry(entry string, op FileOp) string {
	if len(entry) < 3 || entry[1] != ' ' {
		return entry
	}
	sign, payload := entry[:2], entry[2:]
	opTag := op.String()
	switch {
	case strings.HasPrefix(payload, "@dir:"):
		return sign + "@dir-" + opTag + ":" + payload[len("@dir:"):]
	case strings.HasPrefix(payload, "@"):
		return sign + "@" + opTag + ":" + payload[len("@"):]
	default:
		return sign + "@" + opTag + ":" + payload
	}
}

// splitScopedRuleEntry reverses an internal operation-tagged entry (as produced
// by FormatExactOperationRule) into the operation and the untagged storage form.
func splitScopedRuleEntry(entry string) (FileOp, string, bool) {
	pr, ok := ParseRule(entry)
	if !ok || !pr.OperationScoped {
		return 0, "", false
	}
	sign := "- "
	if pr.Verdict == VerdictAllow {
		sign = "+ "
	}
	switch {
	case pr.Exact && pr.DirectoryOnly:
		return pr.Operation, sign + "@dir:" + strconv.Quote(pr.Pattern), true
	case pr.Exact:
		return pr.Operation, sign + "@" + strconv.Quote(pr.Pattern), true
	default:
		return pr.Operation, sign + pr.Pattern, true
	}
}
