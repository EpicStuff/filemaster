package fileaccess

import (
	"testing"

	"github.com/safing/portmaster/service/profile"
)

// TestScopedRuleTagRoundTrip verifies that the untagged storage form (what the
// per-operation config lists hold) survives the tag -> parse -> split cycle and
// routes back to the operation's config key.
func TestScopedRuleTagRoundTrip(t *testing.T) {
	cases := []struct {
		op       FileOp
		stored   string // untagged, as persisted in a per-operation list
		wantKey  string
		wantExec func(pr PathRule) bool
	}{
		{OpRead, `+ /home/alice/**`, profile.CfgOptionFileAccessReadRulesKey, func(pr PathRule) bool { return !pr.Exact && pr.Pattern == "/home/alice/**" }},
		{OpWrite, `- @"/etc/shadow"`, profile.CfgOptionFileAccessWriteRulesKey, func(pr PathRule) bool { return pr.Exact && pr.Pattern == "/etc/shadow" }},
		{OpExec, `+ /usr/bin/**`, profile.CfgOptionFileAccessExecRulesKey, func(pr PathRule) bool { return !pr.Exact && pr.Pattern == "/usr/bin/**" }},
		{OpWrite, `+ @dir:"/var/data"`, profile.CfgOptionFileAccessWriteRulesKey, func(pr PathRule) bool { return pr.Exact && pr.DirectoryOnly && pr.Pattern == "/var/data" }},
	}
	for _, c := range cases {
		tagged := tagScopedRuleEntry(c.stored, c.op)
		pr, ok := ParseRule(tagged)
		if !ok {
			t.Fatalf("ParseRule(%q) from stored %q failed", tagged, c.stored)
		}
		if !pr.OperationScoped || ruleScopeOp(pr.Operation) != ruleScopeOp(c.op) {
			t.Fatalf("tagged %q parsed to op %v, want %v", tagged, pr.Operation, c.op)
		}
		if !c.wantExec(pr) {
			t.Fatalf("tagged %q parsed to unexpected rule %#v", tagged, pr)
		}
		// The exact forms are what the overlay persists (FormatExactOperationRule);
		// splitting must recover the operation key and the untagged storage form.
		if pr.Exact {
			op, back, ok := splitScopedRuleEntry(tagged)
			if !ok || fileAccessRuleKey(op) != c.wantKey || back != c.stored {
				t.Fatalf("split(%q) = (%v, %q, %t); want key %q and stored %q", tagged, op, back, ok, c.wantKey, c.stored)
			}
		}
	}
}

// TestFileAccessRuleKeyFoldsOpenToRead documents that opens are governed by the
// read-rule list.
func TestFileAccessRuleKeyFoldsOpenToRead(t *testing.T) {
	if fileAccessRuleKey(OpOpen) != profile.CfgOptionFileAccessReadRulesKey {
		t.Fatal("open must route to the read-rule list")
	}
}
