package fileaccess

import (
	"testing"

	"github.com/safing/portmaster/service/profile"
)

// TestRuleScopeOpFoldsOpenToRead documents that opens are governed by the
// Access (Read) rule list: OpOpen folds to OpRead, every other operation is left
// unchanged.
func TestRuleScopeOpFoldsOpenToRead(t *testing.T) {
	if got := ruleScopeOp(OpOpen); got != OpRead {
		t.Fatalf("ruleScopeOp(OpOpen) = %v, want OpRead", got)
	}
	for _, op := range []FileOp{OpRead, OpWrite, OpExec} {
		if got := ruleScopeOp(op); got != op {
			t.Fatalf("ruleScopeOp(%v) = %v, want unchanged", op, got)
		}
	}
}

// TestFileAccessRuleKeyRoutesOperations verifies each supported operation maps to
// its per-operation profile config key (opens folding to the read list), and that
// an unsupported operation fails closed with ok=false rather than defaulting to a
// list.
func TestFileAccessRuleKeyRoutesOperations(t *testing.T) {
	cases := []struct {
		op      FileOp
		wantKey string
	}{
		{OpOpen, profile.CfgOptionFileAccessReadRulesKey},
		{OpRead, profile.CfgOptionFileAccessReadRulesKey},
		{OpWrite, profile.CfgOptionFileAccessWriteRulesKey},
		{OpExec, profile.CfgOptionFileAccessExecRulesKey},
	}
	for _, c := range cases {
		key, ok := fileAccessRuleKey(c.op)
		if !ok || key != c.wantKey {
			t.Fatalf("fileAccessRuleKey(%v) = (%q, %t), want (%q, true)", c.op, key, ok, c.wantKey)
		}
	}
	if key, ok := fileAccessRuleKey(FileOp(99)); ok || key != "" {
		t.Fatalf("fileAccessRuleKey(unsupported) = (%q, %t), want (\"\", false)", key, ok)
	}
}

// TestStoredLiteralRuleRoundTrip verifies the untagged stored form the overlay
// persists survives formatStoredLiteralRule -> ParseRule for both a literal file and
// a literal directory-only rule. The operation is not encoded in the string; it is
// carried by the list the entry lives in.
func TestStoredLiteralRuleRoundTrip(t *testing.T) {
	cases := []struct {
		path      string
		directory bool
		verdict   Verdict
		want      string
	}{
		{"/home/alice/notes?.txt", false, VerdictAllow, `+ file:/home/alice/notes\?.txt`},
		{"/etc/shadow", false, VerdictDeny, `- file:/etc/shadow`},
		{"/var/data", true, VerdictAllow, `+ folder:/var/data`},
	}
	for _, c := range cases {
		kind := ObjectKindFile
		if c.directory {
			kind = ObjectKindFolder
		}
		entry := formatStoredLiteralRule(c.path, kind, c.verdict)
		if entry != c.want {
			t.Fatalf("formatStoredLiteralRule(%q, %t, %s) = %q, want %q", c.path, c.directory, c.verdict, entry, c.want)
		}
		pr, ok := ParseRule(entry)
		if !ok {
			t.Fatalf("ParseRule(%q) failed", entry)
		}
		if pr.Verdict != c.verdict || pr.ObjectKind != kind || !pr.Matches(c.path) || pr.Matches(c.path+"x") {
			t.Fatalf("ParseRule(%q) = %#v, want literal %q dir=%t verdict=%s", entry, pr, c.path, c.directory, c.verdict)
		}
	}
}
