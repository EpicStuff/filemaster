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

// TestStoredExactRuleRoundTrip verifies the untagged stored form the overlay
// persists survives formatStoredExactRule -> ParseRule for both an exact file and
// an exact directory-only rule. The operation is not encoded in the string; it is
// carried by the list the entry lives in.
func TestStoredExactRuleRoundTrip(t *testing.T) {
	cases := []struct {
		path      string
		directory bool
		verdict   Verdict
		want      string
	}{
		{"/home/alice/notes.txt", false, VerdictAllow, `+ @"/home/alice/notes.txt"`},
		{"/etc/shadow", false, VerdictDeny, `- @"/etc/shadow"`},
		{"/var/data", true, VerdictAllow, `+ @dir:"/var/data"`},
	}
	for _, c := range cases {
		entry := formatStoredExactRule(c.path, c.directory, c.verdict)
		if entry != c.want {
			t.Fatalf("formatStoredExactRule(%q, %t, %s) = %q, want %q", c.path, c.directory, c.verdict, entry, c.want)
		}
		pr, ok := ParseRule(entry)
		if !ok {
			t.Fatalf("ParseRule(%q) failed", entry)
		}
		if !pr.Exact || pr.Pattern != c.path || pr.Verdict != c.verdict || pr.DirectoryOnly != c.directory {
			t.Fatalf("ParseRule(%q) = %#v, want exact %q dir=%t verdict=%s", entry, pr, c.path, c.directory, c.verdict)
		}
	}
}
