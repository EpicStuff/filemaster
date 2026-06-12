package fileaccess

import (
	"context"
	"testing"
)

func TestMatchPathPattern(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		// Exact.
		{"/etc/passwd", "/etc/passwd", true},
		{"/etc/passwd", "/etc/passwd.bak", false},
		{"/etc/passwd", "/etc/shadow", false},

		// /** recursive.
		{"/home/alice/Documents/**", "/home/alice/Documents", true},
		{"/home/alice/Documents/**", "/home/alice/Documents/a.txt", true},
		{"/home/alice/Documents/**", "/home/alice/Documents/sub/dir/file", true},
		{"/home/alice/Documents/**", "/home/alice/Documentsx", false},
		{"/home/alice/Documents/**", "/home/alice/Other", false},

		// Single-segment glob.
		{"/etc/*.conf", "/etc/foo.conf", true},
		{"/etc/*.conf", "/etc/sub/foo.conf", false}, // * does not cross /
		{"/etc/*", "/etc/passwd", true},
		// filepath.Match: "*" matches any sequence including empty, so
		// "/etc/*" matches "/etc/". Documented quirk, not a bug.
		{"/etc/*", "/etc/", true},
	}
	for _, c := range cases {
		if got := matchPathPattern(c.pattern, c.path); got != c.want {
			t.Errorf("matchPathPattern(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestPathRulesDecide(t *testing.T) {
	rs := PathRules{
		Rules: []PathRule{
			{Pattern: "/etc/shadow", Verdict: VerdictDeny},
			{Pattern: "/etc/**", Verdict: VerdictAllow},
			{Pattern: "/home/alice/secret/**", Verdict: VerdictDeny},
		},
		Default: VerdictAllow,
	}

	cases := []struct {
		path string
		want Verdict
	}{
		{"/etc/shadow", VerdictDeny},                   // explicit deny wins despite later allow
		{"/etc/passwd", VerdictAllow},                  // caught by /etc/**
		{"/etc/ssh/sshd_config", VerdictAllow},         // caught by /etc/**
		{"/home/alice/secret/notes.txt", VerdictDeny},  // caught by secret/**
		{"/home/alice/photos/x.jpg", VerdictAllow},     // default
		{"/var/log/system.log", VerdictAllow},          // default
	}
	for _, c := range cases {
		got := rs.Decide(context.Background(), FileEvent{Path: c.path, Op: OpOpen})
		if got != c.want {
			t.Errorf("Decide(%q) = %s, want %s", c.path, got, c.want)
		}
	}
}

// TestPathRulesAsHandler proves PathRules can be plugged into a Source.
func TestPathRulesAsHandler(t *testing.T) {
	rs := PathRules{
		Rules:   []PathRule{{Pattern: "/etc/**", Verdict: VerdictDeny}},
		Default: VerdictAllow,
	}
	var _ Handler = rs // compile-time check
	_ = rs.Decide(context.Background(), FileEvent{Path: "/etc/passwd"})
}
