package fileaccess

import (
	"context"
	"testing"
	"time"
)

// scriptedPrompter returns canned responses keyed by file path.
type scriptedPrompter struct {
	responses map[string]string
	noReply   map[string]bool
	called    int
}

func (p *scriptedPrompter) Prompt(ctx context.Context, e FileEvent, _ time.Duration) (string, bool) {
	p.called++
	if p.noReply[e.Path] {
		return "", false
	}
	r, ok := p.responses[e.Path]
	return r, ok
}

// TestPromptHandlerRuleHitPreseeded covers the bootstrap path: rules
// supplied at construction time via "initial" are used as the per-exe
// seed, so they apply to every (initially-unseen) exe.
func TestPromptHandlerRuleHitPreseeded(t *testing.T) {
	initial := &PathRules{
		Rules:   []PathRule{{Pattern: "/etc/passwd", Verdict: VerdictAllow}},
		Default: VerdictAllow,
	}
	p := &scriptedPrompter{}
	h := NewPromptHandler(p, initial, time.Second)

	// First lookup for /etc/passwd by an unseen exe still has to prompt
	// because we lazy-seed on first appendRule, not on first lookup.
	// That's intentional -- we keep per-exe state out of the map until
	// the user has actually expressed an opinion. So this test checks
	// the explicit-seed-via-appendRule path below.

	// Force seeding by triggering an "always" response.
	p.responses = map[string]string{"/foo": ActionAllowAlways}
	v := h.Decide(context.Background(), &FileEvent{Exe: "/usr/bin/cat", Path: "/foo"})
	if v != VerdictAllow {
		t.Fatalf("first /foo for /usr/bin/cat: got %s, want allow", v)
	}
	if p.called != 1 {
		t.Fatalf("prompter called %d times, want 1", p.called)
	}

	// Now /etc/passwd for /usr/bin/cat should hit the SEEDED rule from
	// the initial set, not prompt.
	v = h.Decide(context.Background(), &FileEvent{Exe: "/usr/bin/cat", Path: "/etc/passwd"})
	if v != VerdictAllow {
		t.Errorf("/etc/passwd for /usr/bin/cat: got %s, want allow (from seeded initial rule)", v)
	}
	if p.called != 1 {
		t.Errorf("prompter called %d times, want 1 (seeded rule should not re-prompt)", p.called)
	}
}

func TestPromptHandlerAllowOnce(t *testing.T) {
	p := &scriptedPrompter{responses: map[string]string{
		"/home/alice/notes.txt": ActionAllow,
	}}
	h := NewPromptHandler(p, nil, time.Second)

	v := h.Decide(context.Background(), &FileEvent{Exe: "/usr/bin/vim", Path: "/home/alice/notes.txt"})
	if v != VerdictAllow {
		t.Errorf("got %s, want allow", v)
	}
	if got := h.RulesFor("/usr/bin/vim"); len(got) != 0 {
		t.Errorf("rule list grew on allow-once: %v", got)
	}
}

func TestPromptHandlerAllowAlwaysPersists(t *testing.T) {
	p := &scriptedPrompter{responses: map[string]string{
		"/home/alice/notes?.txt": ActionAllowAlways,
	}}
	h := NewPromptHandler(p, nil, time.Second)

	e := FileEvent{Exe: "/usr/bin/vim", Path: "/home/alice/notes?.txt"}
	v := h.Decide(context.Background(), &e)
	if v != VerdictAllow {
		t.Fatalf("first call: got %s, want allow", v)
	}
	if got := h.RulesFor("/usr/bin/vim"); len(got) != 1 || got[0].Pattern != "/home/alice/notes\\?.txt" || got[0].Verdict != VerdictAllow {
		t.Fatalf("rule not persisted for /usr/bin/vim: %+v", got)
	}

	// Second call by same exe must hit the rule and not invoke the prompter.
	tripwire := &scriptedPrompter{}
	h.prompter = tripwire
	v = h.Decide(context.Background(), &e)
	if v != VerdictAllow {
		t.Errorf("second call: got %s, want allow (from persisted rule)", v)
	}
	if tripwire.called != 0 {
		t.Errorf("prompter called %d times after persisted rule should match", tripwire.called)
	}

	// The literal question mark must not become a one-character glob.
	tripwire.responses = map[string]string{"/home/alice/notesA.txt": ActionDeny}
	if v = h.Decide(context.Background(), &FileEvent{Exe: "/usr/bin/vim", Path: "/home/alice/notesA.txt"}); v != VerdictDeny {
		t.Errorf("similar glob path: got %s, want deny from prompt", v)
	}
	if tripwire.called != 1 {
		t.Errorf("prompter called %d times for non-literal match, want 1", tripwire.called)
	}
}

// TestPromptHandlerPerExeIsolation is the phase-2.5 win condition: a
// rule for /home/alice/notes.txt persisted under /usr/bin/vim must NOT
// auto-allow that path for /usr/bin/cat.
func TestPromptHandlerPerExeIsolation(t *testing.T) {
	p := &scriptedPrompter{responses: map[string]string{
		"/home/alice/notes.txt": ActionAllowAlways,
	}}
	h := NewPromptHandler(p, nil, time.Second)

	// vim establishes the allow-always rule.
	_ = h.Decide(context.Background(), &FileEvent{Exe: "/usr/bin/vim", Path: "/home/alice/notes.txt"})
	if calls := p.called; calls != 1 {
		t.Fatalf("first prompt count: %d, want 1", calls)
	}

	// cat hits the same path -- should prompt again because cat has no
	// rule of its own.
	p.responses["/home/alice/notes.txt"] = ActionDeny
	v := h.Decide(context.Background(), &FileEvent{Exe: "/usr/bin/cat", Path: "/home/alice/notes.txt"})
	if v != VerdictDeny {
		t.Errorf("cat verdict: got %s, want deny", v)
	}
	if p.called != 2 {
		t.Errorf("prompter called %d times, want 2 (vim then cat -- no cross-exe match)", p.called)
	}

	// vim hits its rule again -- still no second prompt for vim.
	v = h.Decide(context.Background(), &FileEvent{Exe: "/usr/bin/vim", Path: "/home/alice/notes.txt"})
	if v != VerdictAllow {
		t.Errorf("vim second call: got %s, want allow", v)
	}
	if p.called != 2 {
		t.Errorf("prompter called %d times after vim re-access, want 2", p.called)
	}
}

func TestPromptHandlerDenyAlwaysPersists(t *testing.T) {
	p := &scriptedPrompter{responses: map[string]string{
		"/etc/shadow": ActionDenyAlways,
	}}
	h := NewPromptHandler(p, nil, time.Second)

	e := FileEvent{Exe: "/usr/bin/cat", Path: "/etc/shadow"}
	v := h.Decide(context.Background(), &e)
	if v != VerdictDeny {
		t.Errorf("got %s, want deny", v)
	}
	if got := h.RulesFor("/usr/bin/cat"); len(got) != 1 || got[0].Verdict != VerdictDeny {
		t.Errorf("deny rule not persisted: %+v", got)
	}
}

func TestPromptHandlerNoResponseDefaultsDeny(t *testing.T) {
	p := &scriptedPrompter{noReply: map[string]bool{"/home/alice/x": true}}
	h := NewPromptHandler(p, nil, time.Second)

	v := h.Decide(context.Background(), &FileEvent{Exe: "/usr/bin/vim", Path: "/home/alice/x"})
	if v != VerdictDeny {
		t.Errorf("got %s, want deny on no-response", v)
	}
	if got := h.RulesFor("/usr/bin/vim"); len(got) != 0 {
		t.Errorf("rule list grew on no-response: %v", got)
	}
}

func TestPromptHandlerUnknownActionDefaultsDeny(t *testing.T) {
	p := &scriptedPrompter{responses: map[string]string{"/x": "weird-action"}}
	h := NewPromptHandler(p, nil, time.Second)

	v := h.Decide(context.Background(), &FileEvent{Exe: "/bin/sh", Path: "/x"})
	if v != VerdictDeny {
		t.Errorf("got %s, want deny on unknown action", v)
	}
}
