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
}

func (p *scriptedPrompter) Prompt(ctx context.Context, e FileEvent, _ time.Duration) (string, bool) {
	if p.noReply[e.Path] {
		// Simulate user not responding -- handler should default-deny.
		return "", false
	}
	r, ok := p.responses[e.Path]
	return r, ok
}

func TestPromptHandlerRuleHit(t *testing.T) {
	rules := &PathRules{
		Rules:   []PathRule{{Pattern: "/etc/passwd", Verdict: VerdictAllow}},
		Default: VerdictAllow,
	}
	p := &scriptedPrompter{}
	h := NewPromptHandler(p, rules, time.Second)

	v := h.Decide(context.Background(), FileEvent{Path: "/etc/passwd"})
	if v != VerdictAllow {
		t.Errorf("Decide /etc/passwd: got %s, want allow (rule hit, no prompt)", v)
	}
	if len(h.Rules()) != 1 {
		t.Errorf("rule list mutated unexpectedly: %v", h.Rules())
	}
}

func TestPromptHandlerAllowOnce(t *testing.T) {
	p := &scriptedPrompter{responses: map[string]string{
		"/home/alice/notes.txt": ActionAllow,
	}}
	h := NewPromptHandler(p, nil, time.Second)

	v := h.Decide(context.Background(), FileEvent{Path: "/home/alice/notes.txt"})
	if v != VerdictAllow {
		t.Errorf("got %s, want allow", v)
	}
	// "Allow once" must NOT persist a rule.
	if got := h.Rules(); len(got) != 0 {
		t.Errorf("rule list grew on allow-once: %v", got)
	}
}

func TestPromptHandlerAllowAlwaysPersists(t *testing.T) {
	p := &scriptedPrompter{responses: map[string]string{
		"/home/alice/notes.txt": ActionAllowAlways,
	}}
	h := NewPromptHandler(p, nil, time.Second)

	v := h.Decide(context.Background(), FileEvent{Path: "/home/alice/notes.txt"})
	if v != VerdictAllow {
		t.Fatalf("first call: got %s, want allow", v)
	}
	if got := h.Rules(); len(got) != 1 || got[0].Pattern != "/home/alice/notes.txt" || got[0].Verdict != VerdictAllow {
		t.Fatalf("rule not persisted: %+v", got)
	}

	// Second call must hit the rule and not invoke the prompter -- swap
	// in a prompter that fails the test if called.
	tripwire := &scriptedPrompter{}
	h.prompter = tripwire
	v = h.Decide(context.Background(), FileEvent{Path: "/home/alice/notes.txt"})
	if v != VerdictAllow {
		t.Errorf("second call: got %s, want allow (from persisted rule)", v)
	}
}

func TestPromptHandlerDenyAlwaysPersists(t *testing.T) {
	p := &scriptedPrompter{responses: map[string]string{
		"/etc/shadow": ActionDenyAlways,
	}}
	h := NewPromptHandler(p, nil, time.Second)

	v := h.Decide(context.Background(), FileEvent{Path: "/etc/shadow"})
	if v != VerdictDeny {
		t.Errorf("got %s, want deny", v)
	}
	if got := h.Rules(); len(got) != 1 || got[0].Verdict != VerdictDeny {
		t.Errorf("deny rule not persisted: %+v", got)
	}
}

func TestPromptHandlerNoResponseDefaultsDeny(t *testing.T) {
	p := &scriptedPrompter{noReply: map[string]bool{"/home/alice/x": true}}
	h := NewPromptHandler(p, nil, time.Second)

	v := h.Decide(context.Background(), FileEvent{Path: "/home/alice/x"})
	if v != VerdictDeny {
		t.Errorf("got %s, want deny on no-response", v)
	}
	if got := h.Rules(); len(got) != 0 {
		t.Errorf("rule list grew on no-response: %v", got)
	}
}

func TestPromptHandlerUnknownActionDefaultsDeny(t *testing.T) {
	p := &scriptedPrompter{responses: map[string]string{"/x": "weird-action"}}
	h := NewPromptHandler(p, nil, time.Second)

	v := h.Decide(context.Background(), FileEvent{Path: "/x"})
	if v != VerdictDeny {
		t.Errorf("got %s, want deny on unknown action", v)
	}
}
