package fileaccess

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeRuleStore is an in-memory RuleStore for tests.
type fakeRuleStore struct {
	id       string
	rules    []string
	appendMu sync.Mutex
}

func (s *fakeRuleStore) ID() string {
	return s.id
}

func (s *fakeRuleStore) Rules() []string {
	s.appendMu.Lock()
	defer s.appendMu.Unlock()
	out := make([]string, len(s.rules))
	copy(out, s.rules)
	return out
}

func (s *fakeRuleStore) AppendRule(entry string) error {
	s.appendMu.Lock()
	defer s.appendMu.Unlock()
	// Mirror Profile.AddEndpoint semantics: prepend so most-recent wins.
	s.rules = append([]string{entry}, s.rules...)
	return nil
}

// fakeLookup keys RuleStores by PID. Pid 0 returns an error.
type fakeLookup struct {
	stores map[int32]*fakeRuleStore
	err    error
}

func (l *fakeLookup) Lookup(_ context.Context, pid int32) (RuleStore, error) {
	if l.err != nil {
		return nil, l.err
	}
	s, ok := l.stores[pid]
	if !ok {
		return nil, ErrNoProfile
	}
	return s, nil
}

func TestParseAndFormatRuleRoundTrip(t *testing.T) {
	cases := []struct {
		pattern string
		v       Verdict
		want    string
	}{
		{"/etc/passwd", VerdictAllow, "+ /etc/passwd"},
		{"/etc/shadow", VerdictDeny, "- /etc/shadow"},
		{"/home/alice/Documents/**", VerdictAllow, "+ /home/alice/Documents/**"},
	}
	for _, c := range cases {
		got := FormatRule(c.pattern, c.v)
		if got != c.want {
			t.Errorf("FormatRule(%q, %s) = %q, want %q", c.pattern, c.v, got, c.want)
		}
		r, ok := ParseRule(got)
		if !ok {
			t.Errorf("ParseRule(%q) = !ok, want ok", got)
			continue
		}
		if r.Pattern != c.pattern || r.Verdict != c.v {
			t.Errorf("ParseRule(%q) = {%q, %s}, want {%q, %s}", got, r.Pattern, r.Verdict, c.pattern, c.v)
		}
	}
}

func TestParseRuleRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "+", "+a", "x /foo", "/foo", "++ /foo"} {
		if _, ok := ParseRule(bad); ok {
			t.Errorf("ParseRule(%q) parsed unexpectedly", bad)
		}
	}
}

// TestProfileHandlerRuleHit: a rule stored in the profile shortcuts
// the prompter.
func TestProfileHandlerRuleHit(t *testing.T) {
	store := &fakeRuleStore{
		id:    "profile-A",
		rules: []string{"+ /etc/passwd"},
	}
	lookup := &fakeLookup{stores: map[int32]*fakeRuleStore{42: store}}
	p := &scriptedPrompter{}

	h := NewProfileHandler(lookup, p, nil, time.Second, nopLogger{})
	v := h.Decide(context.Background(), FileEvent{PID: 42, Path: "/etc/passwd"})
	if v != VerdictAllow {
		t.Errorf("got %s, want allow", v)
	}
	if p.called != 0 {
		t.Errorf("prompter called %d times, want 0", p.called)
	}
}

// TestProfileHandlerAllowAlwaysPersistsInProfile: an allow-always
// response writes the rule back into the profile's store, and the
// second access of the same path goes straight to the rule.
func TestProfileHandlerAllowAlwaysPersistsInProfile(t *testing.T) {
	store := &fakeRuleStore{id: "profile-B"}
	lookup := &fakeLookup{stores: map[int32]*fakeRuleStore{99: store}}

	p := &scriptedPrompter{responses: map[string]string{
		"/home/alice/notes.txt": ActionAllowAlways,
	}}
	h := NewProfileHandler(lookup, p, nil, time.Second, nopLogger{})

	e := FileEvent{PID: 99, Exe: "/usr/bin/vim", Path: "/home/alice/notes.txt"}
	v := h.Decide(context.Background(), e)
	if v != VerdictAllow {
		t.Fatalf("first call: got %s, want allow", v)
	}
	if got := store.Rules(); len(got) != 1 || got[0] != "+ /home/alice/notes.txt" {
		t.Fatalf("rule not persisted in profile store: %v", got)
	}

	// Tripwire on the second call: prompter must not be invoked.
	tripwire := &scriptedPrompter{}
	h.prompter = tripwire
	v = h.Decide(context.Background(), e)
	if v != VerdictAllow {
		t.Errorf("second call: got %s, want allow (from persisted rule)", v)
	}
	if tripwire.called != 0 {
		t.Errorf("prompter called %d times on second access; persisted rule should have matched", tripwire.called)
	}
}

// TestProfileHandlerPerProfileIsolation: two profiles maintain
// independent rule lists, mirroring the per-app guarantee.
func TestProfileHandlerPerProfileIsolation(t *testing.T) {
	storeVim := &fakeRuleStore{id: "vim"}
	storeCat := &fakeRuleStore{id: "cat"}
	lookup := &fakeLookup{stores: map[int32]*fakeRuleStore{
		100: storeVim,
		101: storeCat,
	}}
	p := &scriptedPrompter{responses: map[string]string{
		"/home/alice/notes.txt": ActionAllowAlways,
	}}
	h := NewProfileHandler(lookup, p, nil, time.Second, nopLogger{})

	if v := h.Decide(context.Background(), FileEvent{PID: 100, Path: "/home/alice/notes.txt"}); v != VerdictAllow {
		t.Fatalf("vim: got %s, want allow", v)
	}
	if p.called != 1 {
		t.Fatalf("prompter calls after vim: %d, want 1", p.called)
	}

	// cat for the same path -- vim's rule does NOT carry across.
	p.responses["/home/alice/notes.txt"] = ActionDeny
	if v := h.Decide(context.Background(), FileEvent{PID: 101, Path: "/home/alice/notes.txt"}); v != VerdictDeny {
		t.Errorf("cat: got %s, want deny", v)
	}
	if p.called != 2 {
		t.Errorf("prompter calls after cat: %d, want 2", p.called)
	}

	if len(storeVim.Rules()) != 1 || len(storeCat.Rules()) != 0 {
		t.Errorf("per-profile rule counts wrong: vim=%d cat=%d", len(storeVim.Rules()), len(storeCat.Rules()))
	}
}

// TestProfileHandlerFallback: lookup error routes the event to the
// fallback handler instead of default-denying.
func TestProfileHandlerFallback(t *testing.T) {
	fallback := HandlerFunc(func(_ context.Context, _ FileEvent) Verdict { return VerdictAllow })
	lookup := &fakeLookup{err: errors.New("boom")}
	p := &scriptedPrompter{}

	h := NewProfileHandler(lookup, p, fallback, time.Second, nopLogger{})

	v := h.Decide(context.Background(), FileEvent{PID: 1, Path: "/etc/anything"})
	if v != VerdictAllow {
		t.Errorf("got %s, want allow (from fallback)", v)
	}
}

// TestProfileHandlerNoProfileFallback: ErrNoProfile is the same path
// as any other lookup error -- delegate to the fallback.
func TestProfileHandlerNoProfileFallback(t *testing.T) {
	fallbackCalled := false
	fallback := HandlerFunc(func(_ context.Context, _ FileEvent) Verdict {
		fallbackCalled = true
		return VerdictDeny
	})
	lookup := &fakeLookup{stores: map[int32]*fakeRuleStore{}}
	h := NewProfileHandler(lookup, &scriptedPrompter{}, fallback, time.Second, nopLogger{})

	_ = h.Decide(context.Background(), FileEvent{PID: 999, Path: "/anywhere"})
	if !fallbackCalled {
		t.Error("fallback was not invoked on ErrNoProfile")
	}
}
