package fileaccess

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/safing/portmaster/service/profile"
)

// fakeRuleStore is an in-memory RuleStore for tests.
type fakeRuleStore struct {
	id       string
	appendMu sync.Mutex
	appended []string
}

func (s *fakeRuleStore) ID() string { return s.id }

func (s *fakeRuleStore) AppendRule(entry string) error {
	s.appendMu.Lock()
	defer s.appendMu.Unlock()
	s.appended = append(s.appended, entry)
	return nil
}

// fakeProfile bundles what a fake "profile" needs to look like to the
// lookup: an ID, the current rule strings, a default action, and the
// resolved exe path. fakeLookup composes a LookupResult from it.
type fakeProfile struct {
	id     string
	exe    string
	rules  []string
	defAct uint8 // profile.DefaultAction* constants
}

// fakeLookup keys fakeProfiles by PID. err != nil short-circuits to
// the fallback regardless.
type fakeLookup struct {
	profiles map[int32]*fakeProfile
	err      error

	mu     sync.Mutex
	stores map[int32]*fakeRuleStore
}

func (l *fakeLookup) Lookup(_ context.Context, pid int32) (LookupResult, error) {
	if l.err != nil {
		return LookupResult{}, l.err
	}
	fp, ok := l.profiles[pid]
	if !ok {
		return LookupResult{Path: "", DefaultAction: profile.DefaultActionAsk}, ErrNoProfile
	}

	l.mu.Lock()
	if l.stores == nil {
		l.stores = make(map[int32]*fakeRuleStore)
	}
	store, ok := l.stores[pid]
	if !ok {
		store = &fakeRuleStore{id: fp.id}
		l.stores[pid] = store
	}
	// Merge any persisted entries that AppendRule has recorded into the
	// next-lookup parsed view, mirroring how the real binding re-reads
	// from the live profile.
	allRules := append([]string(nil), store.appended...)
	allRules = append(allRules, fp.rules...)
	l.mu.Unlock()

	return LookupResult{
		Path:          fp.exe,
		Store:         store,
		ParsedRules:   ParseRules(allRules),
		DefaultAction: fp.defAct,
	}, nil
}

func (l *fakeLookup) appendedFor(pid int32) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stores == nil {
		return nil
	}
	if s, ok := l.stores[pid]; ok {
		return append([]string(nil), s.appended...)
	}
	return nil
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

// TestProfileHandlerRuleHit: a rule present in the parsed view
// shortcuts the prompter.
func TestProfileHandlerRuleHit(t *testing.T) {
	lookup := &fakeLookup{profiles: map[int32]*fakeProfile{
		42: {
			id:     "profile-A",
			rules:  []string{"+ /etc/passwd"},
			defAct: profile.DefaultActionAsk,
		},
	}}
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
	lookup := &fakeLookup{profiles: map[int32]*fakeProfile{
		99: {id: "profile-B", defAct: profile.DefaultActionAsk},
	}}
	p := &scriptedPrompter{responses: map[string]string{
		"/home/alice/notes.txt": ActionAllowAlways,
	}}
	h := NewProfileHandler(lookup, p, nil, time.Second, nopLogger{})

	e := FileEvent{PID: 99, Path: "/home/alice/notes.txt"}
	v := h.Decide(context.Background(), e)
	if v != VerdictAllow {
		t.Fatalf("first call: got %s, want allow", v)
	}
	got := lookup.appendedFor(99)
	if len(got) != 1 || got[0] != "+ /home/alice/notes.txt" {
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
// independent rule lists.
func TestProfileHandlerPerProfileIsolation(t *testing.T) {
	lookup := &fakeLookup{profiles: map[int32]*fakeProfile{
		100: {id: "vim", defAct: profile.DefaultActionAsk},
		101: {id: "cat", defAct: profile.DefaultActionAsk},
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

	if len(lookup.appendedFor(100)) != 1 || len(lookup.appendedFor(101)) != 0 {
		t.Errorf("per-profile rule counts wrong: vim=%d cat=%d",
			len(lookup.appendedFor(100)), len(lookup.appendedFor(101)))
	}
}

// TestProfileHandlerDefaultActionPermit: profile says "permit by
// default" -> no rule + no prompt, allow.
func TestProfileHandlerDefaultActionPermit(t *testing.T) {
	lookup := &fakeLookup{profiles: map[int32]*fakeProfile{
		1: {id: "permit-app", defAct: profile.DefaultActionPermit},
	}}
	p := &scriptedPrompter{}
	h := NewProfileHandler(lookup, p, nil, time.Second, nopLogger{})

	v := h.Decide(context.Background(), FileEvent{PID: 1, Path: "/anything"})
	if v != VerdictAllow {
		t.Errorf("got %s, want allow (DefaultActionPermit)", v)
	}
	if p.called != 0 {
		t.Errorf("prompter called %d times; permit should never prompt", p.called)
	}
}

// TestProfileHandlerDefaultActionBlock: profile says "block by
// default" -> no rule + no prompt, deny.
func TestProfileHandlerDefaultActionBlock(t *testing.T) {
	lookup := &fakeLookup{profiles: map[int32]*fakeProfile{
		1: {id: "block-app", defAct: profile.DefaultActionBlock},
	}}
	p := &scriptedPrompter{}
	h := NewProfileHandler(lookup, p, nil, time.Second, nopLogger{})

	v := h.Decide(context.Background(), FileEvent{PID: 1, Path: "/anything"})
	if v != VerdictDeny {
		t.Errorf("got %s, want deny (DefaultActionBlock)", v)
	}
	if p.called != 0 {
		t.Errorf("prompter called %d times; block should never prompt", p.called)
	}
}

// TestProfileHandlerDefaultActionAskFiresPrompter: explicit ask AND
// unset (NotSet) both fall through to the prompter.
func TestProfileHandlerDefaultActionAskFiresPrompter(t *testing.T) {
	for name, defAct := range map[string]uint8{
		"DefaultActionAsk":    profile.DefaultActionAsk,
		"DefaultActionNotSet": profile.DefaultActionNotSet,
	} {
		t.Run(name, func(t *testing.T) {
			lookup := &fakeLookup{profiles: map[int32]*fakeProfile{
				1: {id: "ask-app", defAct: defAct},
			}}
			p := &scriptedPrompter{responses: map[string]string{
				"/anything": ActionAllow,
			}}
			h := NewProfileHandler(lookup, p, nil, time.Second, nopLogger{})

			v := h.Decide(context.Background(), FileEvent{PID: 1, Path: "/anything"})
			if v != VerdictAllow {
				t.Errorf("got %s, want allow", v)
			}
			if p.called != 1 {
				t.Errorf("prompter calls: %d, want 1", p.called)
			}
		})
	}
}

// TestProfileHandlerFallbackPopulatesExe: a lookup that errors still
// returns a Path; the handler propagates it onto the event so the
// fallback can key by exe even though no profile resolved.
func TestProfileHandlerFallbackPopulatesExe(t *testing.T) {
	var seenExe string
	fallback := HandlerFunc(func(_ context.Context, e FileEvent) Verdict {
		seenExe = e.Exe
		return VerdictAllow
	})
	lookup := &fakeLookup{
		err: errors.New("transient"),
	}
	h := NewProfileHandler(lookup, &scriptedPrompter{}, fallback, time.Second, nopLogger{})

	_ = h.Decide(context.Background(), FileEvent{PID: 1, Path: "/x"})
	if seenExe != "" {
		t.Errorf("fallback saw exe %q; lookup error means no Path was resolved", seenExe)
	}
}

// TestProfileHandlerNoProfilePopulatesExeAndFallback: ErrNoProfile is
// the same path as any other no-profile result -- delegate to the
// fallback, and propagate the resolved exe so the fallback can key by it.
func TestProfileHandlerNoProfilePopulatesExeAndFallback(t *testing.T) {
	var seen FileEvent
	fallback := HandlerFunc(func(_ context.Context, e FileEvent) Verdict {
		seen = e
		return VerdictDeny
	})
	// The fake lookup returns no profile for unknown PIDs but doesn't
	// give an exe back. To exercise the propagation, give it a known
	// entry with Path but no rule data.
	lookup := &fakeLookup{profiles: map[int32]*fakeProfile{}}
	h := NewProfileHandler(lookup, &scriptedPrompter{}, fallback, time.Second, nopLogger{})

	v := h.Decide(context.Background(), FileEvent{PID: 999, Path: "/x"})
	if v != VerdictDeny {
		t.Errorf("got %s, want deny (from fallback)", v)
	}
	if seen.Path != "/x" {
		t.Errorf("fallback saw path %q, want /x", seen.Path)
	}
}
