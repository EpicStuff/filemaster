package fileaccess

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/safing/portmaster/service/profile"
)

// fakeRuleStore is an in-memory RuleStore for tests. It records the operation
// each entry was routed to so tests can assert per-operation persistence.
type fakeRuleStore struct {
	id         string
	appendMu   sync.Mutex
	appended   []string
	appendedOp []FileOp
	errs       []error
}

func (s *fakeRuleStore) ID() string { return s.id }

func (s *fakeRuleStore) AppendRule(op FileOp, entry string) error {
	s.appendMu.Lock()
	defer s.appendMu.Unlock()
	s.appended = append(s.appended, entry)
	s.appendedOp = append(s.appendedOp, op)
	if len(s.errs) != 0 {
		err := s.errs[0]
		s.errs = s.errs[1:]
		return err
	}
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

// fakeLookup keys fakeProfiles by PID. An injected error models a broken
// ProfileLookup, which the handler denies defensively.
type fakeLookup struct {
	profiles map[int32]*fakeProfile
	err      error

	mu     sync.Mutex
	stores map[int32]*fakeRuleStore
	calls  int
}

func (l *fakeLookup) Lookup(_ context.Context, pid int32) (LookupResult, error) {
	l.mu.Lock()
	l.calls++
	l.mu.Unlock()
	if l.err != nil {
		return LookupResult{}, l.err
	}
	fp, ok := l.profiles[pid]
	if !ok {
		return LookupResult{DefaultAction: profile.DefaultActionAsk}, nil
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
	// from the live profile. Learned entries precede the profile's own seed
	// rules (first match wins) and are routed into the same per-operation list
	// the store persisted them to; the profile's seed rules are read rules.
	var lists ruleLists
	for i, entry := range store.appended {
		switch ruleScopeOp(store.appendedOp[i]) {
		case OpWrite:
			lists.write = append(lists.write, entry)
		case OpExec:
			lists.exec = append(lists.exec, entry)
		default:
			lists.read = append(lists.read, entry)
		}
	}
	lists.read = append(lists.read, fp.rules...)
	l.mu.Unlock()

	return LookupResult{
		Path:          fp.exe,
		Store:         store,
		Snapshot:      newDecisionSnapshot(fp.id, "", fp.defAct, lists, 1),
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

func (l *fakeLookup) appendedOpFor(pid int32) []FileOp {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stores == nil {
		return nil
	}
	if s, ok := l.stores[pid]; ok {
		return append([]FileOp(nil), s.appendedOp...)
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

func TestQualifiedRuleParseAndFormatRoundTrip(t *testing.T) {
	cases := []struct {
		entry   string
		pattern string
		kind    ObjectKind
	}{
		{"+ /tmp/item", "/tmp/item", ObjectKindAny},
		{"+ file:/tmp/item", "/tmp/item", ObjectKindFile},
		{"- folder:/tmp/item", "/tmp/item", ObjectKindFolder},
		{"+ file:/opt/app/*", "/opt/app/*", ObjectKindFile},
		{"+ folder:/opt/app/**", "/opt/app/**", ObjectKindFolder},
		{`+ file:/tmp/exact\?.txt`, `/tmp/exact\?.txt`, ObjectKindFile},
		{`- folder:/tmp/exact-dir`, "/tmp/exact-dir", ObjectKindFolder},
	}
	for _, c := range cases {
		rule, ok := ParseRule(c.entry)
		if !ok {
			t.Fatalf("ParseRule(%q) failed", c.entry)
		}
		if rule.Pattern != c.pattern || rule.ObjectKind != c.kind {
			t.Fatalf("ParseRule(%q) = %#v", c.entry, rule)
		}
	}

	if got := FormatRule("folder:/var/cache/*", VerdictAllow); got != "+ folder:/var/cache/*" {
		t.Fatalf("FormatRule qualified glob = %q", got)
	}
	if got := FormatLiteralRuleForKind("/tmp/exact?.txt", ObjectKindFile, VerdictAllow); got != `+ file:/tmp/exact\?.txt` {
		t.Fatalf("FormatLiteralRuleForKind file = %q", got)
	}
	if got := FormatLiteralRuleForKind("/tmp/exact-dir", ObjectKindFolder, VerdictDeny); got != `- folder:/tmp/exact-dir` {
		t.Fatalf("FormatLiteralRuleForKind folder = %q", got)
	}
	if _, ok := ParseRule(`+ @"/tmp/legacy"`); ok {
		t.Fatal("legacy @ exact syntax parsed unexpectedly")
	}
}

func TestOperationLiteralRuleRoundTripAndProfileDecision(t *testing.T) {
	// The operation is no longer encoded in the stored string; it is carried by
	// the list the entry lives in. The stored form is untagged.
	entry := formatStoredLiteralRule("/tmp/data?", ObjectKindAny, VerdictAllow)
	rule, ok := ParseRule(entry)
	if !ok || rule.ObjectKind != ObjectKindAny || !rule.Matches("/tmp/data?") || rule.Matches("/tmp/datax") {
		t.Fatalf("parsed literal rule = %#v, ok=%t", rule, ok)
	}
	// Placed in the read list, the rule governs opens (which fold to reads) and
	// reads, but nothing in the write list matches.
	snapshot := newDecisionSnapshot("profile", "local", 2, ruleLists{read: []string{entry}}, 1)
	if _, matched, ok := snapshot.Lookup("/tmp/data?", OpOpen, false); !ok || !matched {
		t.Fatal("read rule did not match open (opens are governed by read rules)")
	}
	if _, matched, ok := snapshot.Lookup("/tmp/data?", OpRead, false); !ok || !matched {
		t.Fatal("read rule did not match read")
	}
	if _, matched, ok := snapshot.Lookup("/tmp/data?", OpWrite, false); !ok || matched {
		t.Fatal("read rule leaked into write")
	}

	directoryEntry := formatStoredLiteralRule("/tmp/folder", ObjectKindFolder, VerdictDeny)
	directoryRule, ok := ParseRule(directoryEntry)
	if !ok || directoryRule.ObjectKind != ObjectKindFolder || !directoryRule.applies("/tmp/folder", true) || directoryRule.applies("/tmp/folder", false) {
		t.Fatalf("directory rule did not preserve discriminator: %#v", directoryRule)
	}
}

func TestParseRuleRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "+", "+a", "x /foo", "/foo", "++ /foo", "+ file:", "+ folder:", "+ device:/tmp", "+ unknown:/tmp", `+ file:@dir:"/tmp"`} {
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

	h := NewProfileHandler(lookup, p, time.Second, nopLogger{})
	v := h.Decide(context.Background(), &FileEvent{PID: 42, Path: "/etc/passwd"})
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
		"/home/alice/projects":  ActionAllowAlways,
	}}
	h := NewProfileHandler(lookup, p, time.Second, nopLogger{})

	fileEvent := FileEvent{PID: 99, Path: "/home/alice/notes.txt"}
	v := h.Decide(context.Background(), &fileEvent)
	if v != VerdictAllow {
		t.Fatalf("first call: got %s, want allow", v)
	}
	folderEvent := FileEvent{PID: 99, Path: "/home/alice/projects", IsDir: true}
	v = h.Decide(context.Background(), &folderEvent)
	if v != VerdictAllow {
		t.Fatalf("folder first call: got %s, want allow", v)
	}
	flushCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.FlushPermanentRules(flushCtx); err != nil {
		t.Fatalf("FlushPermanentRules: %v", err)
	}
	// The events carry no operation (OpOpen), which folds to read. Always rules
	// intentionally remain plain and unqualified because the prompt has no
	// object-kind choice.
	got := lookup.appendedFor(99)
	want := []string{"+ /home/alice/notes.txt", "+ /home/alice/projects"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("rule not persisted in profile store: %v", got)
	}
	if ops := lookup.appendedOpFor(99); len(ops) != 2 || ops[0] != OpRead || ops[1] != OpRead {
		t.Fatalf("persisted rule op routing = %v, want [OpRead]", ops)
	}

	// Tripwire on the second call: prompter must not be invoked.
	tripwire := &scriptedPrompter{}
	h.prompter = tripwire
	v = h.Decide(context.Background(), &fileEvent)
	if v != VerdictAllow {
		t.Errorf("second call: got %s, want allow (from persisted rule)", v)
	}
	v = h.Decide(context.Background(), &folderEvent)
	if v != VerdictAllow {
		t.Errorf("folder second call: got %s, want allow (from persisted rule)", v)
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
	h := NewProfileHandler(lookup, p, time.Second, nopLogger{})

	if v := h.Decide(context.Background(), &FileEvent{PID: 100, Path: "/home/alice/notes.txt"}); v != VerdictAllow {
		t.Fatalf("vim: got %s, want allow", v)
	}
	flushCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.FlushPermanentRules(flushCtx); err != nil {
		t.Fatalf("FlushPermanentRules: %v", err)
	}
	if p.called != 1 {
		t.Fatalf("prompter calls after vim: %d, want 1", p.called)
	}

	// cat for the same path -- vim's rule does NOT carry across.
	p.responses["/home/alice/notes.txt"] = ActionDeny
	if v := h.Decide(context.Background(), &FileEvent{PID: 101, Path: "/home/alice/notes.txt"}); v != VerdictDeny {
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

func TestProfileHandlerCoordinatorlessAlwaysUsesDurableOverlayAndRetry(t *testing.T) {
	path := "/tmp/coordinatorless-always"
	store := &fakeRuleStore{id: "profile-C", errs: []error{errors.New("save failed")}}
	lookup := &fakeLookup{
		profiles: map[int32]*fakeProfile{77: {id: "profile-C", defAct: profile.DefaultActionAsk}},
		stores:   map[int32]*fakeRuleStore{77: store},
	}
	prompter := &scriptedPrompter{responses: map[string]string{path: ActionAllowAlways}}
	handler := NewProfileHandler(lookup, prompter, time.Second, nopLogger{})

	if verdict := handler.Decide(context.Background(), &FileEvent{PID: 77, Path: path}); verdict != VerdictAllow {
		t.Fatalf("first verdict = %s, want allow", verdict)
	}
	waitRule(t, func() bool {
		diagnostics := handler.rulePersistence().Diagnostics()["/profile-C"]
		return diagnostics.DirtyCount == 1 && diagnostics.PersistentFailure && diagnostics.LastError != nil
	})

	// The dirty overlay wins immediately, before the failed store has retried.
	handler.prompter = &scriptedPrompter{responses: map[string]string{path: ActionDeny}}
	if verdict := handler.Decide(context.Background(), &FileEvent{PID: 77, Path: path}); verdict != VerdictAllow {
		t.Fatalf("dirty overlay verdict = %s, want allow", verdict)
	}
	if handler.prompter.(*scriptedPrompter).called != 0 {
		t.Fatal("coordinatorless retry path prompted despite the dirty overlay")
	}

	flushCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.FlushPermanentRules(flushCtx); err != nil {
		t.Fatalf("FlushPermanentRules: %v", err)
	}
	diagnostics := handler.rulePersistence().Diagnostics()["/profile-C"]
	if diagnostics.DirtyCount != 0 || diagnostics.PersistentFailure || diagnostics.LastError != nil {
		t.Fatalf("successful retry did not clear persistent failure: %+v", diagnostics)
	}
	if got := lookup.appendedFor(77); len(got) != 2 {
		t.Fatalf("store attempts = %v, want failed write and real retry", got)
	}
}

func TestProfileHandlerCoordinatorlessAlwaysDoesNotPersistBeforeAcceptedResponse(t *testing.T) {
	path := "/tmp/coordinatorless-unaccepted"
	store := &fakeRuleStore{id: "profile-D"}
	lookup := &fakeLookup{
		profiles: map[int32]*fakeProfile{78: {id: "profile-D", defAct: profile.DefaultActionAsk}},
		stores:   map[int32]*fakeRuleStore{78: store},
	}
	handler := NewProfileHandler(lookup, &scriptedPrompter{responses: map[string]string{path: ActionAllowAlways}}, time.Second, nopLogger{})
	verdict, afterResponse := handler.DecideForResponse(context.Background(), &FileEvent{PID: 78, Path: path})
	if verdict != VerdictAllow || afterResponse == nil {
		t.Fatalf("Always decision = %s, callback=%v", verdict, afterResponse != nil)
	}
	if got := lookup.appendedFor(78); len(got) != 0 {
		t.Fatalf("unaccepted response persisted rule: %v", got)
	}
	if diagnostics := handler.rulePersistence().Diagnostics(); len(diagnostics) != 0 {
		t.Fatalf("unaccepted response created dirty persistence state: %+v", diagnostics)
	}
}

// TestProfileHandlerDefaultActionPermit: profile says "permit by
// default" -> no rule + no prompt, allow.
func TestProfileHandlerDefaultActionPermit(t *testing.T) {
	lookup := &fakeLookup{profiles: map[int32]*fakeProfile{
		1: {id: "permit-app", defAct: profile.DefaultActionPermit},
	}}
	p := &scriptedPrompter{}
	h := NewProfileHandler(lookup, p, time.Second, nopLogger{})

	v := h.Decide(context.Background(), &FileEvent{PID: 1, Path: "/anything"})
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
	h := NewProfileHandler(lookup, p, time.Second, nopLogger{})

	v := h.Decide(context.Background(), &FileEvent{PID: 1, Path: "/anything"})
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
			h := NewProfileHandler(lookup, p, time.Second, nopLogger{})

			v := h.Decide(context.Background(), &FileEvent{PID: 1, Path: "/anything"})
			if v != VerdictAllow {
				t.Errorf("got %s, want allow", v)
			}
			if p.called != 1 {
				t.Errorf("prompter calls: %d, want 1", p.called)
			}
		})
	}
}

func TestProfileHandlerDecidePendingExecUsesLaunchingProfile(t *testing.T) {
	// Exec is decided like read/write: the launching process's profile governs
	// the launch. A permit default resolves to allow without a prompt, and the
	// profile must actually be consulted (unlike the old unconditional deny).
	lookup := &fakeLookup{profiles: map[int32]*fakeProfile{
		1: {id: "launcher", defAct: profile.DefaultActionPermit},
	}}
	h := NewProfileHandler(lookup, nil, time.Second, nopLogger{})
	pending := newPendingEvent(&FileEvent{PID: 1, Path: "/tmp/target", Op: OpExec}, func(Verdict) responseResult {
		return responseResult{accepted: true}
	})

	handled, handedOff, decided, verdict, afterResponse := h.DecidePending(context.Background(), pending)
	if handled || handedOff {
		t.Fatalf("exec pending decision = handled=%t handedOff=%t, want direct rule response", handled, handedOff)
	}
	if !decided {
		t.Fatal("exec permit-default decision was not reported as decided; pipeline would re-lookup")
	}
	if verdict != VerdictAllow {
		t.Fatalf("exec pending verdict = %s, want allow from permit default", verdict)
	}
	if afterResponse != nil {
		t.Fatal("rule-resolved exec unexpectedly scheduled post-response work")
	}
	lookup.mu.Lock()
	calls := lookup.calls
	lookup.mu.Unlock()
	if calls != 1 {
		t.Fatalf("exec pending decision consulted launching PID profile %d times, want 1", calls)
	}
}

func TestProfileHandlerLookupFailureDenies(t *testing.T) {
	h := NewProfileHandler(&fakeLookup{err: errors.New("transient")}, &scriptedPrompter{}, time.Second, nopLogger{})
	if got := h.Decide(context.Background(), &FileEvent{PID: 1, Path: "/x"}); got != VerdictDeny {
		t.Fatalf("lookup failure verdict = %s, want deny", got)
	}
}

func TestProfileHandlerSelfProfileUsesInMemorySnapshot(t *testing.T) {
	store := &fakeRuleStore{id: profile.PortmasterProfileID}
	h := NewProfileHandler(
		&fakeLookup{err: errors.New("normal lookup must not run for self")},
		&scriptedPrompter{},
		time.Second,
		nopLogger{},
	)
	h.setSelfProfile(4242, LookupResult{
		Path:          "/usr/bin/filemaster",
		Store:         store,
		Snapshot:      newDecisionSnapshot(profile.PortmasterProfileID, string(profile.SourceLocal), profile.DefaultActionBlock, ruleLists{read: []string{"+ /var/lib/filemaster/**"}}, 1),
		DefaultAction: profile.DefaultActionBlock,
		ProfileSource: string(profile.SourceLocal),
		ProfileName:   "Filemaster",
	})

	allowed := &FileEvent{PID: 4242, Path: "/var/lib/filemaster/state.db"}
	if got := h.Decide(context.Background(), allowed); got != VerdictAllow {
		t.Fatalf("self rule verdict = %s, want allow", got)
	}
	if allowed.Exe != "/usr/bin/filemaster" {
		t.Fatalf("self event executable = %q, want daemon path", allowed.Exe)
	}
	if allowed.ProfileID != profile.PortmasterProfileID {
		t.Fatalf("self event profile = %q, want daemon profile", allowed.ProfileID)
	}

	if got := h.Decide(context.Background(), &FileEvent{PID: 4242, Path: "/etc/shadow"}); got != VerdictDeny {
		t.Fatalf("self default verdict = %s, want deny", got)
	}
}
