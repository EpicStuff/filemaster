package fileaccess

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/safing/portmaster/service/profile"
)

type persistenceTestStore struct {
	mu      sync.Mutex
	entries []string
	ops     []FileOp
	errs    []error
	started chan struct{}
	release chan struct{}
	active  int
	max     int
}

func (s *persistenceTestStore) ID() string { return "profile" }

func (s *persistenceTestStore) AppendRule(op FileOp, entry string) error {
	s.mu.Lock()
	s.active++
	if s.active > s.max {
		s.max = s.active
	}
	if s.started != nil {
		select {
		case s.started <- struct{}{}:
		default:
		}
	}
	release := s.release
	s.mu.Unlock()
	if release != nil {
		<-release
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	s.entries = append(s.entries, entry)
	s.ops = append(s.ops, op)
	if len(s.errs) == 0 {
		return nil
	}
	err := s.errs[0]
	s.errs = s.errs[1:]
	return err
}

func (s *persistenceTestStore) snapshot() ([]string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.entries...), s.max
}

func (s *persistenceTestStore) opSnapshot() []FileOp {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]FileOp(nil), s.ops...)
}

func persistenceSnapshot(rules ...string) *DecisionSnapshot {
	return newDecisionSnapshot("profile", "local", 2, ruleLists{read: rules}, 1)
}

func waitRule(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for durable rule work")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPermanentRulesApplyAllowAndDenyImmediately(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	store := &persistenceTestStore{release: make(chan struct{})}
	allow := persistence.Apply(persistenceSnapshot(), store, "/tmp/allow", VerdictAllow)
	if verdict, ok := allow.Read.Lookup("/tmp/allow"); !ok || verdict != VerdictAllow {
		t.Fatalf("allow overlay did not affect the next decision: %v %v", verdict, ok)
	}
	deny := persistence.Apply(allow, store, "/tmp/deny", VerdictDeny)
	if verdict, ok := deny.Read.Lookup("/tmp/deny"); !ok || verdict != VerdictDeny {
		t.Fatalf("deny overlay did not affect the next decision: %v %v", verdict, ok)
	}
}

func TestPermanentRulesFailureStaysDirtyAndRetries(t *testing.T) {
	wait := make(chan time.Time, 2)
	persistence := NewRulePersistence(nil, RulePersistenceOptions{MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, After: func(time.Duration) <-chan time.Time { return wait }})
	store := &persistenceTestStore{errs: []error{errors.New("disk unavailable")}}
	persistence.Apply(persistenceSnapshot(), store, "/tmp/retry", VerdictAllow)
	waitRule(t, func() bool {
		diagnostics := persistence.Diagnostics()["local/profile"]
		return diagnostics.DirtyCount == 1 && diagnostics.PersistentFailure && diagnostics.RetryCount == 1
	})
	entries, _ := store.snapshot()
	if len(entries) != 1 {
		t.Fatalf("got %d writes before retry, want 1", len(entries))
	}
	wait <- time.Now()
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 0 })
	entries, _ = store.snapshot()
	if len(entries) != 2 || entries[0] != FormatRule("/tmp/retry", VerdictAllow) || entries[1] != FormatRule("/tmp/retry", VerdictAllow) {
		t.Fatalf("retry writes = %v", entries)
	}
	if diagnostics := persistence.Diagnostics()["local/profile"]; diagnostics.PersistentFailure || diagnostics.LastError != nil {
		t.Fatalf("successful retry did not clear failure diagnostics: %+v", diagnostics)
	}
}

func TestPermanentRulesBackoffIsBounded(t *testing.T) {
	var mu sync.Mutex
	var delays []time.Duration
	wait := make(chan time.Time, 3)
	persistence := NewRulePersistence(nil, RulePersistenceOptions{MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, After: func(delay time.Duration) <-chan time.Time {
		mu.Lock()
		delays = append(delays, delay)
		mu.Unlock()
		return wait
	}})
	store := &persistenceTestStore{errs: []error{errors.New("one"), errors.New("two"), errors.New("three")}}
	persistence.Apply(persistenceSnapshot(), store, "/tmp/backoff", VerdictDeny)
	for want := 1; want <= 3; want++ {
		waitRule(t, func() bool {
			mu.Lock()
			defer mu.Unlock()
			return len(delays) >= want
		})
		wait <- time.Now()
	}
	mu.Lock()
	defer mu.Unlock()
	if len(delays) < 3 || delays[0] != time.Millisecond || delays[1] != 2*time.Millisecond || delays[2] != 2*time.Millisecond {
		t.Fatalf("retry delays = %v, want bounded exponential backoff", delays)
	}
}

func TestPermanentRulesCoalesceAndNewerOppositeWins(t *testing.T) {
	store := &persistenceTestStore{started: make(chan struct{}, 2), release: make(chan struct{}, 2)}
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	first := persistence.Apply(persistenceSnapshot(), store, "/tmp/same", VerdictAllow)
	<-store.started
	persistence.Apply(first, store, "/tmp/same", VerdictAllow)
	latest := persistence.Apply(first, store, "/tmp/same", VerdictDeny)
	if verdict, ok := latest.Read.Lookup("/tmp/same"); !ok || verdict != VerdictDeny {
		t.Fatalf("newer permanent rule did not supersede older rule: %v %v", verdict, ok)
	}
	store.release <- struct{}{}
	<-store.started
	store.release <- struct{}{}
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 0 })
	entries, _ := store.snapshot()
	if len(entries) != 2 || entries[0] != FormatRule("/tmp/same", VerdictAllow) || entries[1] != FormatRule("/tmp/same", VerdictDeny) {
		t.Fatalf("serialized writes = %v", entries)
	}
}

func TestPermanentRulesSerializeProfilesAndMergeReload(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	store := &persistenceTestStore{started: make(chan struct{}, 2), release: make(chan struct{}, 2)}
	merged := persistence.Apply(persistenceSnapshot("+ /tmp/clean"), store, "/tmp/dirty", VerdictAllow)
	if verdict, ok := merged.Read.Lookup("/tmp/dirty"); !ok || verdict != VerdictAllow {
		t.Fatal("dirty rule missing from merged snapshot")
	}
	if verdict, ok := merged.Read.Lookup("/tmp/clean"); !ok || verdict != VerdictAllow {
		t.Fatal("clean rule missing from merged snapshot")
	}
	<-store.started
	// A reload with unrelated clean rules cannot discard the dirty overlay.
	reloaded := persistence.Merge(persistenceSnapshot("- /tmp/external"))
	if verdict, ok := reloaded.Read.Lookup("/tmp/dirty"); !ok || verdict != VerdictAllow {
		t.Fatal("reload discarded dirty overlay")
	}
	store.release <- struct{}{}
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 0 })
	_, max := store.snapshot()
	if max != 1 {
		t.Fatalf("same-profile writes overlapped: max=%d", max)
	}
}

func TestPermanentRulesObserverAndFlush(t *testing.T) {
	var persistence *RulePersistence
	observed := make(chan *DecisionSnapshot, 1)
	persistence = NewRulePersistence(func(snapshot *DecisionSnapshot) {
		_ = persistence.Diagnostics() // proves observer is outside the overlay lock
		observed <- snapshot
	}, RulePersistenceOptions{})
	store := &persistenceTestStore{}
	persistence.Apply(persistenceSnapshot(), store, "/tmp/flush", VerdictAllow)
	<-observed
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := persistence.Flush(ctx); err != nil {
		t.Fatalf("flush failed: %v", err)
	}

	blocked := &persistenceTestStore{errs: []error{errors.New("offline")}}
	wait := make(chan time.Time)
	failing := NewRulePersistence(nil, RulePersistenceOptions{MinBackoff: time.Hour, MaxBackoff: time.Hour, After: func(time.Duration) <-chan time.Time { return wait }})
	active := failing.Apply(persistenceSnapshot(), blocked, "/tmp/kept", VerdictDeny)
	deadline, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if err := failing.Flush(deadline); err == nil {
		t.Fatal("flush succeeded with dirty rule still pending")
	}
	if verdict, ok := active.Read.Lookup("/tmp/kept"); !ok || verdict != VerdictDeny {
		t.Fatal("flush timeout changed active dirty policy")
	}
}

func TestPermanentRulesFailedMemoryMutationRemainsDirtyUntilRealSave(t *testing.T) {
	wait := make(chan time.Time, 1)
	persistence := NewRulePersistence(nil, RulePersistenceOptions{MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond, After: func(time.Duration) <-chan time.Time { return wait }})
	store := &persistenceTestStore{errs: []error{errors.New("save after memory mutation failed")}}
	persistence.Apply(persistenceSnapshot(), store, "/tmp/memory", VerdictAllow)
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 1 })

	// This is the snapshot a profile lookup would build from the failed
	// in-memory mutation. It must not be treated as durable confirmation.
	persistence.Merge(persistenceSnapshot("+ /tmp/memory"))
	if diagnostics := persistence.Diagnostics()["local/profile"]; diagnostics.DirtyCount != 1 {
		t.Fatalf("failed in-memory mutation cleared dirty state: %+v", diagnostics)
	}

	wait <- time.Now()
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 0 })
	entries, _ := store.snapshot()
	if len(entries) != 2 {
		t.Fatalf("storage attempts = %v, want failed save plus real retry", entries)
	}
}

func TestPermanentRulesRequireEffectiveDurablePrecedence(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	store := &persistenceTestStore{release: make(chan struct{}, 2)}

	hidden := persistence.Apply(persistenceSnapshot("- /tmp/file", "+ /tmp/file"), store, "/tmp/file", VerdictAllow)
	if diagnostics := persistence.Diagnostics()["local/profile"]; diagnostics.DirtyCount != 1 {
		t.Fatalf("hidden lower allow was treated as durable: %+v", diagnostics)
	}
	if got := hidden.Read.Rules[0]; got.Pattern != "/tmp/file" || got.Verdict != VerdictAllow {
		t.Fatalf("exact allow was not placed at effective precedence: %+v", got)
	}

	broader := NewRulePersistence(nil, RulePersistenceOptions{})
	broaderStore := &persistenceTestStore{release: make(chan struct{}, 1)}
	merged := broader.Apply(persistenceSnapshot("+ /tmp/*"), broaderStore, "/tmp/file", VerdictAllow)
	if diagnostics := broader.Diagnostics()["local/profile"]; diagnostics.DirtyCount != 1 {
		t.Fatalf("broader rule was treated as exact durable confirmation: %+v", diagnostics)
	}
	if got := merged.Read.Rules[0]; got.Pattern != "/tmp/file" || got.Verdict != VerdictAllow {
		t.Fatalf("exact rule was not placed before broader rule: %+v", got)
	}
}

func TestPermanentRulesPublishMonotonicRevisionsAcrossOverlayLifecycle(t *testing.T) {
	store := &persistenceTestStore{started: make(chan struct{}, 2), release: make(chan struct{}, 2)}
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	base := persistenceSnapshot()
	first := persistence.Apply(base, store, "/tmp/one", VerdictAllow)
	second := persistence.Apply(first, store, "/tmp/two", VerdictDeny)
	if second.Revision <= first.Revision {
		t.Fatalf("overlay revisions did not increase: %d then %d", first.Revision, second.Revision)
	}

	// Complete both writes, then present a newer external profile revision.
	<-store.started
	store.release <- struct{}{}
	<-store.started
	store.release <- struct{}{}
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 0 })
	external := newDecisionSnapshot("profile", "local", 2, ruleLists{read: []string{"+ /tmp/one", "- /tmp/two", "+ /tmp/external"}}, 2)
	clean := persistence.Merge(external)
	if clean.Revision <= second.Revision {
		t.Fatalf("clean durable snapshot revision %d did not exceed overlay %d", clean.Revision, second.Revision)
	}
	newer := persistence.Merge(newDecisionSnapshot("profile", "local", 2, ruleLists{read: []string{"+ /tmp/one", "- /tmp/two", "- /tmp/external"}}, 3))
	if newer.Revision <= clean.Revision {
		t.Fatalf("new external revision %d was rejected after overlay %d", newer.Revision, clean.Revision)
	}
	if again := persistence.Merge(newer); again != newer {
		t.Fatalf("unchanged merged lookup rebuilt a revision: %d then %d", newer.Revision, again.Revision)
	}
}

func TestPermanentRulesRetryUsesReboundStore(t *testing.T) {
	wait := make(chan time.Time, 1)
	persistence := NewRulePersistence(nil, RulePersistenceOptions{MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond, After: func(time.Duration) <-chan time.Time { return wait }})
	oldStore := &persistenceTestStore{errs: []error{errors.New("old profile save failed")}}
	newStore := &persistenceTestStore{}
	snapshot := persistence.Apply(persistenceSnapshot(), oldStore, "/tmp/rebind", VerdictAllow)
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].RetryCount == 1 })
	persistence.Bind(snapshot, newStore)
	wait <- time.Now()
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 0 })
	oldEntries, _ := oldStore.snapshot()
	newEntries, _ := newStore.snapshot()
	if len(oldEntries) != 1 || len(newEntries) != 1 {
		t.Fatalf("retry stores old=%v new=%v, want old failed once and new saved once", oldEntries, newEntries)
	}
}

func TestPermanentRulesCurrentBindingWinsOverOldPromptStore(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	storeA := &persistenceTestStore{}
	storeB := &persistenceTestStore{}
	snapshot := persistenceSnapshot()
	persistence.BindStore("local", "profile", storeB)
	persistence.Apply(snapshot, storeA, "/tmp/current", VerdictAllow)
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 0 })
	entriesA, _ := storeA.snapshot()
	entriesB, _ := storeB.snapshot()
	if len(entriesA) != 0 || len(entriesB) != 1 {
		t.Fatalf("old prompt store replaced current binding: A=%v B=%v", entriesA, entriesB)
	}
}

func TestPermanentRulesRejectsStaleSuccessfulBindingWrite(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	storeA := &persistenceTestStore{started: make(chan struct{}, 1), release: make(chan struct{}, 1)}
	storeB := &persistenceTestStore{started: make(chan struct{}, 1), release: make(chan struct{}, 1)}
	snapshot := persistenceSnapshot()
	persistence.Apply(snapshot, storeA, "/tmp/rebound", VerdictAllow)
	<-storeA.started
	persistence.BindStore("local", "profile", storeB)
	storeA.release <- struct{}{}
	<-storeB.started
	if diagnostics := persistence.Diagnostics()["local/profile"]; diagnostics.DirtyCount != 1 {
		t.Fatalf("stale successful write cleared dirty state: %+v", diagnostics)
	}
	flushContext, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := persistence.Flush(flushContext); err == nil {
		t.Fatal("flush succeeded before the current store accepted the rule")
	}
	storeB.release <- struct{}{}
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 0 })
	entriesA, _ := storeA.snapshot()
	entriesB, _ := storeB.snapshot()
	if len(entriesA) != 1 || len(entriesB) != 1 {
		t.Fatalf("binding writes = A:%v B:%v, want one stale and one current attempt", entriesA, entriesB)
	}
}

func TestPermanentRulesBindingsAreIndependentAndDoNotLoseWakeups(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	storeA := &persistenceTestStore{}
	storeB := &persistenceTestStore{}
	first := newDecisionSnapshot("first", "local", 2, ruleLists{}, 1)
	second := newDecisionSnapshot("second", "local", 2, ruleLists{}, 1)
	persistence.BindStore("local", "first", storeA)
	persistence.BindStore("local", "second", storeB)
	persistence.Apply(first, storeA, "/tmp/first", VerdictAllow)
	persistence.Apply(second, storeB, "/tmp/second", VerdictDeny)
	for range 5 {
		persistence.BindStore("local", "first", storeA)
		persistence.BindStore("local", "second", storeB)
	}
	waitRule(t, func() bool {
		diagnostics := persistence.Diagnostics()
		return diagnostics["local/first"].DirtyCount == 0 && diagnostics["local/second"].DirtyCount == 0
	})
	entriesA, maxA := storeA.snapshot()
	entriesB, maxB := storeB.snapshot()
	if len(entriesA) != 1 || len(entriesB) != 1 || maxA != 1 || maxB != 1 {
		t.Fatalf("independent bindings A=%v/%d B=%v/%d", entriesA, maxA, entriesB, maxB)
	}
}

func TestRuleStoreIdentityUsesProfilePointerOnly(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	first := &profile.Profile{ID: "same", Name: "same"}
	second := &profile.Profile{ID: "same", Name: "same"}
	persistence.BindStore("local", "profile", &profileRuleStore{p: first, id: "profile"})
	firstGeneration := persistence.bindings["local/profile"].generation
	persistence.BindStore("local", "profile", &profileRuleStore{p: first, id: "profile"})
	if got := persistence.bindings["local/profile"].generation; got != firstGeneration {
		t.Fatalf("wrappers around one profile pointer changed binding generation: %d -> %d", firstGeneration, got)
	}
	persistence.BindStore("local", "profile", &profileRuleStore{p: second, id: "profile"})
	if got := persistence.bindings["local/profile"].generation; got != firstGeneration+1 {
		t.Fatalf("distinct profile pointers did not replace binding: %d -> %d", firstGeneration, got)
	}
}

func TestLiteralPermanentRulesRoundTripLiteralPaths(t *testing.T) {
	paths := []string{"/tmp/a*b", "/tmp/a?b", "/tmp/a[b]", "/tmp/back\\slash\"quote ", "/tmp/trailing "}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			entry := FormatLiteralRule(path, VerdictAllow)
			rule, ok := ParseRule(entry)
			if !ok || rule.Verdict != VerdictAllow || !rule.Matches(path) || rule.Matches(path+"x") {
				t.Fatalf("literal rule round trip = %+v, %v", rule, ok)
			}
			if !rule.Matches(path) || rule.Matches(path+"x") {
				t.Fatalf("literal rule matched an adjacent path: %+v", rule)
			}
		})
	}
	legacy, ok := ParseRule("+ /tmp/a*")
	if !ok || !legacy.Matches("/tmp/abc") {
		t.Fatalf("legacy wildcard compatibility broken: %+v, %v", legacy, ok)
	}
}

func TestPermanentRulesKeepLearnedPathsLiteralInOverlay(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	store := &persistenceTestStore{started: make(chan struct{}, 1), release: make(chan struct{})}
	defer close(store.release)
	merged := persistence.Apply(persistenceSnapshot("- /tmp/a*b"), store, "/tmp/a*b", VerdictAllow)
	<-store.started // Keep the learned rule dirty while inspecting its overlay.
	if len(merged.Read.Rules) != 2 {
		t.Fatalf("merged rules = %#v, want literal overlay plus base glob", merged.Read.Rules)
	}
	if rule := merged.Read.Rules[0]; rule.Pattern != `/tmp/a\*b` || rule.Verdict != VerdictAllow {
		t.Fatalf("literal learned rule = %+v", rule)
	}
	if verdict, ok := merged.Read.Lookup("/tmp/a*b"); !ok || verdict != VerdictAllow {
		t.Fatalf("learned rule did not win: %v, %v", verdict, ok)
	}
	if verdict, ok := merged.Read.Lookup("/tmp/axxb"); !ok || verdict != VerdictDeny {
		t.Fatalf("dirty literal overlay matched a glob lookalike: %v, %v", verdict, ok)
	}
}

func TestLegacyExactRulesAreRejected(t *testing.T) {
	if _, ok := ParseRule(`+ @"/tmp/one/../two"`); ok {
		t.Fatal("legacy @ exact rule was accepted")
	}
}

func TestPermanentRulesRevisionConflictStaysDirtyUntilRetry(t *testing.T) {
	wait := make(chan time.Time, 1)
	persistence := NewRulePersistence(nil, RulePersistenceOptions{
		MinBackoff: time.Millisecond,
		MaxBackoff: time.Millisecond,
		After:      func(time.Duration) <-chan time.Time { return wait },
	})
	store := &persistenceTestStore{errs: []error{profile.ErrProfileRevisionConflict}}
	persistence.Apply(persistenceSnapshot(), store, "/tmp/conflict", VerdictAllow)
	waitRule(t, func() bool {
		diagnostics := persistence.Diagnostics()["local/profile"]
		return diagnostics.DirtyCount == 1 && errors.Is(diagnostics.LastError, profile.ErrProfileRevisionConflict)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := persistence.Flush(ctx); err == nil {
		t.Fatal("flush succeeded while the revision-conflicted rule was dirty")
	}
	wait <- time.Now()
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 0 })
}

func TestPermanentRulesCurrentRevisionCanRemoveAppliedRule(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	store := &persistenceTestStore{}
	base := persistenceSnapshot()
	persistence.Apply(base, store, "/tmp/remove", VerdictDeny)
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 0 })
	removed := persistence.Merge(newDecisionSnapshot("profile", "local", 2, ruleLists{}, 2))
	if verdict, ok := removed.Read.Lookup("/tmp/remove"); ok || verdict != VerdictAllow {
		t.Fatalf("removed durable rule was silently restored: %v, %v", verdict, ok)
	}
}

func TestPermanentRulesEqualRevisionDivergenceDoesNotRestoreCleanRule(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	store := &persistenceTestStore{}
	base := persistenceSnapshot()
	persistence.Apply(base, store, "/tmp/equal-revision", VerdictAllow)
	waitRule(t, func() bool { return persistence.Diagnostics()["local/profile"].DirtyCount == 0 })
	identical := persistence.Merge(newDecisionSnapshot("profile", "local", 2, ruleLists{read: []string{FormatLiteralRule("/tmp/equal-revision", VerdictAllow)}}, base.Revision))
	if verdict, ok := identical.Read.Lookup("/tmp/equal-revision"); !ok || verdict != VerdictAllow {
		t.Fatalf("equal-revision identical content changed durable policy: %v, %v", verdict, ok)
	}

	// An equal revision is only unchanged when its policy content is equal. A
	// divergent replacement is authoritative for clean/applied rules.
	removed := persistence.Merge(newDecisionSnapshot("profile", "local", 2, ruleLists{}, base.Revision))
	if _, ok := removed.Read.Lookup("/tmp/equal-revision"); ok {
		t.Fatal("equal-revision external removal was silently restored")
	}

	blocked := &persistenceTestStore{release: make(chan struct{})}
	defer close(blocked.release)
	updated := persistence.Apply(removed, blocked, "/tmp/local-dirty", VerdictDeny)
	if verdict, ok := updated.Read.Lookup("/tmp/local-dirty"); !ok || verdict != VerdictDeny {
		t.Fatalf("dirty local intent was lost during equal-revision merge: %v, %v", verdict, ok)
	}
	mergedDirty := persistence.Merge(newDecisionSnapshot("profile", "local", 2, ruleLists{}, base.Revision))
	if verdict, ok := mergedDirty.Read.Lookup("/tmp/local-dirty"); !ok || verdict != VerdictDeny {
		t.Fatalf("equal-revision base overwrote newer dirty overlay: %v, %v", verdict, ok)
	}
}

func TestPermanentRulesRetireIdleWorkersAndStopWithoutDiscardingDirtyState(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{WorkerIdle: time.Millisecond})
	for _, id := range []string{"idle-a", "idle-b", "idle-c", "idle-d"} {
		persistence.Apply(newDecisionSnapshot(id, "local", 2, ruleLists{}, 1), &persistenceTestStore{}, "/tmp/"+id, VerdictAllow)
	}
	waitRule(t, func() bool {
		diagnostics := persistence.Diagnostics()
		for _, id := range []string{"idle-a", "idle-b", "idle-c", "idle-d"} {
			if diagnostics["local/"+id].DirtyCount != 0 {
				return false
			}
		}
		return true
	})
	waitRule(t, func() bool {
		persistence.mu.Lock()
		defer persistence.mu.Unlock()
		for _, state := range persistence.profiles {
			if state.started {
				return false
			}
		}
		return true
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := persistence.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	merged := persistence.Apply(persistenceSnapshot(), &persistenceTestStore{}, "/tmp/after-stop", VerdictAllow)
	if _, ok := merged.Read.Lookup("/tmp/after-stop"); ok {
		t.Fatal("stopped persistence accepted a new durable rule")
	}
}

func TestPermanentRulesStopWaitsForBlockedWorkerAfterFlushDeadline(t *testing.T) {
	store := &persistenceTestStore{started: make(chan struct{}, 1), release: make(chan struct{})}
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	persistence.Apply(persistenceSnapshot(), store, "/tmp/blocked-stop", VerdictAllow)
	<-store.started

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- persistence.Stop(ctx) }()
	<-ctx.Done()
	select {
	case err := <-done:
		t.Fatalf("Stop returned before blocked worker exited: %v", err)
	default:
	}
	waitRule(t, func() bool {
		persistence.mu.Lock()
		defer persistence.mu.Unlock()
		return persistence.stopped
	})
	merged := persistence.Apply(persistenceSnapshot(), &persistenceTestStore{}, "/tmp/rejected-after-stop", VerdictDeny)
	if _, ok := merged.Read.Lookup("/tmp/rejected-after-stop"); ok {
		t.Fatal("persistence accepted a rule after stop admission began")
	}

	close(store.release)
	if err := <-done; err == nil {
		t.Fatal("Stop lost the bounded flush timeout")
	}
	persistence.WaitWorkers()
}

func TestPermanentRulesKeepAlwaysRulesOperationScoped(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond})
	store := &persistenceTestStore{}
	base := persistenceSnapshot()
	merged := persistence.ApplyEvent(base, store, "/tmp/data", OpRead, false, VerdictAllow)
	if verdict, matched, ok := merged.Lookup("/tmp/data", OpRead, false); !ok || !matched || verdict != VerdictAllow {
		t.Fatalf("read rule lookup = (%v, %t, %t), want (allow, true, true)", verdict, matched, ok)
	}
	// The rule lives only in the read list, not the write or exec lists.
	if verdict, ok := merged.Read.Lookup("/tmp/data"); !ok || verdict != VerdictAllow {
		t.Fatalf("read list lookup = (%v, %t), want (allow, true)", verdict, ok)
	}
	if _, ok := merged.Write.Lookup("/tmp/data"); ok {
		t.Fatal("read Always rule leaked into the write list")
	}
	if _, ok := merged.Exec.Lookup("/tmp/data"); ok {
		t.Fatal("read Always rule leaked into the exec list")
	}
	// Opens are governed by the read list, so the read rule also matches opens.
	if verdict, matched, ok := merged.Lookup("/tmp/data", OpOpen, false); !ok || !matched || verdict != VerdictAllow {
		t.Fatalf("open lookup = (%v, %t, %t), want (allow, true, true); opens fold to reads", verdict, matched, ok)
	}
	// Write is a supported operation (ok) but no rule matched (not matched).
	if _, matched, ok := merged.Lookup("/tmp/data", OpWrite, false); !ok || matched {
		t.Fatalf("read Always rule matched write: matched=%t ok=%t", matched, ok)
	}
	waitRule(t, func() bool {
		entries, _ := store.snapshot()
		return len(entries) == 1
	})
	entries, _ := store.snapshot()
	if got := entries[0]; got != FormatRule("/tmp/data", VerdictAllow) {
		t.Fatalf("stored rule = %q", got)
	}
	if ops := store.opSnapshot(); len(ops) != 1 || ops[0] != OpRead {
		t.Fatalf("persisted op routing = %v, want [OpRead]", ops)
	}
}

// TestPermanentRulesRouteLearnedRulesPerOperation covers that ApplyEvent places
// a learned rule in the list for its operation and nowhere else: OpExec lands in
// Exec, OpWrite lands in Write, and neither leaks into Read.
func TestPermanentRulesRouteLearnedRulesPerOperation(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	store := &persistenceTestStore{}

	execMerged := persistence.ApplyEvent(persistenceSnapshot(), store, "/tmp/prog", OpExec, false, VerdictAllow)
	if verdict, ok := execMerged.Exec.Lookup("/tmp/prog"); !ok || verdict != VerdictAllow {
		t.Fatalf("exec rule missing from exec list: (%v, %t)", verdict, ok)
	}
	if _, ok := execMerged.Read.Lookup("/tmp/prog"); ok {
		t.Fatal("exec rule leaked into read list")
	}
	if _, ok := execMerged.Write.Lookup("/tmp/prog"); ok {
		t.Fatal("exec rule leaked into write list")
	}

	writeMerged := persistence.ApplyEvent(persistenceSnapshot(), store, "/tmp/doc", OpWrite, false, VerdictDeny)
	if verdict, ok := writeMerged.Write.Lookup("/tmp/doc"); !ok || verdict != VerdictDeny {
		t.Fatalf("write rule missing from write list: (%v, %t)", verdict, ok)
	}
	if _, ok := writeMerged.Read.Lookup("/tmp/doc"); ok {
		t.Fatal("write rule leaked into read list")
	}

	waitRule(t, func() bool {
		entries, _ := store.snapshot()
		return len(entries) == 2
	})
	ops := store.opSnapshot()
	if len(ops) != 2 || ops[0] != OpExec || ops[1] != OpWrite {
		t.Fatalf("persisted op routing = %v, want [OpExec OpWrite]", ops)
	}
}

// TestPermanentRulesSamePathCoexistAcrossOperations covers that learning the
// same path for two different operations keeps both -- dedup is per-operation, so
// a read rule does not suppress an exec rule on the identical path.
func TestPermanentRulesSamePathCoexistAcrossOperations(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	store := &persistenceTestStore{}
	merged := persistence.ApplyEvent(persistenceSnapshot(), store, "/tmp/dual", OpRead, false, VerdictAllow)
	merged = persistence.ApplyEvent(merged, store, "/tmp/dual", OpExec, false, VerdictDeny)
	if verdict, ok := merged.Read.Lookup("/tmp/dual"); !ok || verdict != VerdictAllow {
		t.Fatalf("read rule lost after exec rule on same path: (%v, %t)", verdict, ok)
	}
	if verdict, ok := merged.Exec.Lookup("/tmp/dual"); !ok || verdict != VerdictDeny {
		t.Fatalf("exec rule missing after coexisting read rule: (%v, %t)", verdict, ok)
	}
	waitRule(t, func() bool {
		entries, _ := store.snapshot()
		return len(entries) == 2
	})
	ops := store.opSnapshot()
	if len(ops) != 2 || ops[0] != OpRead || ops[1] != OpExec {
		t.Fatalf("persisted op routing = %v, want [OpRead OpExec]", ops)
	}
}

// TestPermanentRulesReloadKeepsLearnedRuleInOperationList covers that a profile
// reload (Merge) that has not yet caught up to a dirty learned exec rule keeps it
// in the exec list, not the read list.
func TestPermanentRulesReloadKeepsLearnedRuleInOperationList(t *testing.T) {
	persistence := NewRulePersistence(nil, RulePersistenceOptions{})
	store := &persistenceTestStore{started: make(chan struct{}, 1), release: make(chan struct{})}
	defer close(store.release)
	persistence.ApplyEvent(persistenceSnapshot(), store, "/tmp/reloaded", OpExec, false, VerdictAllow)
	<-store.started
	reloaded := persistence.Merge(persistenceSnapshot("- /tmp/other"))
	if verdict, ok := reloaded.Exec.Lookup("/tmp/reloaded"); !ok || verdict != VerdictAllow {
		t.Fatalf("reload dropped the dirty exec rule from the exec list: (%v, %t)", verdict, ok)
	}
	if _, ok := reloaded.Read.Lookup("/tmp/reloaded"); ok {
		t.Fatal("reload moved the dirty exec rule into the read list")
	}
}
