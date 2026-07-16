package fileaccess

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/safing/portmaster/service/profile"
)

type actionPrompter struct {
	entered   chan struct{}
	actions   chan string
	completed chan struct{}
}

func (p *actionPrompter) Prompt(_ context.Context, _ FileEvent, _ time.Duration) (string, bool) {
	p.entered <- struct{}{}
	action := <-p.actions
	if p.completed != nil {
		p.completed <- struct{}{}
	}
	return action, true
}

type promptResponseObserver struct {
	handler Handler

	mu       sync.Mutex
	observed []FileEvent
}

func (o *promptResponseObserver) DecisionHandler() Handler { return o.handler }

func (o *promptResponseObserver) Decide(ctx context.Context, event *FileEvent) Verdict {
	return o.handler.Decide(ctx, event)
}

func (o *promptResponseObserver) Observe(event *FileEvent, _ Verdict) {
	o.mu.Lock()
	o.observed = append(o.observed, *event)
	o.mu.Unlock()
}

func (o *promptResponseObserver) observedCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.observed)
}

type refreshingAskLookup struct {
	store     RuleStore
	refreshed chan int32
}

type orderedRuleStore struct {
	mu       *sync.Mutex
	sequence *[]string
	appended []string
}

type panicRefreshHandler struct{}

func (panicRefreshHandler) Decide(context.Context, *FileEvent) Verdict { return VerdictDeny }

func (panicRefreshHandler) RefreshProcessMapping(context.Context, int32) error {
	panic("refresh panic")
}

func (s *orderedRuleStore) ID() string { return "profile" }

func (s *orderedRuleStore) AppendRule(rule string) error {
	s.mu.Lock()
	*s.sequence = append(*s.sequence, "append")
	s.appended = append(s.appended, rule)
	s.mu.Unlock()
	return nil
}

func storedRules(store *fakeRuleStore) []string {
	store.appendMu.Lock()
	defer store.appendMu.Unlock()
	return append([]string(nil), store.appended...)
}

func (l *refreshingAskLookup) Lookup(context.Context, int32) (LookupResult, error) {
	snapshot := newDecisionSnapshot("profile", "local", profile.DefaultActionAsk, nil, 1)
	return LookupResult{
		Path:          "/usr/bin/test",
		Store:         l.store,
		Snapshot:      snapshot,
		ParsedRules:   snapshot.Rules,
		DefaultAction: snapshot.DefaultAction,
		ProfileSource: snapshot.Source,
	}, nil
}

func (l *refreshingAskLookup) RefreshProcessMapping(_ context.Context, pid int32) error {
	l.refreshed <- pid
	return nil
}

func waitPromptStart(t *testing.T, prompter *actionPrompter) {
	t.Helper()
	select {
	case <-prompter.entered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for coordinator prompt")
	}
}

func TestPromptCoordinatorObservesAndRefreshesEveryAcceptedGroupedEvent(t *testing.T) {
	prompter := &actionPrompter{entered: make(chan struct{}, 1), actions: make(chan string, 1), completed: make(chan struct{}, 1)}
	lookup := &refreshingAskLookup{store: &fakeRuleStore{id: "profile"}, refreshed: make(chan int32, 2)}
	handler := NewProfileHandler(lookup, prompter, nil, time.Second, nopLogger{})
	observer := &promptResponseObserver{handler: handler}
	pipeline := NewDecisionPipeline(observer, DecisionPipelineConfig{Workers: 2, QueueCapacity: 2, OutstandingLimit: 4, PerProfileAskLimit: 4})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)

	first, firstResponses := pipelinePending(FileEvent{PID: 10, Path: "/tmp/exec", Op: OpExec})
	second, secondResponses := pipelinePending(FileEvent{PID: 11, Path: "/tmp/exec", Op: OpExec})
	if err := pipeline.Handle(ctx, first); err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	if err := pipeline.Handle(ctx, second); err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	waitPromptStart(t, prompter)
	deadline := time.After(time.Second)
	for {
		coordinator := handler.coordinator()
		coordinator.mu.Lock()
		entries := 0
		for _, group := range coordinator.groups {
			entries += len(group.entries)
		}
		coordinator.mu.Unlock()
		if entries == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("grouped entries = %d, want 2", entries)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	prompter.actions <- ActionAllow
	if got := waitPipelineVerdict(t, firstResponses); got != VerdictAllow {
		t.Fatalf("first verdict = %s, want allow", got)
	}
	if got := waitPipelineVerdict(t, secondResponses); got != VerdictAllow {
		t.Fatalf("second verdict = %s, want allow", got)
	}
	for range 2 {
		select {
		case <-lookup.refreshed:
		case <-time.After(time.Second):
			t.Fatal("missing grouped exec refresh")
		}
	}
	if got := observer.observedCount(); got != 2 {
		t.Fatalf("observed grouped events = %d, want 2", got)
	}
}

func TestPromptCoordinatorUnacceptedResponseSkipsObservationAndRefresh(t *testing.T) {
	prompter := &actionPrompter{entered: make(chan struct{}, 1), actions: make(chan string, 1)}
	lookup := &refreshingAskLookup{store: &fakeRuleStore{id: "profile"}, refreshed: make(chan int32, 1)}
	handler := NewProfileHandler(lookup, prompter, nil, time.Second, nopLogger{})
	observer := &promptResponseObserver{handler: handler}
	pipeline := NewDecisionPipeline(observer, DecisionPipelineConfig{Workers: 1, QueueCapacity: 1, OutstandingLimit: 2, PerProfileAskLimit: 2})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)

	pending := newPendingEvent(&FileEvent{PID: 10, Path: "/tmp/exec", Op: OpExec}, func(Verdict) responseResult {
		return responseResult{err: errors.New("response failed")}
	})
	if err := pipeline.Handle(ctx, pending); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	waitPromptStart(t, prompter)
	prompter.actions <- ActionAllow
	deadline := time.After(time.Second)
	for pipeline.Diagnostics().Outstanding != 0 {
		select {
		case <-deadline:
			t.Fatal("pipeline accounting was not released")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if got := observer.observedCount(); got != 0 {
		t.Fatalf("observed failed response = %d, want 0", got)
	}
	select {
	case pid := <-lookup.refreshed:
		t.Fatalf("refreshed failed response pid %d", pid)
	default:
	}
}

func TestPromptCoordinatorLatestSnapshotPreventsStaleAdmission(t *testing.T) {
	prompter := &actionPrompter{entered: make(chan struct{}, 1), actions: make(chan string, 1)}
	h := newCoordinatorHarness(prompter, 2)
	newer := coordinatorSnapshot("profile", 2, profile.DefaultActionPermit)
	h.coordinator.SnapshotReplaced(newer)

	pending, responses := coordinatorPending(FileEvent{Path: "/tmp/file", Op: OpOpen})
	stale := coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)
	handled, handedOff, verdict, _ := h.coordinator.Admit(context.Background(), pending, nil, stale)
	if !handled || !handedOff || verdict != VerdictDeny {
		t.Fatalf("stale admission = handled:%t handedOff:%t verdict:%s", handled, handedOff, verdict)
	}
	if got := waitCoordinatorVerdict(t, responses); got != VerdictAllow {
		t.Fatalf("stale admission verdict = %s, want allow", got)
	}
	select {
	case <-prompter.entered:
		t.Fatal("stale snapshot created a prompt")
	default:
	}
}

func TestPromptCoordinatorNewerSnapshotCannotBeOverwrittenByOlderRevision(t *testing.T) {
	prompter := &actionPrompter{entered: make(chan struct{}, 1), actions: make(chan string, 1)}
	h := newCoordinatorHarness(prompter, 2)
	pending, _ := coordinatorPending(FileEvent{Path: "/tmp/file", Op: OpOpen})
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), pending, nil, coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)); !handled || !handedOff {
		t.Fatal("event was not admitted")
	}
	waitPromptStart(t, prompter)
	newer := coordinatorSnapshot("profile", 3, profile.DefaultActionAsk)
	h.coordinator.SnapshotReplaced(newer)
	h.coordinator.SnapshotReplaced(coordinatorSnapshot("profile", 2, profile.DefaultActionAsk))
	h.coordinator.mu.Lock()
	for _, group := range h.coordinator.groups {
		if group.snapshot != newer {
			h.coordinator.mu.Unlock()
			t.Fatal("older Ask revision replaced newer group snapshot")
		}
	}
	h.coordinator.mu.Unlock()
	h.coordinator.Close()
}

func TestPromptCoordinatorNewerDispositionCannotBeReplacedByOlderRevision(t *testing.T) {
	prompter := &actionPrompter{entered: make(chan struct{}, 1), actions: make(chan string, 1)}
	h := newCoordinatorHarness(prompter, 2)
	pending, responses := coordinatorPending(FileEvent{Path: "/tmp/file", Op: OpOpen})
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), pending, nil, coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)); !handled || !handedOff {
		t.Fatal("event was not admitted")
	}
	waitPromptStart(t, prompter)
	permit := coordinatorSnapshot("profile", 3, profile.DefaultActionPermit)
	h.coordinator.SnapshotReplaced(permit)
	h.coordinator.SnapshotReplaced(coordinatorSnapshot("profile", 2, profile.DefaultActionBlock))
	if got := waitCoordinatorVerdict(t, responses); got != VerdictAllow {
		t.Fatalf("newer permit verdict = %s, want allow", got)
	}
	h.coordinator.mu.Lock()
	latest := h.coordinator.latestProfileSnapshot["local/profile"]
	h.coordinator.mu.Unlock()
	if latest != permit {
		t.Fatal("older disposition replaced newer published snapshot")
	}
}

func TestPromptCoordinatorLosingAlwaysActionDoesNotPersist(t *testing.T) {
	prompter := &actionPrompter{entered: make(chan struct{}, 1), actions: make(chan string, 1), completed: make(chan struct{}, 1)}
	store := &fakeRuleStore{id: "profile"}
	h := newCoordinatorHarness(prompter, 2)
	pending, responses := coordinatorPending(FileEvent{Path: "/tmp/file", Op: OpOpen})
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), pending, store, coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)); !handled || !handedOff {
		t.Fatal("event was not admitted")
	}
	waitPromptStart(t, prompter)
	h.coordinator.SnapshotReplaced(coordinatorSnapshot("profile", 2, profile.DefaultActionPermit))
	if got := waitCoordinatorVerdict(t, responses); got != VerdictAllow {
		t.Fatalf("reevaluated verdict = %s, want allow", got)
	}
	prompter.actions <- ActionAllowAlways
	select {
	case <-prompter.completed:
	case <-time.After(time.Second):
		t.Fatal("stale prompt action did not return")
	}
	if got := storedRules(store); len(got) != 0 {
		t.Fatalf("stale prompt persisted rules: %v", got)
	}
}

func TestPromptCoordinatorAlwaysPersistsAfterMixedResponsesAndReleasesEachEntry(t *testing.T) {
	prompter := &actionPrompter{entered: make(chan struct{}, 1), actions: make(chan string, 1)}
	var mu sync.Mutex
	sequence := make([]string, 0, 3)
	store := &orderedRuleStore{mu: &mu, sequence: &sequence}
	releases := 0
	coordinator := NewPromptCoordinator(prompter, time.Second, func(string) (func(), bool) {
		return func() {
			mu.Lock()
			releases++
			mu.Unlock()
		}, true
	}, func(_ context.Context, pending PendingEvent, verdict Verdict) bool {
		mu.Lock()
		sequence = append(sequence, "response")
		mu.Unlock()
		err := pending.Respond(verdict)
		if owner, ok := pending.(*pendingEventOwner); ok {
			return owner.responseAccepted()
		}
		return err == nil
	})

	first, _ := coordinatorPending(FileEvent{Path: "/tmp/file", Op: OpOpen})
	second := newPendingEvent(&FileEvent{Path: "/tmp/file", Op: OpOpen}, func(Verdict) responseResult {
		return responseResult{err: errors.New("response failed")}
	})
	snapshot := coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)
	if handled, handedOff, _, _ := coordinator.Admit(context.Background(), first, store, snapshot); !handled || !handedOff {
		t.Fatal("first event was not admitted")
	}
	if handled, handedOff, _, _ := coordinator.Admit(context.Background(), second, store, snapshot); !handled || !handedOff {
		t.Fatal("second event was not admitted")
	}
	waitPromptStart(t, prompter)
	prompter.actions <- ActionAllowAlways
	deadline := time.After(time.Second)
	mu.Lock()
	appended := len(store.appended)
	mu.Unlock()
	for appended != 1 {
		select {
		case <-deadline:
			t.Fatal("Always rule was not persisted")
		default:
			time.Sleep(time.Millisecond)
		}
		mu.Lock()
		appended = len(store.appended)
		mu.Unlock()
	}
	mu.Lock()
	if releases != 2 {
		mu.Unlock()
		t.Fatalf("releases = %d, want 2", releases)
	}
	if got := sequence; len(got) != 3 || got[0] != "response" || got[1] != "response" || got[2] != "append" {
		mu.Unlock()
		t.Fatalf("response/persistence sequence = %v", got)
	}
	mu.Unlock()
}

func TestPromptCoordinatorMixedResponseGroupReleasesPipelineAccountingOnce(t *testing.T) {
	prompter := &actionPrompter{entered: make(chan struct{}, 1), actions: make(chan string, 1)}
	handler := NewProfileHandler(askLookup{store: &fakeRuleStore{id: "profile"}}, prompter, nil, time.Second, nopLogger{})
	pipeline := NewDecisionPipeline(handler, DecisionPipelineConfig{Workers: 2, QueueCapacity: 2, OutstandingLimit: 4, PerProfileAskLimit: 4})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)

	first, firstResponses := pipelinePending(FileEvent{PID: 1, Path: "/tmp/file", Op: OpOpen})
	second := newPendingEvent(&FileEvent{PID: 2, Path: "/tmp/file", Op: OpOpen}, func(Verdict) responseResult {
		return responseResult{err: errors.New("response failed")}
	})
	if err := pipeline.Handle(ctx, first); err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	if err := pipeline.Handle(ctx, second); err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	waitPromptStart(t, prompter)
	deadline := time.After(time.Second)
	for {
		coordinator := handler.coordinator()
		coordinator.mu.Lock()
		entries := 0
		for _, group := range coordinator.groups {
			entries += len(group.entries)
		}
		coordinator.mu.Unlock()
		if entries == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("grouped entries = %d, want 2", entries)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	prompter.actions <- ActionAllow
	if got := waitPipelineVerdict(t, firstResponses); got != VerdictAllow {
		t.Fatalf("first verdict = %s, want allow", got)
	}
	deadline = time.After(time.Second)
	for pipeline.Diagnostics().Outstanding != 0 {
		select {
		case <-deadline:
			t.Fatalf("outstanding = %d, want 0", pipeline.Diagnostics().Outstanding)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	pipeline.askMu.Lock()
	remainingAsk := len(pipeline.pendingAsk)
	pipeline.askMu.Unlock()
	if remainingAsk != 0 {
		t.Fatalf("pending Ask profiles = %d, want 0", remainingAsk)
	}
}

func TestFinishPromptEventRefreshPanicStillObserves(t *testing.T) {
	observed := make(chan struct{}, 1)
	pipeline := &DecisionPipeline{
		handler: panicRefreshHandler{},
		observe: func(*FileEvent, Verdict) { observed <- struct{}{} },
	}
	pipeline.outstanding.Store(1)
	pending, responses := coordinatorPending(FileEvent{PID: 7, Path: "/tmp/exec", Op: OpExec})
	if accepted := pipeline.finishPromptEvent(context.Background(), pending, VerdictAllow); !accepted {
		t.Fatal("accepted response reported false")
	}
	if got := waitCoordinatorVerdict(t, responses); got != VerdictAllow {
		t.Fatalf("verdict = %s, want allow", got)
	}
	select {
	case <-observed:
	case <-time.After(time.Second):
		t.Fatal("refresh panic suppressed observation")
	}
	if got := pipeline.outstanding.Load(); got != 0 {
		t.Fatalf("outstanding = %d, want 0", got)
	}
}

func TestFinishPromptEventObservationPanicDoesNotBlockLaterEntries(t *testing.T) {
	var observations int
	pipeline := &DecisionPipeline{handler: allowAll}
	pipeline.observe = func(*FileEvent, Verdict) {
		observations++
		if observations == 1 {
			panic("observation panic")
		}
	}
	pipeline.outstanding.Store(2)
	prompter := &actionPrompter{entered: make(chan struct{}, 1), actions: make(chan string, 1)}
	coordinator := NewPromptCoordinator(prompter, time.Second, func(string) (func(), bool) {
		return func() {}, true
	}, pipeline.finishPromptEvent)
	first, firstResponses := coordinatorPending(FileEvent{Path: "/tmp/file", Op: OpOpen})
	second, secondResponses := coordinatorPending(FileEvent{Path: "/tmp/file", Op: OpOpen})
	snapshot := coordinatorSnapshot("profile", 1, profile.DefaultActionAsk)
	if handled, handedOff, _, _ := coordinator.Admit(context.Background(), first, nil, snapshot); !handled || !handedOff {
		t.Fatal("first event was not admitted")
	}
	if handled, handedOff, _, _ := coordinator.Admit(context.Background(), second, nil, snapshot); !handled || !handedOff {
		t.Fatal("second event was not admitted")
	}
	waitPromptStart(t, prompter)
	prompter.actions <- ActionAllow
	if got := waitCoordinatorVerdict(t, firstResponses); got != VerdictAllow {
		t.Fatalf("first verdict = %s, want allow", got)
	}
	if got := waitCoordinatorVerdict(t, secondResponses); got != VerdictAllow {
		t.Fatalf("second verdict = %s, want allow", got)
	}
	if got := pipeline.outstanding.Load(); got != 0 {
		t.Fatalf("outstanding = %d, want 0", got)
	}
	if observations != 2 {
		t.Fatalf("observations = %d, want 2", observations)
	}
}

func TestSnapshotObserverCanReenterSnapshotLookup(t *testing.T) {
	lookup := &processProfileLookup{}
	done := make(chan struct{})
	lookup.setSnapshotObserver(func(*DecisionSnapshot) {
		lookup.snapshotFor("profile", "local", profile.DefaultActionAsk, nil)
		close(done)
	})
	go func() { lookup.snapshotFor("profile", "local", profile.DefaultActionAsk, nil) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("snapshot observer reentry deadlocked")
	}
}

func TestPromptCoordinatorUnknownPIDDoesNotGroupWithoutLifetimeIdentity(t *testing.T) {
	prompter := &actionPrompter{entered: make(chan struct{}, 2), actions: make(chan string, 2)}
	h := newCoordinatorHarness(prompter, 4)
	snapshot := &DecisionSnapshot{DefaultAction: profile.DefaultActionAsk}
	first, _ := coordinatorPending(FileEvent{PID: 42, Exe: "/usr/bin/app", Path: "/tmp/file", Op: OpOpen})
	second, _ := coordinatorPending(FileEvent{PID: 42, Exe: "/usr/bin/app", Path: "/tmp/file", Op: OpOpen})
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), first, nil, snapshot); !handled || !handedOff {
		t.Fatal("first unidentified event was not admitted")
	}
	if handled, handedOff, _, _ := h.coordinator.Admit(context.Background(), second, nil, snapshot); !handled || !handedOff {
		t.Fatal("second unidentified event was not admitted")
	}
	waitPromptStart(t, prompter)
	waitPromptStart(t, prompter)
	prompter.actions <- ActionDeny
	prompter.actions <- ActionDeny
}
