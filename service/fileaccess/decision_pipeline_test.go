package fileaccess

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/safing/portmaster/service/profile"
)

func pipelinePending(event FileEvent) (PendingEvent, <-chan Verdict) {
	responses := make(chan Verdict, 1)
	pending := newPendingEvent(&event, func(verdict Verdict) responseResult {
		responses <- verdict
		return responseResult{accepted: true}
	})
	return pending, responses
}

func waitPipelineVerdict(t *testing.T, responses <-chan Verdict) Verdict {
	t.Helper()
	select {
	case verdict := <-responses:
		return verdict
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for pipeline verdict")
		return VerdictDeny
	}
}

func TestDecisionPipelineCompletesIndependentEventsConcurrently(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	pipeline := NewDecisionPipeline(HandlerFunc(func(context.Context, *FileEvent) Verdict {
		started <- struct{}{}
		<-release
		return VerdictAllow
	}), DecisionPipelineConfig{Workers: 2, QueueCapacity: 2, OutstandingLimit: 2})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)

	first, firstResponses := pipelinePending(FileEvent{PID: 1, Path: "/tmp/first"})
	second, secondResponses := pipelinePending(FileEvent{PID: 2, Path: "/tmp/second"})
	if err := pipeline.Handle(ctx, first); err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	if err := pipeline.Handle(ctx, second); err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("independent decision did not reach a second worker")
		}
	}
	close(release)
	if got := waitPipelineVerdict(t, firstResponses); got != VerdictAllow {
		t.Fatalf("first verdict = %s, want allow", got)
	}
	if got := waitPipelineVerdict(t, secondResponses); got != VerdictAllow {
		t.Fatalf("second verdict = %s, want allow", got)
	}
}

func TestDecisionPipelineQueueIsBoundedAndSaturationResolvesOwnership(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	pipeline := NewDecisionPipeline(HandlerFunc(func(context.Context, *FileEvent) Verdict {
		started <- struct{}{}
		<-release
		return VerdictAllow
	}), DecisionPipelineConfig{Workers: 1, QueueCapacity: 1, OutstandingLimit: 3})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)

	first, firstResponses := pipelinePending(FileEvent{Path: "/tmp/first"})
	second, secondResponses := pipelinePending(FileEvent{Path: "/tmp/second"})
	third, thirdResponses := pipelinePending(FileEvent{Path: "/tmp/third"})
	if err := pipeline.Handle(ctx, first); err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	<-started
	if err := pipeline.Handle(ctx, second); err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	if got := pipeline.Diagnostics().QueueDepth; got != 1 {
		t.Fatalf("queue depth = %d, want 1", got)
	}
	if err := pipeline.Handle(ctx, third); err != nil {
		t.Fatalf("third Handle: %v", err)
	}
	if got := waitPipelineVerdict(t, thirdResponses); got != VerdictDeny {
		t.Fatalf("saturated verdict = %s, want deny", got)
	}
	if err := third.Respond(VerdictAllow); !errors.Is(err, ErrPendingEventAlreadyResolved) {
		t.Fatalf("saturated event remained owned: %v", err)
	}
	if got := pipeline.Diagnostics().QueueSaturationDenies; got != 1 {
		t.Fatalf("queue saturation denies = %d, want 1", got)
	}
	close(release)
	if got := waitPipelineVerdict(t, firstResponses); got != VerdictAllow {
		t.Fatalf("first verdict = %s, want allow", got)
	}
	if got := waitPipelineVerdict(t, secondResponses); got != VerdictAllow {
		t.Fatalf("second verdict = %s, want allow", got)
	}
}

func TestDecisionPipelineGlobalBudgetDeniesImmediately(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	pipeline := NewDecisionPipeline(HandlerFunc(func(context.Context, *FileEvent) Verdict {
		started <- struct{}{}
		<-release
		return VerdictAllow
	}), DecisionPipelineConfig{Workers: 1, QueueCapacity: 2, OutstandingLimit: 1})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)

	first, firstResponses := pipelinePending(FileEvent{Path: "/tmp/first"})
	second, secondResponses := pipelinePending(FileEvent{Path: "/tmp/second"})
	if err := pipeline.Handle(ctx, first); err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	<-started
	if err := pipeline.Handle(ctx, second); err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	if got := waitPipelineVerdict(t, secondResponses); got != VerdictDeny {
		t.Fatalf("global budget verdict = %s, want deny", got)
	}
	if got := pipeline.Diagnostics().OutstandingBudgetDenies; got != 1 {
		t.Fatalf("global budget denies = %d, want 1", got)
	}
	close(release)
	if got := waitPipelineVerdict(t, firstResponses); got != VerdictAllow {
		t.Fatalf("first verdict = %s, want allow", got)
	}
}

type blockingPrompter struct {
	entered chan struct{}
	release <-chan struct{}
}

func (p *blockingPrompter) Prompt(context.Context, FileEvent, time.Duration) (string, bool) {
	p.entered <- struct{}{}
	<-p.release
	return ActionAllow, true
}

type askLookup struct{ store RuleStore }

func (l askLookup) Lookup(context.Context, int32) (LookupResult, error) {
	snapshot := newDecisionSnapshot("profile", "local", profile.DefaultActionAsk, ruleLists{}, 1)
	return LookupResult{
		Path:          "/usr/bin/test",
		Store:         l.store,
		Snapshot:      snapshot,
		DefaultAction: snapshot.DefaultAction,
		ProfileSource: snapshot.Source,
	}, nil
}

func TestDecisionPipelinePerProfileAskBudget(t *testing.T) {
	release := make(chan struct{})
	prompter := &blockingPrompter{entered: make(chan struct{}, 1), release: release}
	handler := NewProfileHandler(askLookup{store: &fakeRuleStore{id: "profile"}}, prompter, nil, time.Second, nopLogger{})
	pipeline := NewDecisionPipeline(handler, DecisionPipelineConfig{Workers: 2, QueueCapacity: 2, OutstandingLimit: 2, PerProfileAskLimit: 1})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)

	first, firstResponses := pipelinePending(FileEvent{PID: 1, Path: "/tmp/first"})
	second, secondResponses := pipelinePending(FileEvent{PID: 2, Path: "/tmp/second"})
	if err := pipeline.Handle(ctx, first); err != nil {
		t.Fatalf("first Handle: %v", err)
	}
	<-prompter.entered
	if err := pipeline.Handle(ctx, second); err != nil {
		t.Fatalf("second Handle: %v", err)
	}
	if got := waitPipelineVerdict(t, secondResponses); got != VerdictDeny {
		t.Fatalf("per-profile overload verdict = %s, want deny", got)
	}
	if got := pipeline.Diagnostics().ProfileAskBudgetDenies; got != 1 {
		t.Fatalf("per-profile overload denies = %d, want 1", got)
	}
	close(release)
	if got := waitPipelineVerdict(t, firstResponses); got != VerdictAllow {
		t.Fatalf("first verdict = %s, want allow", got)
	}
}

type execRefreshHandler struct{ refreshed chan int32 }

func (h *execRefreshHandler) Decide(context.Context, *FileEvent) Verdict { return VerdictAllow }
func (h *execRefreshHandler) RefreshProcessMapping(_ context.Context, pid int32) error {
	h.refreshed <- pid
	return nil
}

func TestDecisionPipelineRefreshesAllowedExecMapping(t *testing.T) {
	handler := &execRefreshHandler{refreshed: make(chan int32, 1)}
	pipeline := NewDecisionPipeline(handler, DecisionPipelineConfig{Workers: 1, QueueCapacity: 1, OutstandingLimit: 1})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)
	pending, responses := pipelinePending(FileEvent{PID: 91, Path: "/tmp/exec", Op: OpExec})
	if err := pipeline.Handle(ctx, pending); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := waitPipelineVerdict(t, responses); got != VerdictAllow {
		t.Fatalf("exec verdict = %s, want allow", got)
	}
	select {
	case pid := <-handler.refreshed:
		if pid != 91 {
			t.Fatalf("refreshed pid = %d, want 91", pid)
		}
	case <-time.After(time.Second):
		t.Fatal("allowed exec did not refresh process mapping")
	}
}

func TestDecisionPipelineProfileHandlerExecUsesLaunchingProfile(t *testing.T) {
	// Exec flows through the profile like read/write. A block default denies the
	// launch via the launching process's profile, which must be consulted.
	lookup := &fakeLookup{profiles: map[int32]*fakeProfile{
		91: {id: "launcher", defAct: profile.DefaultActionBlock},
	}}
	handler := NewProfileHandler(lookup, nil, nil, time.Second, nopLogger{})
	pipeline := NewDecisionPipeline(handler, DecisionPipelineConfig{Workers: 1, QueueCapacity: 1, OutstandingLimit: 1})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)

	pending, responses := pipelinePending(FileEvent{PID: 91, Path: "/tmp/target", Op: OpExec})
	if err := pipeline.Handle(ctx, pending); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := waitPipelineVerdict(t, responses); got != VerdictDeny {
		t.Fatalf("exec verdict = %s, want deny from block default", got)
	}

	lookup.mu.Lock()
	calls := lookup.calls
	lookup.mu.Unlock()
	// Exactly one lookup: DecidePending resolves the block default and reports
	// it as decided, so the pipeline responds without re-running DecideForResponse.
	if calls != 1 {
		t.Fatalf("pipeline consulted launching PID profile %d times for exec, want 1 (no double lookup)", calls)
	}
}

func TestDecisionPipelineReportsPendingAskByProfile(t *testing.T) {
	pipeline := NewDecisionPipeline(allowAll, DecisionPipelineConfig{Workers: 1, QueueCapacity: 1, OutstandingLimit: 4, PerProfileAskLimit: 4})

	releaseA1, ok := pipeline.acquireAsk("local/a")
	if !ok {
		t.Fatal("acquire local/a #1 denied")
	}
	releaseA2, ok := pipeline.acquireAsk("local/a")
	if !ok {
		t.Fatal("acquire local/a #2 denied")
	}
	releaseB, ok := pipeline.acquireAsk("local/b")
	if !ok {
		t.Fatal("acquire local/b denied")
	}

	diag := pipeline.Diagnostics()
	if diag.PendingAsk != 3 {
		t.Fatalf("aggregate PendingAsk = %d, want 3", diag.PendingAsk)
	}
	if got := diag.PendingAskByProfile["local/a"]; got != 2 {
		t.Fatalf("PendingAskByProfile[local/a] = %d, want 2", got)
	}
	if got := diag.PendingAskByProfile["local/b"]; got != 1 {
		t.Fatalf("PendingAskByProfile[local/b] = %d, want 1", got)
	}

	releaseA1()
	releaseA2()
	releaseB()
	if diag := pipeline.Diagnostics(); len(diag.PendingAskByProfile) != 0 {
		t.Fatalf("PendingAskByProfile after release = %v, want empty", diag.PendingAskByProfile)
	}
}

type observingHandler struct {
	inner     Handler
	responded atomic.Bool
	observed  chan bool
}

func (h *observingHandler) Decide(context.Context, *FileEvent) Verdict { return VerdictDeny }
func (h *observingHandler) DecisionHandler() Handler                   { return h.inner }
func (h *observingHandler) Observe(*FileEvent, Verdict)                { h.observed <- h.responded.Load() }

func TestDecisionPipelineRespondsBeforeObservation(t *testing.T) {
	observer := &observingHandler{
		inner:    HandlerFunc(func(context.Context, *FileEvent) Verdict { return VerdictAllow }),
		observed: make(chan bool, 1),
	}
	pipeline := NewDecisionPipeline(observer, DecisionPipelineConfig{Workers: 1, QueueCapacity: 1, OutstandingLimit: 1})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)
	responses := make(chan Verdict, 1)
	pending := newPendingEvent(&FileEvent{Path: "/tmp/observe"}, func(verdict Verdict) responseResult {
		observer.responded.Store(true)
		responses <- verdict
		return responseResult{accepted: true}
	})
	if err := pipeline.Handle(ctx, pending); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := waitPipelineVerdict(t, responses); got != VerdictAllow {
		t.Fatalf("verdict = %s, want allow", got)
	}
	select {
	case afterResponse := <-observer.observed:
		if !afterResponse {
			t.Fatal("observation ran before response")
		}
	case <-time.After(time.Second):
		t.Fatal("observation did not run")
	}
}

func TestDecisionPipelineFilemasterSelfSnapshot(t *testing.T) {
	lookup := &fakeLookup{err: errors.New("normal lookup must not run")}
	handler := NewProfileHandler(lookup, &scriptedPrompter{}, nil, time.Second, nopLogger{})
	store := &fakeRuleStore{id: profile.PortmasterProfileID}
	snapshot := newDecisionSnapshot(profile.PortmasterProfileID, "local", profile.DefaultActionAsk, ruleLists{read: []string{"- /tmp/self"}}, 1)
	handler.setSelfProfile(77, LookupResult{
		Store:         store,
		Snapshot:      snapshot,
		DefaultAction: snapshot.DefaultAction,
		ProfileSource: snapshot.Source,
	})
	pipeline := NewDecisionPipeline(handler, DecisionPipelineConfig{Workers: 1, QueueCapacity: 1, OutstandingLimit: 1})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pipeline.Start(ctx)
	pending, responses := pipelinePending(FileEvent{PID: 77, Path: "/tmp/self"})
	if err := pipeline.Handle(ctx, pending); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := waitPipelineVerdict(t, responses); got != VerdictDeny {
		t.Fatalf("self snapshot verdict = %s, want deny", got)
	}
}
