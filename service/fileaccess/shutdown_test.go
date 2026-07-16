package fileaccess

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/safing/portmaster/service/mgr"
	"github.com/safing/portmaster/service/profile"
)

type shutdownFakeSource struct {
	mu sync.Mutex

	lifecycle  *PipelineLifecycle
	markResult MarkRemovalResult
	markStart  chan struct{}
	markBlock  chan struct{}
	markOnce   sync.Once
	marks      int
	closes     int
	reader     ReaderDiagnostics
	response   ResponseWriterDiagnostics
}

func (source *shutdownFakeSource) Run(context.Context, PendingHandler) error { return nil }
func (source *shutdownFakeSource) SetWatchPaths([]string) error              { return nil }
func (source *shutdownFakeSource) SetLifecycle(lifecycle *PipelineLifecycle) {
	source.lifecycle = lifecycle
}
func (source *shutdownFakeSource) WaitReconciliation(context.Context) error { return nil }
func (source *shutdownFakeSource) WaitReaderDrained(context.Context) error  { return nil }
func (source *shutdownFakeSource) WaitReaderExit(context.Context) error     { return nil }

func (source *shutdownFakeSource) RemoveAllMarks() MarkRemovalResult {
	source.markOnce.Do(func() {
		if source.markStart != nil {
			close(source.markStart)
		}
	})
	if source.markBlock != nil {
		<-source.markBlock
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	source.marks++
	return source.markResult
}

func (source *shutdownFakeSource) PrepareClose(ctx context.Context) error {
	source.mu.Lock()
	source.response.Sealed = true
	current := source.response.CurrentFD
	source.mu.Unlock()
	if current < 0 {
		return nil
	}
	<-ctx.Done()
	return ctx.Err()
}

func (source *shutdownFakeSource) Close() error {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.closes++
	source.response.Closed = true
	source.reader.Exited = true
	return nil
}

func (source *shutdownFakeSource) ReaderDiagnostics() ReaderDiagnostics {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.reader
}

func (source *shutdownFakeSource) ResponseDiagnostics() ResponseWriterDiagnostics {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.response
}

func newShutdownTestFileAccess(source Source, lifecycle *PipelineLifecycle) *FileAccess {
	return &FileAccess{
		mgr:          mgr.New("fileaccess shutdown test"),
		source:       source,
		lifecycle:    lifecycle,
		shutdownDone: make(chan struct{}),
	}
}

func TestShutdownConcurrentCallsShareOneResult(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	source := &shutdownFakeSource{
		markResult: MarkRemovalResult{Complete: true},
		markStart:  make(chan struct{}),
		markBlock:  make(chan struct{}),
		response:   ResponseWriterDiagnostics{CurrentFD: -1},
	}
	fileAccess := newShutdownTestFileAccess(source, lifecycle)

	results := make(chan error, 2)
	go func() { results <- fileAccess.Shutdown(context.Background()) }()
	<-source.markStart
	go func() { results <- fileAccess.Shutdown(context.Background()) }()
	close(source.markBlock)

	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("shutdown failed: %v", err)
		}
	}
	if lifecycle.State() != LifecycleClosed {
		t.Fatalf("lifecycle state = %s, want closed", lifecycle.State())
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.marks != 1 || source.closes != 1 {
		t.Fatalf("mark attempts=%d closes=%d, want one each", source.marks, source.closes)
	}
}

func TestShutdownQueueAdmissionAndQueuedOwnershipDrain(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	pipeline := newDecisionPipeline(HandlerFunc(func(context.Context, *FileEvent) Verdict {
		return VerdictAllow
	}), DecisionPipelineConfig{Workers: 1, QueueCapacity: 2}, lifecycle)
	pipeline.Activate()

	pending, response := pipelinePending(FileEvent{Path: "/tmp/queued"})
	if err := pipeline.Handle(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	lifecycle.BeginClosing(context.Background())
	if err := pipeline.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if verdict := <-response; verdict != VerdictDeny {
		t.Fatalf("queued shutdown verdict = %v, want deny", verdict)
	}

	rejected, rejectedResponse := pipelinePending(FileEvent{Path: "/tmp/rejected"})
	if err := pipeline.Handle(context.Background(), rejected); err != nil {
		t.Fatal(err)
	}
	if verdict := <-rejectedResponse; verdict != VerdictDeny {
		t.Fatalf("closing admission verdict = %v, want deny", verdict)
	}
	if diagnostics := pipeline.Diagnostics(); diagnostics.Outstanding != 0 || diagnostics.QueueDepth != 0 {
		t.Fatalf("pipeline not drained: %+v", diagnostics)
	}
}

type blockedDecisionHandler struct {
	started chan struct{}
	release chan struct{}
}

func (handler *blockedDecisionHandler) Decide(context.Context, *FileEvent) Verdict {
	close(handler.started)
	<-handler.release
	return VerdictAllow
}

func TestShutdownDeadlineReportsBlockedActiveWorker(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	handler := &blockedDecisionHandler{started: make(chan struct{}), release: make(chan struct{})}
	pipeline := newDecisionPipeline(handler, DecisionPipelineConfig{Workers: 1, QueueCapacity: 1}, lifecycle)
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	defer cancelWorker()
	pipeline.Start(workerCtx)
	pending, response := pipelinePending(FileEvent{Path: "/tmp/active"})
	if err := pipeline.Handle(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	<-handler.started

	source := &shutdownFakeSource{
		markResult: MarkRemovalResult{Complete: true},
		response:   ResponseWriterDiagnostics{CurrentFD: -1},
	}
	fileAccess := newShutdownTestFileAccess(source, lifecycle)
	fileAccess.pipeline = pipeline
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := fileAccess.Shutdown(ctx)
	if err == nil {
		t.Fatal("shutdown unexpectedly succeeded with blocked worker")
	}
	if verdict := <-response; verdict != VerdictDeny {
		t.Fatalf("active shutdown verdict = %v, want deny", verdict)
	}
	diagnostics := fileAccess.ShutdownDiagnostics()
	if !diagnostics.DeadlineExpired || diagnostics.Decision.ActiveDecisions != 1 {
		t.Fatalf("missing blocked worker diagnostics: %+v", diagnostics)
	}
	found := false
	for _, owner := range diagnostics.Unresolved {
		if owner.Location == "active_workers" && owner.Count == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("active owner not reported: %+v", diagnostics.Unresolved)
	}
	close(handler.release)
}

type shutdownAskHandler struct {
	started     chan struct{}
	release     chan struct{}
	coordinator *PromptCoordinator
	snapshot    *DecisionSnapshot
}

func (handler *shutdownAskHandler) Decide(context.Context, *FileEvent) Verdict { return VerdictDeny }

func (handler *shutdownAskHandler) DecidePending(ctx context.Context, pending PendingEvent) (bool, bool, Verdict, func()) {
	close(handler.started)
	<-handler.release
	return handler.coordinator.Admit(ctx, pending, nil, handler.snapshot)
}

func TestShutdownAskTransferRecheckDeniesWithoutPrompt(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	var prompts atomic.Int64
	handler := &shutdownAskHandler{started: make(chan struct{}), release: make(chan struct{})}
	pipeline := newDecisionPipeline(handler, DecisionPipelineConfig{Workers: 1, QueueCapacity: 1}, lifecycle)
	handler.coordinator = newPromptCoordinator(
		coordinatorPrompterFunc(func(context.Context, FileEvent, time.Duration) (string, bool) {
			prompts.Add(1)
			return ActionAllow, true
		}),
		time.Second,
		pipeline.acquireAsk,
		pipeline.finishPromptEvent,
		lifecycle,
	)
	handler.snapshot = coordinatorSnapshot("ask-close", 1, profile.DefaultActionAsk)
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	defer cancelWorker()
	pipeline.Start(workerCtx)
	pending, response := pipelinePending(FileEvent{Path: "/tmp/ask"})
	if err := pipeline.Handle(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	<-handler.started
	lifecycle.BeginClosing(context.Background())
	close(handler.release)
	if verdict := <-response; verdict != VerdictDeny {
		t.Fatalf("Ask after Closing verdict = %v, want deny", verdict)
	}
	if prompts.Load() != 0 {
		t.Fatalf("created %d prompts after Closing", prompts.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pipeline.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pipeline.WaitOutstanding(ctx); err != nil {
		t.Fatal(err)
	}
	if diagnostics := pipeline.Diagnostics(); diagnostics.ActiveDecisions != 0 || diagnostics.Outstanding != 0 {
		t.Fatalf("Ask worker did not exit cleanly: %+v", diagnostics)
	}
}

type shutdownPrompt struct {
	started chan struct{}
	action  chan string
}

func (prompt *shutdownPrompt) Prompt(ctx context.Context, _ FileEvent, _ time.Duration) (string, bool) {
	close(prompt.started)
	select {
	case action := <-prompt.action:
		return action, true
	case <-ctx.Done():
		return "", false
	}
}

func TestShutdownPromptClaimWinsOnceAndDoesNotPersist(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	prompter := &shutdownPrompt{started: make(chan struct{}), action: make(chan string, 1)}
	var releases atomic.Int64
	coordinator := newPromptCoordinator(prompter, time.Second, func(string) (func(), bool) {
		return func() { releases.Add(1) }, true
	}, func(_ context.Context, pending PendingEvent, verdict Verdict) bool {
		return pending.Respond(verdict) == nil
	}, lifecycle)
	pending, response := coordinatorPending(FileEvent{Path: "/tmp/prompt"})
	if handled, handedOff, _, _ := coordinator.Admit(context.Background(), pending, &persistenceTestStore{}, coordinatorSnapshot("prompt-close", 1, profile.DefaultActionAsk)); !handled || !handedOff {
		t.Fatal("prompt was not admitted")
	}
	<-prompter.started
	lifecycle.BeginClosing(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := coordinator.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	prompter.action <- ActionAllowAlways
	if verdict := <-response; verdict != VerdictDeny {
		t.Fatalf("shutdown prompt verdict = %v, want deny", verdict)
	}
	if releases.Load() != 1 {
		t.Fatalf("prompt accounting released %d times, want once", releases.Load())
	}
	for key, diagnostics := range coordinator.RulePersistence().Diagnostics() {
		if diagnostics.DirtyCount != 0 {
			t.Fatalf("stale prompt persisted dirty work for %s: %+v", key, diagnostics)
		}
	}
}

func TestShutdownPermanentRuleFlushTimeoutPreservesOverlay(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	store := &persistenceTestStore{started: make(chan struct{}, 1), release: make(chan struct{})}
	persistence := newRulePersistence(nil, RulePersistenceOptions{}, lifecycle)
	snapshot := persistenceSnapshot()
	merged := persistence.Apply(snapshot, store, "/tmp/dirty", VerdictDeny)
	<-store.started
	lifecycle.BeginClosing(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := persistence.Flush(ctx)
	cancel()
	if err == nil {
		t.Fatal("flush unexpectedly succeeded while storage was blocked")
	}
	if verdict, ok := merged.Rules.Lookup("/tmp/dirty"); !ok || verdict != VerdictDeny {
		t.Fatalf("dirty overlay lost after timeout: verdict=%v ok=%t", verdict, ok)
	}
	diagnostics := persistence.Diagnostics()["local/profile"]
	if diagnostics.DirtyCount != 1 || len(diagnostics.DirtyGenerations) != 1 {
		t.Fatalf("dirty generation not retained: %+v", diagnostics)
	}
	close(store.release)
}

func TestShutdownPermanentRuleFlushSuccessAndFailureDiagnostics(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "storage failure", err: errors.New("storage unavailable")},
	} {
		t.Run(test.name, func(t *testing.T) {
			lifecycle := NewPipelineLifecycle()
			store := &persistenceTestStore{}
			if test.err != nil {
				store.errs = []error{test.err, test.err, test.err}
			}
			after := func(time.Duration) <-chan time.Time {
				if test.err == nil {
					return time.After(time.Millisecond)
				}
				return make(chan time.Time)
			}
			persistence := newRulePersistence(nil, RulePersistenceOptions{After: after}, lifecycle)
			persistence.Apply(persistenceSnapshot(), store, "/tmp/rule", VerdictAllow)
			lifecycle.BeginClosing(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			err := persistence.Flush(ctx)
			cancel()
			if test.err == nil && err != nil {
				t.Fatalf("flush failed: %v", err)
			}
			if test.err != nil {
				if err == nil {
					t.Fatal("failed store flush unexpectedly succeeded")
				}
				for _, diagnostics := range persistence.Diagnostics() {
					if diagnostics.DirtyCount == 0 || diagnostics.LastError == nil {
						t.Fatalf("failure diagnostics missing: %+v", diagnostics)
					}
				}
			}
		})
	}
}
