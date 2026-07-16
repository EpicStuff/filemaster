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

	lifecycle      *PipelineLifecycle
	markResult     MarkRemovalResult
	markStart      chan struct{}
	markBlock      chan struct{}
	markOnce       sync.Once
	reconcileBlock chan struct{}
	readerExit     chan struct{}
	groupClosed    chan struct{}
	marks          int
	closes         int
	cleanups       int
	scopeClean     bool
	reader         ReaderDiagnostics
	response       ResponseWriterDiagnostics
}

func (source *shutdownFakeSource) Run(context.Context, PendingHandler) error { return nil }
func (source *shutdownFakeSource) SetWatchPaths([]string) error              { return nil }
func (source *shutdownFakeSource) SetLifecycle(lifecycle *PipelineLifecycle) {
	source.lifecycle = lifecycle
}
func (source *shutdownFakeSource) WaitReconciliation(context.Context) error {
	if source.reconcileBlock != nil {
		<-source.reconcileBlock
	}
	return nil
}
func (source *shutdownFakeSource) WaitReaderDrained(context.Context) error { return nil }
func (source *shutdownFakeSource) WaitReaderExit(context.Context) error {
	if source.readerExit != nil {
		<-source.readerExit
		source.mu.Lock()
		source.reader.Exited = true
		source.mu.Unlock()
	}
	return nil
}

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

func (source *shutdownFakeSource) CloseGroup() error {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.closes++
	source.response.Sealed = true
	source.response.Closed = true
	if source.groupClosed != nil {
		close(source.groupClosed)
		source.groupClosed = nil
	}
	if source.readerExit == nil {
		source.reader.Exited = true
	}
	return nil
}

func (source *shutdownFakeSource) CleanupScopes() error {
	source.mu.Lock()
	defer source.mu.Unlock()
	if !source.scopeClean {
		source.cleanups++
		source.scopeClean = true
	}
	return nil
}

func (source *shutdownFakeSource) ScopeCleanupComplete() bool {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.scopeClean
}

func (source *shutdownFakeSource) Close() error {
	if err := source.CloseGroup(); err != nil {
		return err
	}
	return source.CleanupScopes()
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
		mgr:               mgr.New("fileaccess shutdown test"),
		source:            source,
		lifecycle:         lifecycle,
		shutdownDone:      make(chan struct{}),
		shutdownFinalDone: make(chan struct{}),
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
	select {
	case <-lifecycle.Closed():
	case <-time.After(time.Second):
		t.Fatal("worker exit did not allow final cleanup to publish Closed")
	}
	if final := fileAccess.ShutdownDiagnostics(); !final.FinalCleanupCompleted || final.Decision.ActiveWorkers != 0 {
		t.Fatalf("worker final cleanup incomplete: %+v", final)
	}
}

type shutdownAskHandler struct {
	started     chan struct{}
	release     chan struct{}
	coordinator *PromptCoordinator
	snapshot    *DecisionSnapshot
	store       RuleStore
}

func (handler *shutdownAskHandler) Decide(context.Context, *FileEvent) Verdict { return VerdictDeny }

func (handler *shutdownAskHandler) DecidePending(ctx context.Context, pending PendingEvent) (bool, bool, Verdict, func()) {
	close(handler.started)
	<-handler.release
	return handler.coordinator.Admit(ctx, pending, handler.store, handler.snapshot)
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
	coordinator.SnapshotReplaced(coordinatorSnapshot("prompt-close", 2, profile.DefaultActionPermit))
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
	replacement := &persistenceTestStore{}
	persistence.BindStore(snapshot.Source, snapshot.ProfileID, replacement)
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
	persistence.mu.Lock()
	binding := persistence.bindings[profileSnapshotKey(snapshot)]
	persistence.mu.Unlock()
	if !sameRuleStore(binding.store, store) {
		t.Fatal("final flush binding changed during Closing")
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

func TestShutdownBackgroundContextUsesBoundedReport(t *testing.T) {
	ctx, cancel := normalizeShutdownContext(context.Background(), 0)
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("normalized Background context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > defaultControlledShutdownTimeout {
		t.Fatalf("normalized deadline remaining = %s", remaining)
	}
	cancel()

	lifecycle := NewPipelineLifecycle()
	source := &shutdownFakeSource{
		markResult: MarkRemovalResult{Failures: []MarkRemovalFailure{{MountID: 7, Error: "persistent"}}},
		response:   ResponseWriterDiagnostics{CurrentFD: -1},
	}
	fileAccess := newShutdownTestFileAccess(source, lifecycle)
	fileAccess.shutdownTimeout = 40 * time.Millisecond
	started := time.Now()
	if err := fileAccess.Shutdown(context.Background()); err == nil {
		t.Fatal("permanent mark failure unexpectedly produced a successful report")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Background shutdown exceeded bounded report: %s", elapsed)
	}
	select {
	case <-fileAccess.shutdownFinalDone:
	case <-time.After(time.Second):
		t.Fatal("final cleanup did not complete after bounded mark retries")
	}
	source.mu.Lock()
	attempts := source.marks
	source.mu.Unlock()
	if attempts == 0 || attempts > 10 {
		t.Fatalf("bounded mark attempts = %d", attempts)
	}
}

func TestDecisionPipelineWaitWorkersIncludesRegisteredIdleWorkers(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	pipeline := newDecisionPipeline(HandlerFunc(func(context.Context, *FileEvent) Verdict { return VerdictAllow }), DecisionPipelineConfig{Workers: 2}, lifecycle)
	pipeline.Activate()
	lifecycle.BeginClosing(context.Background())
	short, cancelShort := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := pipeline.WaitWorkers(short); err == nil {
		t.Fatal("registered but not started workers were treated as exited")
	}
	cancelShort()
	go func() { _ = pipeline.Run(context.Background()) }()
	go func() { _ = pipeline.Run(context.Background()) }()
	wait, cancelWait := context.WithTimeout(context.Background(), time.Second)
	defer cancelWait()
	if err := pipeline.WaitWorkers(wait); err != nil {
		t.Fatal(err)
	}
	diagnostics := pipeline.Diagnostics()
	if diagnostics.ActiveWorkers != 0 || diagnostics.ExitedWorkers != diagnostics.ExpectedWorkers {
		t.Fatalf("worker join diagnostics = %+v", diagnostics)
	}
}

func TestFinishTransferredPromptEventReportsOnlyCurrentAttemptAcceptance(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	pipeline := newDecisionPipeline(HandlerFunc(func(context.Context, *FileEvent) Verdict { return VerdictAllow }), DecisionPipelineConfig{}, lifecycle)
	owner := newPendingEvent(&FileEvent{Path: "/tmp/prior"}, func(Verdict) responseResult {
		return responseResult{accepted: true}
	})
	transferred, err := owner.Transfer()
	if err != nil {
		t.Fatal(err)
	}
	if err := transferred.Respond(VerdictDeny); err != nil {
		t.Fatal(err)
	}
	if pipeline.finishTransferredPromptEvent(context.Background(), transferred, VerdictAllow) {
		t.Fatal("acceptance from the earlier shutdown response was reused")
	}

	closeErrOwner := newPendingEvent(&FileEvent{Path: "/tmp/close-error"}, func(Verdict) responseResult {
		return responseResult{accepted: true, err: errors.New("close failed")}
	})
	if !pipeline.finishTransferredPromptEvent(context.Background(), closeErrOwner, VerdictAllow) {
		t.Fatal("accepted response with a later close error was not attributed to its own attempt")
	}
}

func TestPromptAlwaysWithAcceptedCloseErrorPersists(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	pipeline := newDecisionPipeline(HandlerFunc(func(context.Context, *FileEvent) Verdict { return VerdictAllow }), DecisionPipelineConfig{}, lifecycle)
	prompt := &shutdownPrompt{started: make(chan struct{}), action: make(chan string, 1)}
	coordinator := newPromptCoordinator(prompt, time.Second, func(string) (func(), bool) { return func() {}, true }, pipeline.finishTransferredPromptEvent, lifecycle)
	store := &persistenceTestStore{started: make(chan struct{}, 1), release: make(chan struct{})}
	pending := newPendingEvent(&FileEvent{Path: "/tmp/accepted-close-error", Op: OpOpen}, func(Verdict) responseResult {
		return responseResult{accepted: true, err: errors.New("close failed")}
	})
	snapshot := coordinatorSnapshot("accepted-close-error", 1, profile.DefaultActionAsk)
	if handled, handedOff, _, _ := coordinator.Admit(context.Background(), pending, store, snapshot); !handled || !handedOff {
		t.Fatal("prompt was not admitted")
	}
	<-prompt.started
	prompt.action <- ActionAllowAlways
	select {
	case <-store.started:
	case <-time.After(time.Second):
		t.Fatal("accepted response with close error did not persist Always intent")
	}
	diagnostics := coordinator.RulePersistence().Diagnostics()[snapshot.Source+"/"+snapshot.ProfileID]
	if diagnostics.DirtyCount != 1 {
		t.Fatalf("accepted Always rule was not dirty while storage blocked: %+v", diagnostics)
	}
	close(store.release)
}

func TestShutdownRejectsLateSnapshotAndStoreBindingPublication(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	coordinator := newPromptCoordinator(nil, time.Second, nil, nil, lifecycle)
	first := coordinatorSnapshot("publication", 1, profile.DefaultActionAsk)
	coordinator.SnapshotReplaced(first)
	storeA := &persistenceTestStore{}
	storeB := &persistenceTestStore{}
	coordinator.RulePersistence().BindStore(first.Source, first.ProfileID, storeA)
	lifecycle.BeginClosing(context.Background())
	coordinator.SnapshotReplaced(coordinatorSnapshot("publication", 2, profile.DefaultActionPermit))
	coordinator.RulePersistence().BindStore(first.Source, first.ProfileID, storeB)

	key := first.Source + "/" + first.ProfileID
	coordinator.mu.Lock()
	latest := coordinator.latestProfileSnapshot[key]
	coordinator.mu.Unlock()
	if latest == nil || latest.Revision != 1 {
		t.Fatalf("late snapshot replaced revision: %+v", latest)
	}
	coordinator.RulePersistence().mu.Lock()
	binding := coordinator.RulePersistence().bindings[key]
	coordinator.RulePersistence().mu.Unlock()
	if !sameRuleStore(binding.store, storeA) {
		t.Fatal("late store rebinding replaced the final Running binding")
	}
}

func TestProfileSnapshotPublicationFinishesInsideClosingBarrier(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	coordinator := newPromptCoordinator(nil, time.Second, nil, nil, lifecycle)
	handler := &ProfileHandler{lifecycle: lifecycle}
	handler.setPromptCoordinator(coordinator)
	entered := make(chan struct{})
	release := make(chan struct{})
	handler.beforeSnapshotPublication = func() {
		close(entered)
		<-release
	}
	snapshot := coordinatorSnapshot("barrier", 1, profile.DefaultActionAsk)
	published := make(chan struct{})
	go func() {
		handler.publishSnapshot(snapshot)
		close(published)
	}()
	<-entered
	closing := make(chan struct{})
	go func() {
		lifecycle.BeginClosing(context.Background())
		close(closing)
	}()
	select {
	case <-closing:
		t.Fatal("Closing passed an active snapshot publication")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	<-published
	<-closing
	key := snapshot.Source + "/" + snapshot.ProfileID
	coordinator.mu.Lock()
	latest := coordinator.latestProfileSnapshot[key]
	coordinator.mu.Unlock()
	if latest == nil || latest.Revision != 1 {
		t.Fatalf("in-flight publication was not completed: %+v", latest)
	}
	handler.publishSnapshot(coordinatorSnapshot("barrier", 2, profile.DefaultActionPermit))
	coordinator.mu.Lock()
	latest = coordinator.latestProfileSnapshot[key]
	coordinator.mu.Unlock()
	if latest.Revision != 1 {
		t.Fatalf("publication after Closing was accepted: %+v", latest)
	}
}

func TestShutdownTransferredPromptRaceCannotPersistLosingAlways(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	prompt := &shutdownPrompt{started: make(chan struct{}), action: make(chan string, 1)}
	handlerRelease := make(chan struct{})
	close(handlerRelease)
	handler := &shutdownAskHandler{started: make(chan struct{}), release: handlerRelease, store: &persistenceTestStore{}}
	pipeline := newDecisionPipeline(handler, DecisionPipelineConfig{Workers: 1, QueueCapacity: 1}, lifecycle)
	coordinator := newPromptCoordinator(prompt, time.Second, pipeline.acquireAsk, pipeline.finishTransferredPromptEvent, lifecycle)
	coordinator.complete = pipeline.releaseOutstanding
	handler.coordinator = coordinator
	handler.snapshot = coordinatorSnapshot("three-way", 1, profile.DefaultActionAsk)

	admitted := make(chan struct{})
	releaseAdmission := make(chan struct{})
	coordinator.afterAdmission = func() {
		close(admitted)
		<-releaseAdmission
	}
	userResolving := make(chan struct{})
	releaseUser := make(chan struct{})
	coordinator.beforePromptResolve = func() {
		close(userResolving)
		<-releaseUser
	}

	workerCtx, cancelWorker := context.WithCancel(context.Background())
	defer cancelWorker()
	pipeline.Start(workerCtx)
	pending, responses := pipelinePending(FileEvent{Path: "/tmp/three-way", Op: OpOpen})
	if err := pipeline.Handle(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	<-admitted
	<-prompt.started
	prompt.action <- ActionAllowAlways
	<-userResolving

	lifecycle.BeginClosing(context.Background())
	pipeline.resolveActiveForShutdown()
	drainDone := make(chan error, 1)
	go func() { drainDone <- coordinator.Drain(context.Background()) }()
	if verdict := <-responses; verdict != VerdictDeny {
		t.Fatalf("three-way shutdown verdict = %v, want deny", verdict)
	}
	close(releaseUser)
	if err := <-drainDone; err != nil {
		t.Fatal(err)
	}
	close(releaseAdmission)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := pipeline.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pipeline.WaitOutstanding(ctx); err != nil {
		t.Fatal(err)
	}
	if diagnostics := pipeline.Diagnostics(); diagnostics.Outstanding != 0 || diagnostics.PendingAsk != 0 {
		t.Fatalf("three-way accounting was not released exactly once: %+v", diagnostics)
	}
	select {
	case duplicate := <-responses:
		t.Fatalf("event received a second verdict: %v", duplicate)
	default:
	}
	for key, diagnostics := range coordinator.RulePersistence().Diagnostics() {
		if diagnostics.DirtyCount != 0 {
			t.Fatalf("losing Allow Always created dirty work for %s: %+v", key, diagnostics)
		}
	}
	if diagnostics := coordinator.Diagnostics(); diagnostics.Groups != 0 || diagnostics.Events != 0 || diagnostics.ActivePrompts != 0 {
		t.Fatalf("three-way prompt did not exit: %+v", diagnostics)
	}
}

func TestShutdownReaderJoinPreventsClosedUntilReaderExits(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	readerExit := make(chan struct{})
	groupClosed := make(chan struct{})
	source := &shutdownFakeSource{
		markResult:  MarkRemovalResult{Complete: true},
		readerExit:  readerExit,
		groupClosed: groupClosed,
		response:    ResponseWriterDiagnostics{CurrentFD: -1},
	}
	fileAccess := newShutdownTestFileAccess(source, lifecycle)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	report := make(chan error, 1)
	go func() { report <- fileAccess.Shutdown(ctx) }()
	<-groupClosed
	if err := <-report; err == nil {
		t.Fatal("reader join blocker unexpectedly produced a successful report")
	}
	diagnostics := fileAccess.ShutdownDiagnostics()
	if lifecycle.State() != LifecycleClosing || diagnostics.Source.ReaderJoinError == "" || diagnostics.FinalCleanupCompleted {
		t.Fatalf("reader join was not reported as pending: %+v", diagnostics)
	}
	close(readerExit)
	select {
	case <-lifecycle.Closed():
	case <-time.After(time.Second):
		t.Fatal("reader release did not allow final Closed publication")
	}
	if final := fileAccess.ShutdownDiagnostics(); !final.Source.ReaderExited || !final.FinalCleanupCompleted {
		t.Fatalf("reader final diagnostics incomplete: %+v", final)
	}
}

func TestShutdownReconciliationPreventsClosedUntilExit(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	reconciliation := make(chan struct{})
	source := &shutdownFakeSource{
		markResult:     MarkRemovalResult{Complete: true},
		reconcileBlock: reconciliation,
		response:       ResponseWriterDiagnostics{CurrentFD: -1},
	}
	fileAccess := newShutdownTestFileAccess(source, lifecycle)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := fileAccess.Shutdown(ctx); err == nil {
		t.Fatal("blocked reconciliation unexpectedly produced a successful report")
	}
	diagnostics := fileAccess.ShutdownDiagnostics()
	if lifecycle.State() != LifecycleClosing || diagnostics.ReconciliationStopped || diagnostics.ReconciliationError == "" {
		t.Fatalf("reconciliation blocker missing from diagnostics: %+v", diagnostics)
	}
	close(reconciliation)
	select {
	case <-lifecycle.Closed():
	case <-time.After(time.Second):
		t.Fatal("reconciliation release did not allow Closed publication")
	}
}
