package fileaccess

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

type MarkRemovalFailure struct {
	MountID   int
	MountPath string
	Mask      uint64
	Error     string
}

type MarkRemovalResult struct {
	Complete bool
	Failures []MarkRemovalFailure
}

type MarkRemovalDiagnostics struct {
	Attempts int
	Complete bool
	Final    bool
	Pending  bool
	Failures []MarkRemovalFailure
	Errors   []MarkRemovalFailure
}

type markRemovalWorkerState struct {
	mu     sync.Mutex
	inCall bool
}

func (state *markRemovalWorkerState) beginCall(ctx context.Context, stop <-chan struct{}) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	select {
	case <-stop:
		return false
	default:
	}
	state.inCall = true
	return true
}

func (state *markRemovalWorkerState) endCall() {
	state.mu.Lock()
	state.inCall = false
	state.mu.Unlock()
}

func (state *markRemovalWorkerState) callInFlight() bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.inCall
}

type ResponseWriterDiagnostics struct {
	Sealed         bool
	Closed         bool
	CurrentFD      int32
	CurrentVerdict Verdict
	FatalError     string
}

type ReaderDiagnostics struct {
	DescriptorLimit            int64
	OutstandingDescriptors     int64
	PeakOutstandingDescriptors int64
	AccountedDescriptors       []int32
	FailedResponseDescriptors  []int32
	DescriptorPressure         bool
	EMFILECount                uint64
	QueueOverflowCount         uint64
	UnresolvedPathDenyCount    uint64
	Running                    bool
	Exited                     bool
	Degraded                   bool
	Fatal                      bool
	LastError                  string
	FatalError                 string
}

type SourceShutdownDiagnostics struct {
	ReaderRunning             bool
	ReaderExited              bool
	ReaderDrainComplete       bool
	ReaderDrainPending        bool
	ReaderDrainError          string
	ReaderJoinError           string
	OutstandingDescriptors    int64
	AccountedDescriptors      []int32
	FailedResponseDescriptors []int32
	Response                  ResponseWriterDiagnostics
	GroupClosed               bool
	GroupClosePending         bool
	GroupCloseError           string
	ScopeCleanupComplete      bool
	ScopeCleanupPending       bool
	ScopeCleanupError         string
}

type UnresolvedOwnership struct {
	Location    string
	Count       int
	Descriptors []int32
	Detail      string
}

type ShutdownDiagnostics struct {
	State                 LifecycleState
	ReportingCompleted    bool
	FinalCleanupCompleted bool
	DeadlineExpired       bool
	ConfigurationStopped  bool
	ReconciliationStopped bool
	ReconciliationError   string
	Marks                 MarkRemovalDiagnostics
	Source                SourceShutdownDiagnostics
	Decision              DecisionPipelineDiagnostics
	Prompt                PromptCoordinatorDiagnostics
	PermanentRules        map[string]RulePersistenceDiagnostics
	FlushError            string
	PipelineDrainError    string
	PromptDrainError      string
	OutstandingError      string
	WorkerWaitError       string
	Unresolved            []UnresolvedOwnership
}

type ShutdownError struct {
	Diagnostics ShutdownDiagnostics
}

func (shutdownErr *ShutdownError) Error() string {
	if shutdownErr == nil {
		return ""
	}
	d := shutdownErr.Diagnostics
	return fmt.Sprintf(
		"file access shutdown incomplete: state=%s report_complete=%t final_complete=%t deadline=%t unresolved=%d marks_complete=%t reconciliation_error=%q reader_drain_error=%q reader_join_error=%q worker_error=%q flush_error=%q",
		d.State,
		d.ReportingCompleted,
		d.FinalCleanupCompleted,
		d.DeadlineExpired,
		len(d.Unresolved),
		d.Marks.Complete,
		d.ReconciliationError,
		d.Source.ReaderDrainError,
		d.Source.ReaderJoinError,
		d.WorkerWaitError,
		d.FlushError,
	)
}

type controlledShutdownSource interface {
	RemoveAllMarks() MarkRemovalResult
	WaitReconciliation(context.Context) error
	WaitReaderDrained(context.Context) error
	CloseGroup() error
	CleanupScopes() error
	ScopeCleanupComplete() bool
	WaitReaderExit(context.Context) error
	ReaderDiagnostics() ReaderDiagnostics
	ResponseDiagnostics() ResponseWriterDiagnostics
}

func normalizeShutdownContext(ctx context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 {
		limit = defaultControlledShutdownTimeout
	}
	deadline := time.Now().Add(limit)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		return context.WithCancel(ctx)
	}
	return context.WithDeadline(ctx, deadline)
}

// Shutdown starts one shared shutdown execution. The first caller's bounded
// context defines the immutable reporting milestone; final safety cleanup keeps
// running independently and publishes Closed only after every required join and
// resource cleanup has completed.
func (fa *FileAccess) Shutdown(ctx context.Context) error {
	reportCtx, cancel := normalizeShutdownContext(ctx, fa.shutdownTimeout)
	started := false
	fa.shutdownOnce.Do(func() {
		started = true
		if fa.shutdownDone == nil {
			fa.shutdownDone = make(chan struct{})
		}
		if fa.shutdownFinalDone == nil {
			fa.shutdownFinalDone = make(chan struct{})
		}
		fa.lifecycle.BeginClosing(context.Background())
		go fa.runShutdownExecution(reportCtx, cancel)
	})
	if !started {
		cancel()
	}
	<-fa.shutdownDone
	fa.shutdownMu.Lock()
	defer fa.shutdownMu.Unlock()
	return fa.shutdownResult
}

func (fa *FileAccess) ShutdownDiagnostics() ShutdownDiagnostics {
	return fa.refreshShutdownDiagnostics()
}

func (fa *FileAccess) runShutdownExecution(reportCtx context.Context, cancel context.CancelFunc) {
	fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
		d.State = LifecycleClosing
		d.ConfigurationStopped = true
		_, controlled := fa.source.(controlledShutdownSource)
		d.Marks = MarkRemovalDiagnostics{Complete: !controlled, Final: !controlled, Pending: controlled}
		d.Source.GroupClosePending = fa.source != nil
		d.Source.GroupClosed = fa.source == nil
		d.ReconciliationStopped = !controlled
		d.Source.ScopeCleanupComplete = !controlled
		d.Source.ScopeCleanupPending = controlled
	})

	cleanupDone := make(chan struct{})
	go func() {
		fa.runFinalCleanup(reportCtx)
		close(cleanupDone)
	}()

	cleanupFinished := false
	select {
	case <-cleanupDone:
		cleanupFinished = true
	case <-reportCtx.Done():
		fa.refreshShutdownDiagnostics()
		fa.recordReportingDeadline(reportCtx.Err())
	}

	fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
		d.ReportingCompleted = true
		d.DeadlineExpired = reportCtx.Err() != nil && !cleanupFinished
	})
	report := fa.refreshShutdownDiagnostics()
	var result error
	if shutdownIncomplete(report) {
		result = &ShutdownError{Diagnostics: cloneShutdownDiagnostics(report)}
	}
	fa.shutdownMu.Lock()
	fa.shutdownResult = result
	fa.shutdownMu.Unlock()
	if cleanupFinished {
		fa.publishFinalCleanup(result)
	}
	close(fa.shutdownDone)
	cancel()
	if cleanupFinished {
		return
	}
	<-cleanupDone
	fa.publishFinalCleanup(result)
}

func (fa *FileAccess) publishFinalCleanup(result error) {
	fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.FinalCleanupCompleted = true })
	fa.lifecycle.PublishClosed(result)
	fa.refreshShutdownDiagnostics()
	close(fa.shutdownFinalDone)
}

func (fa *FileAccess) runFinalCleanup(reportCtx context.Context) {
	controlled, hasControlledSource := fa.source.(controlledShutdownSource)
	background := context.Background()

	reconciliationDone := make(chan error, 1)
	if hasControlledSource {
		go func() { reconciliationDone <- controlled.WaitReconciliation(background) }()
	} else {
		reconciliationDone <- nil
	}

	stopMarks := make(chan struct{})
	markDone := make(chan MarkRemovalDiagnostics, 1)
	markState := &markRemovalWorkerState{}
	if hasControlledSource {
		fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
			d.Marks.Pending = true
			d.Marks.Final = false
		})
		go func() {
			marks := fa.removeMarksUntilBounded(reportCtx, stopMarks, controlled, markState)
			fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
				d.Marks = mergeMarkDiagnostics(d.Marks, marks)
			})
			markDone <- marks
		}()
	} else {
		markDone <- MarkRemovalDiagnostics{Complete: true, Final: true, Pending: false}
	}

	pipelineDone := make(chan struct{})
	go func() {
		if fa.pipeline != nil {
			if err := fa.pipeline.Drain(background); err != nil {
				fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.PipelineDrainError = err.Error() })
			} else {
				fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.PipelineDrainError = "" })
			}
			if err := fa.pipeline.WaitOutstanding(background); err != nil {
				fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.OutstandingError = err.Error() })
			} else {
				fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.OutstandingError = "" })
			}
			if err := fa.pipeline.WaitWorkers(background); err != nil {
				fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.WorkerWaitError = err.Error() })
			} else {
				fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.WorkerWaitError = "" })
			}
		}
		close(pipelineDone)
	}()

	var coordinator *PromptCoordinator
	if fa.profileHandler != nil {
		coordinator = fa.profileHandler.coordinator()
	}
	promptDone := make(chan struct{})
	go func() {
		if coordinator != nil {
			if err := coordinator.Drain(background); err != nil {
				fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.PromptDrainError = err.Error() })
			} else {
				fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.PromptDrainError = "" })
			}
			if err := coordinator.FlushPermanentRules(reportCtx); err != nil {
				fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.FlushError = err.Error() })
			} else {
				fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.FlushError = "" })
			}
		}
		close(promptDone)
	}()

	<-pipelineDone
	<-promptDone

	marks := MarkRemovalDiagnostics{}
	markWorkerJoined := false
	select {
	case marks = <-markDone:
		markWorkerJoined = true
	case <-reportCtx.Done():
		if !hasControlledSource || !markState.callInFlight() {
			marks = <-markDone
			markWorkerJoined = true
		} else {
			fa.shutdownMu.Lock()
			marks = cloneMarkDiagnostics(fa.shutdownDiagnostics.Marks)
			fa.shutdownMu.Unlock()
			marks.Pending = true
			marks.Final = false
		}
	}
	fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.Marks = mergeMarkDiagnostics(d.Marks, marks) })

	if hasControlledSource && marks.Complete {
		fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.Source.ReaderDrainPending = true })
		if err := controlled.WaitReaderDrained(background); err != nil {
			fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.Source.ReaderDrainError = err.Error() })
		} else {
			fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
				d.Source.ReaderDrainComplete = true
				d.Source.ReaderDrainError = ""
			})
		}
		fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.Source.ReaderDrainPending = false })
	}

	if hasControlledSource {
		err := controlled.CloseGroup()
		response := controlled.ResponseDiagnostics()
		fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
			d.Source.GroupClosePending = !response.Closed
			d.Source.GroupClosed = response.Closed
			if err != nil {
				d.Source.GroupCloseError = err.Error()
			} else {
				d.Source.GroupCloseError = ""
			}
		})
		for !response.Closed {
			time.Sleep(25 * time.Millisecond)
			response = controlled.ResponseDiagnostics()
			fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
				d.Source.GroupClosePending = !response.Closed
				d.Source.GroupClosed = response.Closed
			})
		}
	} else if fa.source != nil {
		err := fa.source.Close()
		fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
			d.Source.GroupClosePending = false
			d.Source.GroupClosed = err == nil
			if err != nil {
				d.Source.GroupCloseError = err.Error()
			}
		})
	}
	close(stopMarks)

	if fa.mgr != nil {
		fa.mgr.Cancel()
	}
	if hasControlledSource {
		for {
			err := controlled.WaitReaderExit(background)
			reader := controlled.ReaderDiagnostics()
			if err == nil && reader.Exited {
				fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.Source.ReaderJoinError = "" })
				break
			}
			fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
				if err != nil {
					d.Source.ReaderJoinError = err.Error()
				} else {
					d.Source.ReaderJoinError = "reader has not exited"
				}
			})
			time.Sleep(25 * time.Millisecond)
		}

		for !controlled.ScopeCleanupComplete() {
			err := controlled.CleanupScopes()
			fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
				if err != nil {
					d.Source.ScopeCleanupError = err.Error()
				}
			})
			if !controlled.ScopeCleanupComplete() {
				time.Sleep(25 * time.Millisecond)
			}
		}
		fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
			d.Source.ScopeCleanupComplete = true
			d.Source.ScopeCleanupPending = false
			d.Source.ScopeCleanupError = ""
		})
	}

	if err := <-reconciliationDone; err != nil {
		fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.ReconciliationError = err.Error() })
	} else {
		fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.ReconciliationError = "" })
	}
	fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.ReconciliationStopped = true })

	// Scope cleanup waits for an in-flight mark operation. Once it is complete,
	// the bounded mark worker must also be able to observe stop/report expiry and
	// exit without scheduling another mark operation.
	if hasControlledSource && !markWorkerJoined {
		finalMarks := <-markDone
		fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
			d.Marks = mergeMarkDiagnostics(d.Marks, finalMarks)
		})
	}
	fa.refreshShutdownDiagnostics()
}

func (fa *FileAccess) removeMarksUntilBounded(ctx context.Context, stop <-chan struct{}, source controlledShutdownSource, state *markRemovalWorkerState) MarkRemovalDiagnostics {
	result := MarkRemovalDiagnostics{Pending: true}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !state.beginCall(ctx, stop) {
			result.Final = true
			result.Pending = false
			return result
		}

		attempt := source.RemoveAllMarks()
		state.endCall()
		result.Attempts++
		result.Complete = attempt.Complete
		result.Failures = append([]MarkRemovalFailure(nil), attempt.Failures...)
		for _, failure := range attempt.Failures {
			seen := false
			for _, previous := range result.Errors {
				if previous == failure {
					seen = true
					break
				}
			}
			if !seen {
				result.Errors = append(result.Errors, failure)
			}
		}
		fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) { d.Marks = cloneMarkDiagnostics(result) })
		if attempt.Complete {
			result.Final = true
			result.Pending = false
			return result
		}
		select {
		case <-ctx.Done():
			result.Final = true
			result.Pending = false
			return result
		case <-stop:
			result.Final = true
			result.Pending = false
			return result
		case <-ticker.C:
		}
	}
}

func (fa *FileAccess) updateShutdownDiagnostics(update func(*ShutdownDiagnostics)) {
	fa.shutdownMu.Lock()
	update(&fa.shutdownDiagnostics)
	fa.shutdownMu.Unlock()
}

func (fa *FileAccess) recordReportingDeadline(err error) {
	if err == nil {
		return
	}
	detail := err.Error()
	fa.updateShutdownDiagnostics(func(d *ShutdownDiagnostics) {
		if !d.ReconciliationStopped && d.ReconciliationError == "" {
			d.ReconciliationError = detail
		}
		if d.Source.ReaderDrainPending && d.Source.ReaderDrainError == "" {
			d.Source.ReaderDrainError = detail
		}
		if d.Source.GroupClosed && !d.Source.ReaderExited && d.Source.ReaderJoinError == "" {
			d.Source.ReaderJoinError = detail
		}
		if d.Source.GroupClosePending && d.Source.GroupCloseError == "" {
			d.Source.GroupCloseError = detail
		}
		if d.Source.ScopeCleanupPending && d.Source.ScopeCleanupError == "" {
			d.Source.ScopeCleanupError = detail
		}
		if d.Decision.QueueDepth > 0 || d.Decision.ActiveDecisions > 0 {
			if d.PipelineDrainError == "" {
				d.PipelineDrainError = detail
			}
		}
		if d.Decision.Outstanding > 0 && d.OutstandingError == "" {
			d.OutstandingError = detail
		}
		if (d.Decision.ActiveWorkers > 0 || d.Decision.ExitedWorkers < d.Decision.ExpectedWorkers) && d.WorkerWaitError == "" {
			d.WorkerWaitError = detail
		}
		if (d.Prompt.Events > 0 || d.Prompt.ActivePrompts > 0) && d.PromptDrainError == "" {
			d.PromptDrainError = detail
		}
	})
}

func (fa *FileAccess) refreshShutdownDiagnostics() ShutdownDiagnostics {
	fa.shutdownMu.Lock()
	d := cloneShutdownDiagnostics(fa.shutdownDiagnostics)
	d.State = fa.lifecycle.State()
	if fa.pipeline != nil {
		d.Decision = fa.pipeline.Diagnostics()
	}
	var coordinator *PromptCoordinator
	if fa.profileHandler != nil {
		coordinator = fa.profileHandler.coordinator()
	}
	if coordinator != nil {
		d.Prompt = coordinator.Diagnostics()
		d.PermanentRules = coordinator.RulePersistence().Diagnostics()
	}
	if controlled, ok := fa.source.(controlledShutdownSource); ok {
		reader := controlled.ReaderDiagnostics()
		d.Source.ReaderRunning = reader.Running
		d.Source.ReaderExited = reader.Exited
		d.Source.OutstandingDescriptors = reader.OutstandingDescriptors
		d.Source.AccountedDescriptors = append([]int32(nil), reader.AccountedDescriptors...)
		d.Source.FailedResponseDescriptors = append([]int32(nil), reader.FailedResponseDescriptors...)
		d.Source.Response = controlled.ResponseDiagnostics()
		d.Source.GroupClosed = d.Source.Response.Closed
		d.Source.ScopeCleanupComplete = controlled.ScopeCleanupComplete()
		d.Source.ScopeCleanupPending = !d.Source.ScopeCleanupComplete
	}
	d.Unresolved = unresolvedShutdownOwnership(d)
	fa.shutdownDiagnostics = cloneShutdownDiagnostics(d)
	fa.shutdownMu.Unlock()
	return d
}

func unresolvedShutdownOwnership(d ShutdownDiagnostics) []UnresolvedOwnership {
	unresolved := make([]UnresolvedOwnership, 0)
	if d.Marks.Pending {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "mark_removal_worker", Count: 1})
	}
	if !d.ReconciliationStopped {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "reconciliation", Count: 1, Detail: d.ReconciliationError})
	}
	if len(d.Source.AccountedDescriptors) > 0 {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "fanotify_accounted", Count: len(d.Source.AccountedDescriptors), Descriptors: append([]int32(nil), d.Source.AccountedDescriptors...)})
	}
	if len(d.Source.FailedResponseDescriptors) > 0 {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "failed_response_store", Count: len(d.Source.FailedResponseDescriptors), Descriptors: append([]int32(nil), d.Source.FailedResponseDescriptors...)})
	}
	if d.Source.Response.CurrentFD >= 0 {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "response_writer", Count: 1, Descriptors: []int32{d.Source.Response.CurrentFD}})
	}
	if d.Source.GroupClosePending || !d.Source.GroupClosed {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "group_closure", Count: 1, Detail: d.Source.GroupCloseError})
	}
	if d.Source.ScopeCleanupPending {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "scope_cleanup", Count: 1, Detail: d.Source.ScopeCleanupError})
	}
	if d.Source.GroupClosed && !d.Source.ReaderExited {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "reader_join", Count: 1, Detail: d.Source.ReaderJoinError})
	}
	if d.Decision.QueueDepth > 0 {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "decision_queue", Count: d.Decision.QueueDepth})
	}
	if d.Decision.ActiveDecisions > 0 {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "active_workers", Count: int(d.Decision.ActiveDecisions)})
	}
	if d.Decision.ActiveWorkers > 0 || d.Decision.ExitedWorkers < d.Decision.ExpectedWorkers {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "decision_worker_goroutines", Count: int(d.Decision.ExpectedWorkers - d.Decision.ExitedWorkers), Detail: d.WorkerWaitError})
	}
	if d.Decision.Outstanding > 0 {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "pipeline_outstanding", Count: int(d.Decision.Outstanding), Detail: d.OutstandingError})
	}
	if d.Prompt.Events > 0 {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "prompt_coordinator", Count: d.Prompt.Events})
	}
	if d.Prompt.ActivePrompts > 0 {
		unresolved = append(unresolved, UnresolvedOwnership{Location: "prompt_workers", Count: int(d.Prompt.ActivePrompts)})
	}
	return unresolved
}

func shutdownIncomplete(d ShutdownDiagnostics) bool {
	return d.DeadlineExpired || !d.ReportingCompleted || !d.Marks.Complete || d.ReconciliationError != "" || d.FlushError != "" || d.PipelineDrainError != "" || d.PromptDrainError != "" || d.OutstandingError != "" || d.WorkerWaitError != "" || d.Source.ReaderDrainError != "" || d.Source.ReaderJoinError != "" || d.Source.GroupCloseError != "" || d.Source.ScopeCleanupError != "" || len(d.Unresolved) > 0
}

func cloneMarkDiagnostics(source MarkRemovalDiagnostics) MarkRemovalDiagnostics {
	clone := source
	clone.Failures = append([]MarkRemovalFailure(nil), source.Failures...)
	clone.Errors = append([]MarkRemovalFailure(nil), source.Errors...)
	return clone
}

func mergeMarkDiagnostics(current, update MarkRemovalDiagnostics) MarkRemovalDiagnostics {
	merged := cloneMarkDiagnostics(update)
	if current.Attempts > update.Attempts {
		merged.Attempts = current.Attempts
		merged.Complete = current.Complete
		merged.Failures = append([]MarkRemovalFailure(nil), current.Failures...)
	}
	for _, failure := range current.Errors {
		seen := false
		for _, existing := range merged.Errors {
			if existing == failure {
				seen = true
				break
			}
		}
		if !seen {
			merged.Errors = append(merged.Errors, failure)
		}
	}
	return merged
}

func cloneShutdownDiagnostics(source ShutdownDiagnostics) ShutdownDiagnostics {
	clone := source
	clone.Marks = cloneMarkDiagnostics(source.Marks)
	clone.Source.AccountedDescriptors = append([]int32(nil), source.Source.AccountedDescriptors...)
	clone.Source.FailedResponseDescriptors = append([]int32(nil), source.Source.FailedResponseDescriptors...)
	clone.Unresolved = make([]UnresolvedOwnership, len(source.Unresolved))
	for i, owner := range source.Unresolved {
		clone.Unresolved[i] = owner
		clone.Unresolved[i].Descriptors = append([]int32(nil), owner.Descriptors...)
	}
	if source.PermanentRules != nil {
		clone.PermanentRules = make(map[string]RulePersistenceDiagnostics, len(source.PermanentRules))
		keys := make([]string, 0, len(source.PermanentRules))
		for key := range source.PermanentRules {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			diagnostics := source.PermanentRules[key]
			diagnostics.DirtyGenerations = append([]uint64(nil), diagnostics.DirtyGenerations...)
			clone.PermanentRules[key] = diagnostics
		}
	}
	return clone
}
