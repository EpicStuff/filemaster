package fileaccess

import (
	"context"
	"errors"
	"fmt"
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
	Failures []MarkRemovalFailure
	Errors   []MarkRemovalFailure
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
	ReaderDrainError          string
	ReaderJoinError           string
	OutstandingDescriptors    int64
	AccountedDescriptors      []int32
	FailedResponseDescriptors []int32
	Response                  ResponseWriterDiagnostics
	GroupClosed               bool
	GroupCloseError           string
}

type UnresolvedOwnership struct {
	Location    string
	Count       int
	Descriptors []int32
	Detail      string
}

type ShutdownDiagnostics struct {
	State                 LifecycleState
	DeadlineExpired       bool
	ConfigurationStopped  bool
	ReconciliationStopped bool
	Marks                 MarkRemovalDiagnostics
	Source                SourceShutdownDiagnostics
	Decision              DecisionPipelineDiagnostics
	Prompt                PromptCoordinatorDiagnostics
	PermanentRules        map[string]RulePersistenceDiagnostics
	FlushError            string
	PipelineDrainError    string
	PromptDrainError      string
	OutstandingError      string
	Unresolved            []UnresolvedOwnership
}

type ShutdownError struct {
	Diagnostics ShutdownDiagnostics
}

func (shutdownErr *ShutdownError) Error() string {
	if shutdownErr == nil {
		return ""
	}
	return fmt.Sprintf(
		"file access shutdown incomplete: state=%s deadline=%t unresolved=%d marks_complete=%t flush_error=%q",
		shutdownErr.Diagnostics.State,
		shutdownErr.Diagnostics.DeadlineExpired,
		len(shutdownErr.Diagnostics.Unresolved),
		shutdownErr.Diagnostics.Marks.Complete,
		shutdownErr.Diagnostics.FlushError,
	)
}

type controlledShutdownSource interface {
	RemoveAllMarks() MarkRemovalResult
	WaitReconciliation(context.Context) error
	WaitReaderDrained(context.Context) error
	PrepareClose(context.Context) error
	WaitReaderExit(context.Context) error
	ReaderDiagnostics() ReaderDiagnostics
	ResponseDiagnostics() ResponseWriterDiagnostics
}

func (fa *FileAccess) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	fa.shutdownOnce.Do(func() {
		closingCtx, _ := fa.lifecycle.BeginClosing(ctx)
		result, diagnostics, closed := fa.runControlledShutdown(closingCtx)
		fa.shutdownMu.Lock()
		fa.shutdownResult = result
		fa.shutdownDiagnostics = diagnostics
		fa.shutdownMu.Unlock()
		if closed {
			fa.lifecycle.PublishClosed(result)
		}
		close(fa.shutdownDone)
	})
	<-fa.shutdownDone
	fa.shutdownMu.Lock()
	defer fa.shutdownMu.Unlock()
	return fa.shutdownResult
}

func (fa *FileAccess) ShutdownDiagnostics() ShutdownDiagnostics {
	fa.shutdownMu.Lock()
	defer fa.shutdownMu.Unlock()
	return fa.shutdownDiagnostics
}

func (fa *FileAccess) runControlledShutdown(ctx context.Context) (error, ShutdownDiagnostics, bool) {
	diagnostics := ShutdownDiagnostics{
		State:                LifecycleClosing,
		ConfigurationStopped: true,
		Marks:                MarkRemovalDiagnostics{Complete: true},
	}

	controlled, hasControlledSource := fa.source.(controlledShutdownSource)
	if hasControlledSource {
		if err := controlled.WaitReconciliation(ctx); err != nil {
			diagnostics.Source.ReaderDrainError = err.Error()
		} else {
			diagnostics.ReconciliationStopped = true
		}
	} else {
		diagnostics.ReconciliationStopped = true
	}

	markDone := make(chan MarkRemovalDiagnostics, 1)
	markProgress := make(chan MarkRemovalDiagnostics, 1)
	if hasControlledSource {
		go func() {
			result := MarkRemovalDiagnostics{}
			ticker := time.NewTicker(25 * time.Millisecond)
			defer ticker.Stop()
			for {
				attempt := controlled.RemoveAllMarks()
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
				select {
				case <-markProgress:
				default:
				}
				markProgress <- result
				if attempt.Complete {
					markDone <- result
					return
				}
				select {
				case <-ctx.Done():
					markDone <- result
					return
				case <-ticker.C:
				}
			}
		}()
	} else {
		markProgress <- diagnostics.Marks
		markDone <- diagnostics.Marks
	}

	pipelineDone := make(chan error, 1)
	if fa.pipeline != nil {
		go func() { pipelineDone <- fa.pipeline.Drain(ctx) }()
	} else {
		pipelineDone <- nil
	}

	var coordinator *PromptCoordinator
	if fa.profileHandler != nil {
		coordinator = fa.profileHandler.coordinator()
	}
	if coordinator != nil {
		if err := coordinator.Drain(ctx); err != nil {
			diagnostics.PromptDrainError = err.Error()
		}
		diagnostics.Prompt = coordinator.Diagnostics()
	}

	flushDone := make(chan error, 1)
	if coordinator != nil {
		go func() { flushDone <- coordinator.FlushPermanentRules(ctx) }()
	} else {
		flushDone <- nil
	}

	select {
	case diagnostics.Marks = <-markDone:
	case <-ctx.Done():
		select {
		case diagnostics.Marks = <-markProgress:
		default:
			diagnostics.Marks.Complete = false
		}
	}
	select {
	case err := <-pipelineDone:
		if err != nil {
			diagnostics.PipelineDrainError = err.Error()
		}
	case <-ctx.Done():
		diagnostics.PipelineDrainError = ctx.Err().Error()
	}
	select {
	case err := <-flushDone:
		if err != nil {
			diagnostics.FlushError = err.Error()
		}
	case <-ctx.Done():
		diagnostics.FlushError = ctx.Err().Error()
	}

	if fa.pipeline != nil {
		if err := fa.pipeline.WaitOutstanding(ctx); err != nil {
			diagnostics.OutstandingError = err.Error()
		}
		diagnostics.Decision = fa.pipeline.Diagnostics()
	}
	if coordinator != nil {
		diagnostics.Prompt = coordinator.Diagnostics()
		diagnostics.PermanentRules = coordinator.RulePersistence().Diagnostics()
	}

	if hasControlledSource && diagnostics.Marks.Complete {
		if err := controlled.WaitReaderDrained(ctx); err != nil {
			diagnostics.Source.ReaderDrainError = err.Error()
		}
	}

	if hasControlledSource {
		if err := controlled.PrepareClose(ctx); err != nil {
			diagnostics.Source.GroupCloseError = err.Error()
		}
	}

	canClose := !hasControlledSource || controlled.ResponseDiagnostics().CurrentFD < 0
	if canClose && fa.source != nil {
		if err := fa.source.Close(); err != nil {
			if diagnostics.Source.GroupCloseError == "" {
				diagnostics.Source.GroupCloseError = err.Error()
			} else {
				diagnostics.Source.GroupCloseError = errors.Join(errors.New(diagnostics.Source.GroupCloseError), err).Error()
			}
		} else {
			diagnostics.Source.GroupClosed = true
		}
	}

	if diagnostics.Source.GroupClosed || !hasControlledSource {
		fa.mgr.Cancel()
		joinCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		if hasControlledSource {
			if err := controlled.WaitReaderExit(joinCtx); err != nil {
				diagnostics.Source.ReaderJoinError = err.Error()
			}
		}
		cancel()
	}

	if hasControlledSource {
		reader := controlled.ReaderDiagnostics()
		diagnostics.Source.ReaderRunning = reader.Running
		diagnostics.Source.ReaderExited = reader.Exited
		diagnostics.Source.OutstandingDescriptors = reader.OutstandingDescriptors
		diagnostics.Source.AccountedDescriptors = append([]int32(nil), reader.AccountedDescriptors...)
		diagnostics.Source.FailedResponseDescriptors = append([]int32(nil), reader.FailedResponseDescriptors...)
		diagnostics.Source.Response = controlled.ResponseDiagnostics()
		diagnostics.Source.GroupClosed = diagnostics.Source.Response.Closed
	}

	diagnostics.DeadlineExpired = ctx.Err() != nil
	if len(diagnostics.Source.AccountedDescriptors) > 0 {
		diagnostics.Unresolved = append(diagnostics.Unresolved, UnresolvedOwnership{
			Location:    "fanotify_accounted",
			Count:       len(diagnostics.Source.AccountedDescriptors),
			Descriptors: append([]int32(nil), diagnostics.Source.AccountedDescriptors...),
		})
	}
	if len(diagnostics.Source.FailedResponseDescriptors) > 0 {
		diagnostics.Unresolved = append(diagnostics.Unresolved, UnresolvedOwnership{
			Location:    "failed_response_store",
			Count:       len(diagnostics.Source.FailedResponseDescriptors),
			Descriptors: append([]int32(nil), diagnostics.Source.FailedResponseDescriptors...),
		})
	}
	if diagnostics.Source.Response.CurrentFD >= 0 {
		diagnostics.Unresolved = append(diagnostics.Unresolved, UnresolvedOwnership{
			Location:    "response_writer",
			Count:       1,
			Descriptors: []int32{diagnostics.Source.Response.CurrentFD},
		})
	}
	if diagnostics.Decision.QueueDepth > 0 {
		diagnostics.Unresolved = append(diagnostics.Unresolved, UnresolvedOwnership{Location: "decision_queue", Count: diagnostics.Decision.QueueDepth})
	}
	if diagnostics.Decision.ActiveDecisions > 0 {
		diagnostics.Unresolved = append(diagnostics.Unresolved, UnresolvedOwnership{Location: "active_workers", Count: int(diagnostics.Decision.ActiveDecisions)})
	}
	if diagnostics.Prompt.Events > 0 {
		diagnostics.Unresolved = append(diagnostics.Unresolved, UnresolvedOwnership{Location: "prompt_coordinator", Count: diagnostics.Prompt.Events})
	}
	if diagnostics.Prompt.ActivePrompts > 0 {
		diagnostics.Unresolved = append(diagnostics.Unresolved, UnresolvedOwnership{Location: "prompt_workers", Count: int(diagnostics.Prompt.ActivePrompts)})
	}

	closed := !hasControlledSource || diagnostics.Source.GroupClosed
	if closed {
		diagnostics.State = LifecycleClosed
	}
	incomplete := diagnostics.DeadlineExpired || !diagnostics.Marks.Complete || diagnostics.FlushError != "" || diagnostics.PipelineDrainError != "" || diagnostics.PromptDrainError != "" || diagnostics.OutstandingError != "" || diagnostics.Source.GroupCloseError != "" || len(diagnostics.Unresolved) > 0
	if incomplete {
		return &ShutdownError{Diagnostics: diagnostics}, diagnostics, closed
	}
	return nil, diagnostics, closed
}
