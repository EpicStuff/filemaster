package fileaccess

import (
	"context"
	"sync"
)

// fakeSource is a Source that delivers a fixed list of events to the
// handler and records the verdicts. Useful for driving decision logic in
// environments where fanotify can't run.
type fakeSource struct {
	events []FileEvent

	mu                sync.Mutex
	decided           []decision
	closeErr          error
	closed            chan struct{}
	pathsAsked        [][]string
	pathsErr          error
	response          func(FileEvent, Verdict) responseResult
	outstanding       int64
	peakOutstanding   int64
	failedResponses   []int32
	marks             MarkRemovalResult
	reconciliationErr error
	readerDrainErr    error
	readerExitErr     error
	readerStarted     bool
	readerRunning     bool
	readerExited      bool
	readerDone        chan struct{}
	groupCloseErr     error
	scopeCleanupErr   error
	scopesCleaned     bool
	groupClosed       bool
	lifecycle         *PipelineLifecycle
}

type decision struct {
	Event   FileEvent
	Verdict Verdict
}

func newFakeSource(events []FileEvent) *fakeSource {
	return &fakeSource{
		events:     events,
		closed:     make(chan struct{}),
		readerDone: make(chan struct{}),
	}
}

func (s *fakeSource) Run(ctx context.Context, handler PendingHandler) error {
	s.mu.Lock()
	s.readerStarted = true
	s.readerRunning = true
	s.readerExited = false
	readerDone := s.readerDone
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.readerRunning = false
		s.readerExited = true
		close(readerDone)
		s.mu.Unlock()
	}()

	for _, sourceEvent := range s.events {
		select {
		case <-ctx.Done():
			return nil
		case <-s.closed:
			return nil
		default:
		}
		event := sourceEvent
		s.mu.Lock()
		s.outstanding++
		if s.outstanding > s.peakOutstanding {
			s.peakOutstanding = s.outstanding
		}
		s.mu.Unlock()
		pending := newPendingEvent(&event, func(verdict Verdict) responseResult {
			s.mu.Lock()
			s.decided = append(s.decided, decision{Event: event, Verdict: verdict})
			response := s.response
			s.mu.Unlock()
			result := responseResult{accepted: true}
			if response != nil {
				result = response(event, verdict)
			}
			s.mu.Lock()
			if result.accepted {
				s.outstanding--
			} else {
				s.failedResponses = append(s.failedResponses, int32(len(s.failedResponses)+1))
			}
			s.mu.Unlock()
			return result
		})
		if _, err := deliverPendingEvent(ctx, handler, pending); err != nil {
			return err
		}
	}
	// Park until shutdown so the worker stays alive like a real source.
	select {
	case <-ctx.Done():
	case <-s.closed:
	}
	return nil
}

func (s *fakeSource) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return s.closeErr
}

// SetWatchPaths records the latest paths the caller asked for. The
// fake source doesn't have marks; tests can read pathsAsked to verify
// the module's live-reload hook delegated through.
func (s *fakeSource) SetWatchPaths(paths []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pathsAsked = append(s.pathsAsked, append([]string(nil), paths...))
	return s.pathsErr
}

// PathsAsked returns each SetWatchPaths call's path list, in order.
func (s *fakeSource) PathsAsked() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]string, len(s.pathsAsked))
	for i, p := range s.pathsAsked {
		out[i] = append([]string(nil), p...)
	}
	return out
}

func (s *fakeSource) Decisions() []decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]decision, len(s.decided))
	copy(out, s.decided)
	return out
}

func (s *fakeSource) SetLifecycle(lifecycle *PipelineLifecycle) { s.lifecycle = lifecycle }

func (s *fakeSource) RemoveAllMarks() MarkRemovalResult { return s.marks }

func (s *fakeSource) WaitReconciliation(context.Context) error { return s.reconciliationErr }

func (s *fakeSource) WaitReaderDrained(context.Context) error { return s.readerDrainErr }

func (s *fakeSource) CloseGroup() error {
	s.mu.Lock()
	s.groupClosed = true
	err := s.groupCloseErr
	s.mu.Unlock()
	if err == nil {
		// Closing the fake group unblocks its parked reader, matching the real
		// fanotify group lifetime without pretending to model kernel behavior.
		return s.Close()
	}
	return err
}

func (s *fakeSource) CleanupScopes() error {
	s.mu.Lock()
	if s.scopeCleanupErr == nil {
		s.scopesCleaned = true
	}
	err := s.scopeCleanupErr
	s.mu.Unlock()
	return err
}

func (s *fakeSource) ScopeCleanupComplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scopesCleaned
}

func (s *fakeSource) WaitReaderExit(ctx context.Context) error {
	s.mu.Lock()
	started := s.readerStarted
	exited := s.readerExited
	done := s.readerDone
	err := s.readerExitErr
	s.mu.Unlock()
	if !started || exited {
		return err
	}
	select {
	case <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *fakeSource) ReaderDiagnostics() ReaderDiagnostics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ReaderDiagnostics{
		OutstandingDescriptors:     s.outstanding,
		PeakOutstandingDescriptors: s.peakOutstanding,
		FailedResponseDescriptors:  append([]int32(nil), s.failedResponses...),
		Running:                    s.readerRunning,
		Exited:                     s.readerExited,
	}
}

func (s *fakeSource) ResponseDiagnostics() ResponseWriterDiagnostics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ResponseWriterDiagnostics{Closed: s.groupClosed, CurrentFD: -1}
}
