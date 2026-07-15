package fileaccess

import (
	"context"
	"sync"
)

// fakeSource is a Source that delivers a fixed list of events to the
// handler and records the verdicts. Useful for driving phase-2/phase-3
// logic in environments where fanotify can't run.
type fakeSource struct {
	events []FileEvent

	mu         sync.Mutex
	decided    []decision
	closeErr   error
	closed     chan struct{}
	pathsAsked [][]string
	pathsErr   error
}

type decision struct {
	Event   FileEvent
	Verdict Verdict
}

func newFakeSource(events []FileEvent) *fakeSource {
	return &fakeSource{
		events: events,
		closed: make(chan struct{}),
	}
}

func (s *fakeSource) Run(ctx context.Context, handler PendingHandler) error {
	for _, sourceEvent := range s.events {
		select {
		case <-ctx.Done():
			return nil
		case <-s.closed:
			return nil
		default:
		}
		event := sourceEvent
		pending := newPendingEvent(&event, func(verdict Verdict) responseResult {
			s.mu.Lock()
			s.decided = append(s.decided, decision{Event: event, Verdict: verdict})
			s.mu.Unlock()
			return responseResult{accepted: true}
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
