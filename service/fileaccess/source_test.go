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

	mu       sync.Mutex
	decided  []decision
	closeErr error
	closed   chan struct{}
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

func (s *fakeSource) Run(ctx context.Context, h Handler) error {
	for _, e := range s.events {
		select {
		case <-ctx.Done():
			return nil
		case <-s.closed:
			return nil
		default:
		}
		v := h.Decide(ctx, e)
		s.mu.Lock()
		s.decided = append(s.decided, decision{Event: e, Verdict: v})
		s.mu.Unlock()
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

func (s *fakeSource) Decisions() []decision {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]decision, len(s.decided))
	copy(out, s.decided)
	return out
}
