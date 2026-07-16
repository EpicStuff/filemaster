package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrPendingEventNotOwner            = errors.New("pending event is owned elsewhere")
	ErrPendingEventAlreadyResolved     = errors.New("pending event already has a logical verdict")
	ErrPendingEventInvalidVerdict      = errors.New("invalid pending event verdict")
	ErrPendingEventResponseNotAccepted = errors.New("pending event response was not accepted")
	ErrPendingEventAbandoned           = errors.New("pending event handler returned without resolving or transferring ownership")
)

// PendingEvent is one ownership handle for a permission event. Transfer
// invalidates the current handle and returns the only handle allowed to make
// the next ownership decision.
type PendingEvent interface {
	Event() *FileEvent
	Respond(Verdict) error
	Transfer() (PendingEvent, error)
}

// PendingHandler owns an event for the duration of Handle. It must respond or
// explicitly transfer ownership before returning.
type PendingHandler interface {
	Handle(context.Context, PendingEvent) error
}

type PendingHandlerFunc func(context.Context, PendingEvent) error

func (f PendingHandlerFunc) Handle(ctx context.Context, event PendingEvent) error {
	return f(ctx, event)
}

type responseResult struct {
	accepted bool
	err      error
}

type pendingEventState struct {
	mu sync.Mutex

	event                *FileEvent
	respond              func(Verdict) responseResult
	onUnacceptedResponse func(PendingEvent)
	currentOwner         uint64
	nextOwner            uint64
	verdict              Verdict
	verdictSet           bool
	accepted             bool
}

type pendingEventOwner struct {
	state *pendingEventState
	owner uint64
}

func newPendingEvent(event *FileEvent, respond func(Verdict) responseResult) *pendingEventOwner {
	return newPendingEventWithFailureSink(event, respond, nil)
}

func newPendingEventWithFailureSink(event *FileEvent, respond func(Verdict) responseResult, onUnacceptedResponse func(PendingEvent)) *pendingEventOwner {
	state := &pendingEventState{
		event:                event,
		respond:              respond,
		onUnacceptedResponse: onUnacceptedResponse,
		currentOwner:         1,
		nextOwner:            1,
	}
	return &pendingEventOwner{state: state, owner: 1}
}

func resolvePendingCurrent(pending PendingEvent, verdict Verdict) error {
	if owner, ok := pending.(*pendingEventOwner); ok {
		_, err := owner.state.resolveCurrent(verdict)
		return err
	}
	return pending.Respond(verdict)
}

func (event *pendingEventOwner) Event() *FileEvent {
	event.state.mu.Lock()
	defer event.state.mu.Unlock()
	if event.state.currentOwner != event.owner || event.state.accepted {
		return nil
	}
	return event.state.event
}

func (event *pendingEventOwner) Transfer() (PendingEvent, error) {
	event.state.mu.Lock()
	defer event.state.mu.Unlock()
	if event.state.verdictSet {
		return nil, ErrPendingEventAlreadyResolved
	}
	if event.state.currentOwner != event.owner || event.state.accepted {
		return nil, ErrPendingEventNotOwner
	}
	event.state.nextOwner++
	event.state.currentOwner = event.state.nextOwner
	return &pendingEventOwner{state: event.state, owner: event.state.currentOwner}, nil
}

func (event *pendingEventOwner) Respond(verdict Verdict) error {
	if verdict != VerdictAllow && verdict != VerdictDeny {
		return ErrPendingEventInvalidVerdict
	}

	event.state.mu.Lock()
	if event.state.verdictSet {
		event.state.mu.Unlock()
		return ErrPendingEventAlreadyResolved
	}
	if event.state.currentOwner != event.owner || event.state.accepted {
		event.state.mu.Unlock()
		return ErrPendingEventNotOwner
	}
	event.state.verdict = verdict
	event.state.verdictSet = true
	event.state.mu.Unlock()

	return event.state.finishResponse(event, verdict)
}

func (state *pendingEventState) finishResponse(owner PendingEvent, verdict Verdict) error {
	result := state.respond(verdict)
	if !result.accepted && result.err == nil {
		result.err = ErrPendingEventResponseNotAccepted
	}
	if result.accepted {
		state.mu.Lock()
		state.accepted = true
		state.currentOwner = 0
		state.mu.Unlock()
		return result.err
	}

	if state.onUnacceptedResponse != nil {
		state.onUnacceptedResponse(owner)
	}
	return result.err
}

func (state *pendingEventState) resolveCurrent(verdict Verdict) (PendingEvent, error) {
	if verdict != VerdictAllow && verdict != VerdictDeny {
		return nil, ErrPendingEventInvalidVerdict
	}

	state.mu.Lock()
	if state.currentOwner == 0 || state.accepted {
		state.mu.Unlock()
		return nil, nil
	}
	owner := &pendingEventOwner{state: state, owner: state.currentOwner}
	if state.verdictSet {
		state.mu.Unlock()
		return owner, nil
	}
	state.verdict = verdict
	state.verdictSet = true
	state.mu.Unlock()

	return owner, state.finishResponse(owner, verdict)
}

func (event *pendingEventOwner) logicalVerdict() (Verdict, bool) {
	event.state.mu.Lock()
	defer event.state.mu.Unlock()
	return event.state.verdict, event.state.verdictSet
}

func (event *pendingEventOwner) responseAccepted() bool {
	event.state.mu.Lock()
	defer event.state.mu.Unlock()
	return event.state.accepted
}

func (event *pendingEventOwner) needsResolution() bool {
	event.state.mu.Lock()
	defer event.state.mu.Unlock()
	return event.state.currentOwner == event.owner && !event.state.verdictSet
}

func deliverPendingEvent(ctx context.Context, handler PendingHandler, event PendingEvent) (owner PendingEvent, err error) {
	owner, err = event.Transfer()
	if err != nil {
		return nil, fmt.Errorf("transfer pending event ownership: %w", err)
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("pending event handler panic: %v", recovered)
		}
		concrete, ok := owner.(*pendingEventOwner)
		if !ok {
			return
		}
		if err != nil {
			current, responseErr := concrete.state.resolveCurrent(VerdictDeny)
			if current != nil {
				owner = current
			}
			if responseErr != nil {
				err = errors.Join(err, responseErr)
			}
			return
		}
		if !concrete.needsResolution() {
			return
		}
		current, responseErr := concrete.state.resolveCurrent(VerdictDeny)
		if current != nil {
			owner = current
		}
		err = ErrPendingEventAbandoned
		if responseErr != nil {
			err = errors.Join(err, responseErr)
		}
	}()

	if ctx.Err() != nil {
		return owner, owner.Respond(VerdictDeny)
	}
	return owner, handler.Handle(ctx, owner)
}

type decisionPendingHandler struct {
	handler Handler
}

func (handler decisionPendingHandler) Handle(ctx context.Context, pending PendingEvent) error {
	if ctx.Err() != nil {
		return nil
	}
	event := pending.Event()
	if event == nil {
		return ErrPendingEventNotOwner
	}
	verdict := handler.handler.Decide(ctx, event)
	if ctx.Err() != nil {
		verdict = VerdictDeny
	}
	return pending.Respond(verdict)
}
