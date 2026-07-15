package fileaccess

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPendingEventHasOneLogicalVerdict(t *testing.T) {
	responseErr := errors.New("response unavailable")
	var verdicts []Verdict
	pending := newPendingEvent(&FileEvent{Path: "/tmp/owned"}, func(verdict Verdict) responseResult {
		verdicts = append(verdicts, verdict)
		return responseResult{err: responseErr}
	})

	if err := pending.Respond(VerdictAllow); !errors.Is(err, responseErr) {
		t.Fatalf("first Respond error = %v, want %v", err, responseErr)
	}
	if err := pending.Respond(VerdictDeny); !errors.Is(err, ErrPendingEventAlreadyResolved) {
		t.Fatalf("second Respond error = %v, want ErrPendingEventAlreadyResolved", err)
	}
	if len(verdicts) != 1 || verdicts[0] != VerdictAllow {
		t.Fatalf("logical verdicts = %v, want [allow]", verdicts)
	}
}

func TestPendingEventPreventsDuplicateConcurrentResponses(t *testing.T) {
	var responses atomic.Int32
	pending := newPendingEvent(&FileEvent{Path: "/tmp/duplicate"}, func(Verdict) responseResult {
		responses.Add(1)
		return responseResult{accepted: true}
	})

	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, verdict := range []Verdict{VerdictAllow, VerdictDeny} {
		wg.Add(1)
		go func(verdict Verdict) {
			defer wg.Done()
			<-start
			errs <- pending.Respond(verdict)
		}(verdict)
	}
	close(start)
	wg.Wait()
	close(errs)

	var accepted, duplicate int
	for err := range errs {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrPendingEventAlreadyResolved):
			duplicate++
		default:
			t.Fatalf("unexpected Respond error: %v", err)
		}
	}
	if accepted != 1 || duplicate != 1 || responses.Load() != 1 {
		t.Fatalf("accepted=%d duplicate=%d writes=%d, want 1/1/1", accepted, duplicate, responses.Load())
	}
}

func TestPendingEventOwnershipTransfer(t *testing.T) {
	fileEvent := &FileEvent{Path: "/tmp/transfer"}
	var verdict Verdict
	readerOwner := newPendingEvent(fileEvent, func(got Verdict) responseResult {
		verdict = got
		return responseResult{accepted: true}
	})
	workerOwner, err := readerOwner.Transfer()
	if err != nil {
		t.Fatalf("Transfer: %v", err)
	}
	if got := readerOwner.Event(); got != nil {
		t.Fatalf("old owner Event = %+v, want nil", got)
	}
	if err := readerOwner.Respond(VerdictAllow); !errors.Is(err, ErrPendingEventNotOwner) {
		t.Fatalf("old owner Respond error = %v, want ErrPendingEventNotOwner", err)
	}
	if got := workerOwner.Event(); got != fileEvent {
		t.Fatalf("new owner Event = %p, want %p", got, fileEvent)
	}
	if err := workerOwner.Respond(VerdictDeny); err != nil {
		t.Fatalf("new owner Respond: %v", err)
	}
	if verdict != VerdictDeny {
		t.Fatalf("verdict = %s, want deny", verdict)
	}
}

func TestPendingEventCleanTransferRemainsActive(t *testing.T) {
	var coordinatorOwner PendingEvent
	var verdicts []Verdict
	pending := newPendingEvent(&FileEvent{Path: "/tmp/prompt"}, func(verdict Verdict) responseResult {
		verdicts = append(verdicts, verdict)
		return responseResult{accepted: true}
	})

	returnedOwner, err := deliverPendingEvent(context.Background(), PendingHandlerFunc(func(_ context.Context, workerOwner PendingEvent) error {
		var err error
		coordinatorOwner, err = workerOwner.Transfer()
		return err
	}), pending)
	if err != nil {
		t.Fatalf("deliverPendingEvent: %v", err)
	}
	if returnedOwner.Event() != nil {
		t.Fatal("returned worker owner remained active after transfer")
	}
	if coordinatorOwner.Event() == nil {
		t.Fatal("coordinator owner is inactive after clean transfer")
	}
	if verdict, resolved := pending.logicalVerdict(); resolved {
		t.Fatalf("logical verdict after clean transfer = %s, want unresolved", verdict)
	}
	if len(verdicts) != 0 {
		t.Fatalf("verdicts after transfer = %v, want none", verdicts)
	}
	if err := coordinatorOwner.Respond(VerdictAllow); err != nil {
		t.Fatalf("coordinator owner Respond: %v", err)
	}
	if len(verdicts) != 1 || verdicts[0] != VerdictAllow {
		t.Fatalf("verdicts = %v, want [allow]", verdicts)
	}
}

func TestPendingEventTransferThenPanicDeniesCurrentOwner(t *testing.T) {
	var verdicts []Verdict
	pending := newPendingEvent(&FileEvent{Path: "/tmp/transfer-panic"}, func(verdict Verdict) responseResult {
		verdicts = append(verdicts, verdict)
		return responseResult{accepted: true}
	})

	_, err := deliverPendingEvent(context.Background(), PendingHandlerFunc(func(_ context.Context, workerOwner PendingEvent) error {
		if _, err := workerOwner.Transfer(); err != nil {
			return err
		}
		panic("panic after transfer")
	}), pending)
	if err == nil {
		t.Fatal("deliverPendingEvent error = nil, want panic error")
	}
	if len(verdicts) != 1 || verdicts[0] != VerdictDeny {
		t.Fatalf("verdicts = %v, want [deny]", verdicts)
	}
}

func TestPendingEventTransferThenErrorDeniesCurrentOwner(t *testing.T) {
	handlerErr := errors.New("handler failed after transfer")
	var verdicts []Verdict
	pending := newPendingEvent(&FileEvent{Path: "/tmp/transfer-error"}, func(verdict Verdict) responseResult {
		verdicts = append(verdicts, verdict)
		return responseResult{accepted: true}
	})

	_, err := deliverPendingEvent(context.Background(), PendingHandlerFunc(func(_ context.Context, workerOwner PendingEvent) error {
		if _, err := workerOwner.Transfer(); err != nil {
			return err
		}
		return handlerErr
	}), pending)
	if !errors.Is(err, handlerErr) {
		t.Fatalf("deliverPendingEvent error = %v, want %v", err, handlerErr)
	}
	if len(verdicts) != 1 || verdicts[0] != VerdictDeny {
		t.Fatalf("verdicts = %v, want [deny]", verdicts)
	}
}

func TestPendingEventStoredCoordinatorOwnerObservesTransferPanicDeny(t *testing.T) {
	var coordinatorOwner PendingEvent
	var verdicts []Verdict
	pending := newPendingEvent(&FileEvent{Path: "/tmp/coordinator-panic"}, func(verdict Verdict) responseResult {
		verdicts = append(verdicts, verdict)
		return responseResult{accepted: true}
	})

	_, err := deliverPendingEvent(context.Background(), PendingHandlerFunc(func(_ context.Context, workerOwner PendingEvent) error {
		var err error
		coordinatorOwner, err = workerOwner.Transfer()
		if err != nil {
			return err
		}
		panic("panic after coordinator transfer")
	}), pending)
	if err == nil {
		t.Fatal("deliverPendingEvent error = nil, want panic error")
	}
	if len(verdicts) != 1 || verdicts[0] != VerdictDeny {
		t.Fatalf("verdicts = %v, want [deny]", verdicts)
	}
	if verdict, resolved := pending.logicalVerdict(); !resolved || verdict != VerdictDeny {
		t.Fatalf("logical verdict = %s resolved=%v, want deny/true", verdict, resolved)
	}
	if err := coordinatorOwner.Respond(VerdictAllow); !errors.Is(err, ErrPendingEventAlreadyResolved) {
		t.Fatalf("coordinator second verdict error = %v, want ErrPendingEventAlreadyResolved", err)
	}
	if len(verdicts) != 1 {
		t.Fatalf("verdict count after coordinator retry = %d, want 1", len(verdicts))
	}
}

func TestPendingEventPanicResolvesOwnership(t *testing.T) {
	var verdicts []Verdict
	pending := newPendingEvent(&FileEvent{Path: "/tmp/panic"}, func(verdict Verdict) responseResult {
		verdicts = append(verdicts, verdict)
		return responseResult{accepted: true}
	})

	_, err := deliverPendingEvent(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		panic("decision panic")
	}), pending)
	if err == nil {
		t.Fatal("deliverPendingEvent error = nil, want panic error")
	}
	if len(verdicts) != 1 || verdicts[0] != VerdictDeny {
		t.Fatalf("verdicts = %v, want [deny]", verdicts)
	}
}

func TestPendingEventCancellationResolvesOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var called atomic.Bool
	var verdicts []Verdict
	pending := newPendingEvent(&FileEvent{Path: "/tmp/cancel"}, func(verdict Verdict) responseResult {
		verdicts = append(verdicts, verdict)
		return responseResult{accepted: true}
	})

	_, err := deliverPendingEvent(ctx, PendingHandlerFunc(func(context.Context, PendingEvent) error {
		called.Store(true)
		return nil
	}), pending)
	if err != nil {
		t.Fatalf("deliverPendingEvent: %v", err)
	}
	if called.Load() {
		t.Fatal("handler was called after cancellation")
	}
	if len(verdicts) != 1 || verdicts[0] != VerdictDeny {
		t.Fatalf("verdicts = %v, want [deny]", verdicts)
	}
}

func TestPendingEventCancellationDuringHandlerResolvesOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var verdicts []Verdict
	pending := newPendingEvent(&FileEvent{Path: "/tmp/cancel-active"}, func(verdict Verdict) responseResult {
		verdicts = append(verdicts, verdict)
		return responseResult{accepted: true}
	})

	_, err := deliverPendingEvent(ctx, PendingHandlerFunc(func(context.Context, PendingEvent) error {
		cancel()
		return nil
	}), pending)
	if !errors.Is(err, ErrPendingEventAbandoned) {
		t.Fatalf("deliverPendingEvent error = %v, want ErrPendingEventAbandoned", err)
	}
	if len(verdicts) != 1 || verdicts[0] != VerdictDeny {
		t.Fatalf("verdicts = %v, want [deny]", verdicts)
	}
}
