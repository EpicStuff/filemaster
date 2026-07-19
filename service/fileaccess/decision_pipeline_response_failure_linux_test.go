//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type failedResponseDecisionHandler struct {
	afterResponse int
	refreshed     int
}

func (h *failedResponseDecisionHandler) Decide(context.Context, *FileEvent) Verdict {
	return VerdictAllow
}

func (h *failedResponseDecisionHandler) DecideForResponse(context.Context, *FileEvent) (Verdict, func()) {
	return VerdictAllow, func() { h.afterResponse++ }
}

func (h *failedResponseDecisionHandler) RefreshProcessMapping(context.Context, int32) error {
	h.refreshed++
	return nil
}

type failedResponseObserver struct {
	handler  *failedResponseDecisionHandler
	observed int
}

func (h *failedResponseObserver) Decide(ctx context.Context, event *FileEvent) Verdict {
	return h.handler.Decide(ctx, event)
}

func (h *failedResponseObserver) DecisionHandler() Handler { return h.handler }

func (h *failedResponseObserver) Observe(*FileEvent, Verdict) { h.observed++ }

func waitForRetainedFailure(t *testing.T, source *fanotifySource, pipeline *DecisionPipeline, eventFD int32) PendingEvent {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		source.failedMu.Lock()
		owner := source.failedEvents[eventFD]
		source.failedMu.Unlock()
		if owner != nil && pipeline.outstanding.Load() == 0 {
			return owner
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for failed event fd %d to be retained", eventFD)
	return nil
}

func TestDecisionPipelineRetainsUnacceptedFanotifyResponse(t *testing.T) {
	testCases := []struct {
		name  string
		write func([]byte) (int, error)
	}{
		{
			name: "write error",
			write: func([]byte) (int, error) {
				return 0, unix.EIO
			},
		},
		{
			name: "short write",
			write: func(bytes []byte) (int, error) {
				return len(bytes) - 1, nil
			},
		},
	}

	for index, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := newReaderTestSource(1)
			eventFD := int32(700 + index)
			source.accountEventFD(eventFD)
			source.responses.write = func(_ int, bytes []byte) (int, error) {
				return testCase.write(bytes)
			}

			handler := &failedResponseDecisionHandler{}
			observer := &failedResponseObserver{handler: handler}
			pipeline := NewDecisionPipeline(observer, DecisionPipelineConfig{
				Workers:          1,
				QueueCapacity:    1,
				OutstandingLimit: 1,
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pipeline.Start(ctx)

			event := FileEvent{PID: 42, Op: OpExec}
			initialOwner := source.newFanotifyPendingEvent(&event, eventFD)
			if _, err := deliverPendingEvent(ctx, pipeline, initialOwner); err != nil {
				t.Fatalf("queue delivery error = %v", err)
			}

			retained := waitForRetainedFailure(t, source, pipeline, eventFD)
			retainedOwner, ok := retained.(*pendingEventOwner)
			if !ok {
				t.Fatalf("retained owner type = %T, want *pendingEventOwner", retained)
			}
			initialOwner.state.mu.Lock()
			currentOwner := initialOwner.state.currentOwner
			verdict, decided := initialOwner.state.verdict, initialOwner.state.verdictSet
			initialOwner.state.mu.Unlock()
			if retainedOwner.state != initialOwner.state || retainedOwner.owner != currentOwner || retainedOwner.owner == initialOwner.owner {
				t.Fatalf("retained owner = %+v, current owner=%d; want actual transferred current owner", retainedOwner, currentOwner)
			}
			if !decided || verdict != VerdictAllow {
				t.Fatalf("latched verdict = %v, decided=%v; want allow", verdict, decided)
			}
			if err := retained.Respond(VerdictDeny); !errors.Is(err, ErrPendingEventAlreadyResolved) {
				t.Fatalf("second retained-owner verdict error = %v, want ErrPendingEventAlreadyResolved", err)
			}
			if diagnostics := source.ReaderDiagnostics(); diagnostics.OutstandingDescriptors != 0 {
				t.Fatalf("outstanding descriptors = %d, want group-closed failed descriptor released", diagnostics.OutstandingDescriptors)
			}
			if !source.responses.draining.Load() {
				t.Fatal("response writer did not enter fatal draining")
			}
			if handler.afterResponse != 0 || handler.refreshed != 0 || observer.observed != 0 {
				t.Fatalf("post-response work ran after unaccepted response: after=%d refresh=%d observe=%d", handler.afterResponse, handler.refreshed, observer.observed)
			}
		})
	}
}

func TestDecisionPipelineAcceptedCloseErrorDoesNotRetainFanotifyEvent(t *testing.T) {
	source := newReaderTestSource(1)
	const eventFD int32 = 711
	source.accountEventFD(eventFD)
	source.responses.close = func(int) error { return unix.EIO }

	pipeline := NewDecisionPipeline(HandlerFunc(func(context.Context, *FileEvent) Verdict {
		return VerdictAllow
	}), DecisionPipelineConfig{Workers: 1, QueueCapacity: 1, OutstandingLimit: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pipeline.Start(ctx)

	pending := source.newFanotifyPendingEvent(&FileEvent{Op: OpOpen}, eventFD)
	if _, err := deliverPendingEvent(ctx, pipeline, pending); err != nil {
		t.Fatalf("queue delivery error = %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for pipeline.outstanding.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if pipeline.outstanding.Load() != 0 {
		t.Fatal("pipeline did not finish accepted close-error response")
	}

	source.failedMu.Lock()
	retained := source.failedEvents[eventFD]
	source.failedMu.Unlock()
	if retained != nil {
		t.Fatal("accepted response with close error was retained")
	}
	if diagnostics := source.ReaderDiagnostics(); diagnostics.OutstandingDescriptors != 0 {
		t.Fatalf("outstanding descriptors = %d, want released after close attempt", diagnostics.OutstandingDescriptors)
	}
}

func TestSynchronousUnacceptedFanotifyResponseRetainsOwnerOnce(t *testing.T) {
	source := newReaderTestSource(1)
	const eventFD int32 = 712
	source.accountEventFD(eventFD)
	source.responses.write = func(_ int, _ []byte) (int, error) { return 0, unix.EIO }
	pending := source.newFanotifyPendingEvent(&FileEvent{Op: OpOpen}, eventFD)

	if err := pending.Respond(VerdictAllow); !errors.Is(err, unix.EIO) {
		t.Fatalf("first response error = %v, want EIO", err)
	}
	if err := pending.Respond(VerdictDeny); !errors.Is(err, ErrPendingEventAlreadyResolved) {
		t.Fatalf("second response error = %v, want ErrPendingEventAlreadyResolved", err)
	}
	source.failedMu.Lock()
	retained := source.failedEvents[eventFD]
	retainedCount := len(source.failedEvents)
	source.failedMu.Unlock()
	if retained != pending || retainedCount != 1 {
		t.Fatalf("synchronous failed retention = owner %p count %d, want original owner once", retained, retainedCount)
	}
}
