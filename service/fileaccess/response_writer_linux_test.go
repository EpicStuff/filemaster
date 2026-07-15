package fileaccess

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestFanotifyResponseWriterClosesAfterCompleteResponse(t *testing.T) {
	var order []string
	writer := newFanotifyResponseWriter(41, nopLogger{}, nil)
	writer.write = func(fd int, bytes []byte) (int, error) {
		order = append(order, "write")
		if fd != 41 {
			t.Fatalf("write fd = %d, want 41", fd)
		}
		response := *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0]))
		if response.Fd != 17 || response.Response != unix.FAN_ALLOW {
			t.Fatalf("response = %+v, want fd 17 allow", response)
		}
		return len(bytes), nil
	}
	writer.close = func(fd int) error {
		order = append(order, "close")
		if fd != 17 {
			t.Fatalf("close fd = %d, want 17", fd)
		}
		return nil
	}

	result := writer.respond(17, VerdictAllow)
	if result.err != nil || !result.accepted {
		t.Fatalf("respond result = %+v, want accepted without error", result)
	}
	if len(order) != 2 || order[0] != "write" || order[1] != "close" {
		t.Fatalf("operation order = %v, want [write close]", order)
	}
}

func TestFanotifyResponseWriterReleasesOnceAfterCloseError(t *testing.T) {
	closeCalls := 0
	releaseCalls := 0
	writer := newFanotifyResponseWriter(48, nopLogger{}, func(fd int32, closeErr error) {
		releaseCalls++
		if fd != 18 || !errors.Is(closeErr, unix.EIO) {
			t.Fatalf("close callback fd=%d err=%v, want fd 18 EIO", fd, closeErr)
		}
	})
	writer.write = func(_ int, bytes []byte) (int, error) {
		return len(bytes), nil
	}
	writer.close = func(fd int) error {
		closeCalls++
		if fd != 18 {
			t.Fatalf("close fd = %d, want 18", fd)
		}
		return unix.EIO
	}

	result := writer.respond(18, VerdictDeny)
	if !result.accepted || !errors.Is(result.err, unix.EIO) {
		t.Fatalf("respond result = %+v, want accepted EIO close error", result)
	}
	if closeCalls != 1 || releaseCalls != 1 {
		t.Fatalf("close calls=%d release calls=%d, want 1/1", closeCalls, releaseCalls)
	}
}

func TestFanotifyResponseWriterRetriesEINTRWithSameVerdict(t *testing.T) {
	writer := newFanotifyResponseWriter(42, nopLogger{}, nil)
	var responses []unix.FanotifyResponse
	writer.write = func(_ int, bytes []byte) (int, error) {
		responses = append(responses, *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0])))
		if len(responses) == 1 {
			return 0, unix.EINTR
		}
		return len(bytes), nil
	}
	var closes int
	writer.close = func(int) error {
		closes++
		return nil
	}

	result := writer.respond(18, VerdictDeny)
	if result.err != nil || !result.accepted {
		t.Fatalf("respond result = %+v, want accepted without error", result)
	}
	if len(responses) != 2 {
		t.Fatalf("write attempts = %d, want 2", len(responses))
	}
	for i, response := range responses {
		if response.Fd != 18 || response.Response != unix.FAN_DENY {
			t.Fatalf("attempt %d response = %+v, want fd 18 deny", i, response)
		}
	}
	if closes != 1 || writer.draining.Load() {
		t.Fatalf("closes=%d draining=%v, want 1/false", closes, writer.draining.Load())
	}
}

func TestFanotifyResponseWriterRejectsShortWrite(t *testing.T) {
	writer := newFanotifyResponseWriter(43, nopLogger{}, nil)
	writer.write = func(_ int, bytes []byte) (int, error) {
		return len(bytes) - 1, nil
	}
	var closes int
	writer.close = func(int) error {
		closes++
		return nil
	}

	result := writer.respond(19, VerdictAllow)
	if result.accepted || !errors.Is(result.err, ErrShortFanotifyResponse) {
		t.Fatalf("respond result = %+v, want unaccepted short-write error", result)
	}
	if closes != 0 {
		t.Fatalf("close calls = %d, want 0", closes)
	}
	if !writer.draining.Load() || !errors.Is(writer.fatalError(), ErrShortFanotifyResponse) {
		t.Fatalf("draining=%v fatal=%v, want fatal short-write state", writer.draining.Load(), writer.fatalError())
	}
}

func TestFanotifyResponseWriterUnrecoverableError(t *testing.T) {
	writer := newFanotifyResponseWriter(44, nopLogger{}, nil)
	writer.write = func(int, []byte) (int, error) {
		return 0, unix.EIO
	}
	var closes int
	writer.close = func(int) error {
		closes++
		return nil
	}

	result := writer.respond(20, VerdictDeny)
	if result.accepted || !errors.Is(result.err, unix.EIO) {
		t.Fatalf("respond result = %+v, want unaccepted EIO", result)
	}
	if closes != 0 {
		t.Fatalf("close calls = %d, want 0", closes)
	}
	if !writer.draining.Load() || !errors.Is(writer.fatalError(), unix.EIO) {
		t.Fatalf("draining=%v fatal=%v, want fatal EIO state", writer.draining.Load(), writer.fatalError())
	}
}

func TestFanotifyResponseWriterSerializesWrites(t *testing.T) {
	writer := newFanotifyResponseWriter(45, nopLogger{}, nil)
	var active atomic.Int32
	var peak atomic.Int32
	writer.write = func(_ int, bytes []byte) (int, error) {
		current := active.Add(1)
		for {
			old := peak.Load()
			if current <= old || peak.CompareAndSwap(old, current) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		active.Add(-1)
		return len(bytes), nil
	}
	writer.close = func(int) error { return nil }

	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, eventFD := range []int32{21, 22} {
		wg.Add(1)
		go func(eventFD int32) {
			defer wg.Done()
			<-start
			result := writer.respond(eventFD, VerdictAllow)
			if result.err != nil || !result.accepted {
				t.Errorf("respond(%d) = %+v", eventFD, result)
			}
		}(eventFD)
	}
	close(start)
	wg.Wait()
	if peak.Load() != 1 {
		t.Fatalf("concurrent write peak = %d, want 1", peak.Load())
	}
}

func TestFatalResponseFailureStartsControlledDraining(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first")
	secondPath := filepath.Join(dir, "second")
	if err := os.WriteFile(firstPath, []byte("first"), 0o600); err != nil {
		t.Fatalf("write first file: %v", err)
	}
	if err := os.WriteFile(secondPath, []byte("second"), 0o600); err != nil {
		t.Fatalf("write second file: %v", err)
	}
	first, err := os.Open(firstPath)
	if err != nil {
		t.Fatalf("open first file: %v", err)
	}
	defer first.Close()
	second, err := os.Open(secondPath)
	if err != nil {
		t.Fatalf("open second file: %v", err)
	}
	defer second.Close()

	writer := newFanotifyResponseWriter(46, nopLogger{}, nil)
	var writes atomic.Int32
	var secondResponse unix.FanotifyResponse
	writer.write = func(_ int, bytes []byte) (int, error) {
		if writes.Add(1) == 1 {
			return 0, unix.EIO
		}
		secondResponse = *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0]))
		return len(bytes), nil
	}
	writer.close = unix.Close
	source := &fanotifySource{
		log:          nopLogger{},
		responses:    writer,
		failedEvents: make(map[int32]PendingEvent),
	}
	source.activeScopes.Store(&scopeSnapshot{Scopes: []scopeMatch{{Configured: dir, Canonical: dir}}})
	var policyCalls atomic.Int32
	handler := PendingHandlerFunc(func(_ context.Context, pending PendingEvent) error {
		policyCalls.Add(1)
		return pending.Respond(VerdictAllow)
	})

	firstFD := int32(first.Fd())
	source.handleEvent(context.Background(), handler, &unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   firstFD,
		Mask: unix.FAN_OPEN_PERM,
	})
	if !writer.draining.Load() || !errors.Is(writer.fatalError(), unix.EIO) {
		t.Fatalf("draining=%v fatal=%v, want fatal EIO state", writer.draining.Load(), writer.fatalError())
	}
	source.failedMu.Lock()
	_, retained := source.failedEvents[firstFD]
	source.failedMu.Unlock()
	if !retained {
		t.Fatal("failed response event ownership was not retained")
	}

	secondFD := int32(second.Fd())
	source.handleEvent(context.Background(), handler, &unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   secondFD,
		Mask: unix.FAN_OPEN_PERM,
	})
	if policyCalls.Load() != 1 {
		t.Fatalf("policy calls = %d, want 1 before draining only", policyCalls.Load())
	}
	if writes.Load() != 2 {
		t.Fatalf("response writes = %d, want 2", writes.Load())
	}
	if secondResponse.Fd != secondFD || secondResponse.Response != unix.FAN_DENY {
		t.Fatalf("drain response = %+v, want second fd denied", secondResponse)
	}
}

func TestRecoveryDenyFailureRetainsCurrentCoordinatorOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned")
	if err := os.WriteFile(path, []byte("owned"), 0o600); err != nil {
		t.Fatalf("write owned file: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open owned file: %v", err)
	}
	defer file.Close()

	writer := newFanotifyResponseWriter(47, nopLogger{}, nil)
	var writes atomic.Int32
	writer.write = func(int, []byte) (int, error) {
		writes.Add(1)
		return 0, unix.EIO
	}
	var closes atomic.Int32
	writer.close = func(int) error {
		closes.Add(1)
		return nil
	}
	source := &fanotifySource{
		log:          nopLogger{},
		responses:    writer,
		failedEvents: make(map[int32]PendingEvent),
	}
	source.activeScopes.Store(&scopeSnapshot{Scopes: []scopeMatch{{Configured: dir, Canonical: dir}}})

	handlerErr := errors.New("worker failed after coordinator transfer")
	var coordinatorOwner PendingEvent
	handler := PendingHandlerFunc(func(_ context.Context, workerOwner PendingEvent) error {
		var err error
		coordinatorOwner, err = workerOwner.Transfer()
		if err != nil {
			return err
		}
		return handlerErr
	})

	eventFD := int32(file.Fd())
	source.handleEvent(context.Background(), handler, &unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   eventFD,
		Mask: unix.FAN_OPEN_PERM,
	})

	source.failedMu.Lock()
	retainedOwner := source.failedEvents[eventFD]
	source.failedMu.Unlock()
	if retainedOwner == nil {
		t.Fatal("source did not retain failed recovery response owner")
	}
	retained := retainedOwner.(*pendingEventOwner)
	coordinator := coordinatorOwner.(*pendingEventOwner)
	if retained.owner != coordinator.owner {
		t.Fatalf("retained owner token = %d, want current coordinator token %d", retained.owner, coordinator.owner)
	}
	if retained.Event() == nil || coordinatorOwner.Event() == nil {
		t.Fatal("current coordinator ownership was not retained after recovery response failure")
	}
	if verdict, resolved := retained.logicalVerdict(); !resolved || verdict != VerdictDeny {
		t.Fatalf("logical verdict = %s resolved=%v, want deny/true", verdict, resolved)
	}
	if err := coordinatorOwner.Respond(VerdictAllow); !errors.Is(err, ErrPendingEventAlreadyResolved) {
		t.Fatalf("coordinator second verdict error = %v, want ErrPendingEventAlreadyResolved", err)
	}
	if writes.Load() != 1 || closes.Load() != 0 {
		t.Fatalf("writes=%d closes=%d, want 1/0", writes.Load(), closes.Load())
	}
}
