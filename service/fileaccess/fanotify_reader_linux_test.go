//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func newReaderTestSource(limit int64) *fanotifySource {
	source := &fanotifySource{
		log:                nopLogger{},
		descriptorLimit:    limit,
		accounted:          make(map[int32]struct{}),
		descriptorReleased: make(chan struct{}, 1),
		failedEvents:       make(map[int32]PendingEvent),
	}
	if fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0); err == nil {
		source.emergencyFD = fd
	}
	source.responses = newFanotifyResponseWriter(99, nopLogger{}, source.finishEventFDClose)
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		return len(bytes), nil
	}
	source.responses.close = func(int) error { return nil }
	return source
}

func TestDecisionLatencyDiagnosticsTrackOnlyAcceptedResponses(t *testing.T) {
	source := newReaderTestSource(8)
	accepted := source.newFanotifyPendingEvent(&FileEvent{Op: OpOpen}, 101)
	if err := accepted.Respond(VerdictAllow); err != nil {
		t.Fatalf("accept response: %v", err)
	}
	diagnostic := source.ReaderDiagnostics()
	if diagnostic.DecisionResponseCount != 1 {
		t.Fatalf("accepted response count = %d, want 1", diagnostic.DecisionResponseCount)
	}
	if diagnostic.LastDecisionLatencyNanos <= 0 {
		t.Fatalf("accepted response latency = %d, want positive", diagnostic.LastDecisionLatencyNanos)
	}

	source.responses.write = func(_ int, _ []byte) (int, error) { return 0, unix.EIO }
	unaccepted := source.newFanotifyPendingEvent(&FileEvent{Op: OpOpen}, 102)
	if err := unaccepted.Respond(VerdictDeny); !errors.Is(err, unix.EIO) {
		t.Fatalf("unaccepted response error = %v, want EIO", err)
	}
	diagnostic = source.ReaderDiagnostics()
	if diagnostic.DecisionResponseCount != 1 {
		t.Fatalf("unaccepted response changed count to %d", diagnostic.DecisionResponseCount)
	}
}

// TestResponseLatencyMeasuresWriteSeparately proves response latency (§15.19)
// captures the kernel-write cost on its own, distinct from decision latency.
func TestResponseLatencyMeasuresWriteSeparately(t *testing.T) {
	source := newReaderTestSource(8)
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		time.Sleep(5 * time.Millisecond)
		return len(bytes), nil
	}
	pending := source.newFanotifyPendingEvent(&FileEvent{Op: OpOpen}, 101)
	if err := pending.Respond(VerdictAllow); err != nil {
		t.Fatalf("accept response: %v", err)
	}
	diagnostic := source.ReaderDiagnostics()
	if diagnostic.LastResponseLatencyNanos < (4 * time.Millisecond).Nanoseconds() {
		t.Fatalf("response latency = %dns, want >= 4ms (the write sleep)", diagnostic.LastResponseLatencyNanos)
	}
}

func fanotifyEventBytes(events ...unix.FanotifyEventMetadata) []byte {
	metadataSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	buf := make([]byte, 0, len(events)*metadataSize)
	for _, event := range events {
		if event.Event_len == 0 {
			event.Event_len = uint32(metadataSize)
		}
		if event.Metadata_len == 0 {
			event.Metadata_len = uint16(metadataSize)
		}
		bytes := unsafe.Slice((*byte)(unsafe.Pointer(&event)), metadataSize)
		buf = append(buf, bytes...)
	}
	return buf
}

func TestReaderAccountsCompleteBatchBeforeRouting(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "first"), filepath.Join(dir, "second")}
	files := make([]*os.File, 0, len(paths))
	for _, path := range paths {
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		files = append(files, file)
	}

	source := newReaderTestSource(8)
	source.activeScopes.Store(&scopeSnapshot{Scopes: []scopeMatch{{Configured: dir, Canonical: dir}}})
	handled := 0
	handler := PendingHandlerFunc(func(_ context.Context, pending PendingEvent) error {
		handled++
		if handled == 1 {
			diagnostics := source.ReaderDiagnostics()
			if diagnostics.OutstandingDescriptors != 2 || diagnostics.PeakOutstandingDescriptors != 2 {
				t.Fatalf("first policy call diagnostics = %+v, want both batch descriptors accounted", diagnostics)
			}
		}
		return pending.Respond(VerdictAllow)
	})

	source.handleEvents(context.Background(), handler, fanotifyEventBytes(
		unix.FanotifyEventMetadata{Vers: unix.FANOTIFY_METADATA_VERSION, Fd: int32(files[0].Fd()), Mask: unix.FAN_OPEN_PERM},
		unix.FanotifyEventMetadata{Vers: unix.FANOTIFY_METADATA_VERSION, Fd: int32(files[1].Fd()), Mask: unix.FAN_OPEN_PERM},
	))

	if handled != 2 {
		t.Fatalf("handled %d events, want 2", handled)
	}
	if diagnostics := source.ReaderDiagnostics(); diagnostics.OutstandingDescriptors != 0 || diagnostics.PeakOutstandingDescriptors != 2 {
		t.Fatalf("final diagnostics = %+v, want outstanding 0 and peak 2", diagnostics)
	}
}

func TestOutsideScopeDescriptorRemainsAccountedThroughAllow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "outside")
	if err := os.WriteFile(path, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	source := newReaderTestSource(4)
	scope := filepath.Join(dir, "scope")
	if err := os.Mkdir(scope, 0o700); err != nil {
		t.Fatal(err)
	}
	source.activeScopes.Store(&scopeSnapshot{Scopes: []scopeMatch{{Configured: scope, Canonical: scope}}})
	var response unix.FanotifyResponse
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		if got := source.ReaderDiagnostics().OutstandingDescriptors; got != 1 {
			t.Fatalf("outstanding during outside-scope response = %d, want 1", got)
		}
		response = *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0]))
		return len(bytes), nil
	}

	source.handleEvents(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		t.Fatal("outside-scope event reached policy handler")
		return nil
	}), fanotifyEventBytes(unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   int32(file.Fd()),
		Mask: unix.FAN_OPEN_PERM,
	}))

	if response.Response != unix.FAN_ALLOW {
		t.Fatalf("outside-scope response = %+v, want FAN_ALLOW", response)
	}
	if got := source.ReaderDiagnostics().OutstandingDescriptors; got != 0 {
		t.Fatalf("outstanding after outside-scope close = %d, want 0", got)
	}
}

func TestDescriptorHeadroomAndReadBatchCapacity(t *testing.T) {
	if got := calculateDescriptorLimit(1024, 256); got != 768 {
		t.Fatalf("descriptor limit = %d, want 768", got)
	}
	if got := calculateDescriptorLimit(256, 256); got != 0 {
		t.Fatalf("descriptor limit at reserve = %d, want 0", got)
	}

	metadataSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	if got := readBufferCapacity(3); got != 3*metadataSize {
		t.Fatalf("three-event buffer = %d, want %d", got, 3*metadataSize)
	}
	if got := readBufferCapacity(0); got != 0 {
		t.Fatalf("zero-headroom buffer = %d, want 0", got)
	}
	if got := readBufferCapacity(1 << 20); got > maxFanotifyReadBuffer || got%metadataSize != 0 {
		t.Fatalf("capped buffer = %d, want metadata-aligned size <= %d", got, maxFanotifyReadBuffer)
	}
}

func TestConfiguredOutstandingBudgetCapsReaderHeadroom(t *testing.T) {
	source := newReaderTestSource(8)
	source.SetDescriptorBudget(3)
	if got := source.descriptorHeadroom(); got != 3 {
		t.Fatalf("configured descriptor headroom = %d, want 3", got)
	}
	source.SetDescriptorBudget(10)
	if got := source.descriptorHeadroom(); got != 3 {
		t.Fatalf("descriptor budget enlarged headroom = %d, want 3", got)
	}
}

func TestReaderDeniesOverloadInsteadOfPausing(t *testing.T) {
	source := newReaderTestSource(1)
	source.accountEventFD(101)
	source.poll = func([]unix.PollFd, int) (int, error) { return 1, nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	meta := unix.FanotifyEventMetadata{
		Event_len:    uint32(unsafe.Sizeof(unix.FanotifyEventMetadata{})),
		Metadata_len: uint16(unsafe.Sizeof(unix.FanotifyEventMetadata{})),
		Vers:         unix.FANOTIFY_METADATA_VERSION,
		Fd:           102,
		Mask:         unix.FAN_OPEN_PERM,
	}
	readCalled := make(chan int, 1)
	source.read = func(_ int, bytes []byte) (int, error) {
		readCalled <- len(bytes)
		copy(bytes, fanotifyEventBytes(meta))
		cancel()
		return int(unsafe.Sizeof(meta)), nil
	}
	var response unix.FanotifyResponse
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		response = *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0]))
		return len(bytes), nil
	}
	policyCalls := 0
	done := make(chan error, 1)
	go func() {
		done <- source.Run(ctx, PendingHandlerFunc(func(context.Context, PendingEvent) error {
			policyCalls++
			return nil
		}))
	}()

	select {
	case size := <-readCalled:
		want := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
		if size != want {
			t.Fatalf("overload read buffer = %d, want %d", size, want)
		}
	case <-time.After(time.Second):
		t.Fatal("reader paused instead of consuming an overload event")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if response.Fd != meta.Fd || response.Response != unix.FAN_DENY {
		t.Fatalf("overload response = %+v, want fd %d deny", response, meta.Fd)
	}
	if policyCalls != 0 {
		t.Fatalf("overload event reached policy %d times", policyCalls)
	}
	source.releaseEventFD(101)
	if diagnostics := source.ReaderDiagnostics(); diagnostics.OutstandingDescriptors != 0 {
		t.Fatalf("overload descriptor accounting leaked: %+v", diagnostics)
	}
}

func TestReaderHandlesEMFILEAsDegradedCapacityFailure(t *testing.T) {
	source := newReaderTestSource(8)
	source.poll = func([]unix.PollFd, int) (int, error) { return 1, nil }

	meta := unix.FanotifyEventMetadata{
		Event_len:    uint32(unsafe.Sizeof(unix.FanotifyEventMetadata{})),
		Metadata_len: uint16(unsafe.Sizeof(unix.FanotifyEventMetadata{})),
		Vers:         unix.FANOTIFY_METADATA_VERSION,
		Fd:           102,
		Mask:         unix.FAN_OPEN_PERM,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reads := 0
	source.read = func(_ int, bytes []byte) (int, error) {
		reads++
		if reads == 1 {
			return 0, unix.EMFILE
		}
		copy(bytes, fanotifyEventBytes(meta))
		cancel()
		return int(unsafe.Sizeof(meta)), nil
	}

	var response unix.FanotifyResponse
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		response = *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0]))
		return len(bytes), nil
	}
	if err := source.Run(ctx, PendingHandlerFunc(func(context.Context, PendingEvent) error {
		t.Fatal("EMFILE recovery event reached normal policy")
		return nil
	})); err != nil {
		t.Fatal(err)
	}

	if reads != 2 {
		t.Fatalf("read attempts = %d, want EMFILE then emergency-slot read", reads)
	}
	if response.Fd != meta.Fd || response.Response != unix.FAN_DENY {
		t.Fatalf("EMFILE emergency response = %+v, want fd %d deny", response, meta.Fd)
	}
	diagnostics := source.ReaderDiagnostics()
	if diagnostics.EMFILECount != 1 || !diagnostics.Degraded {
		t.Fatalf("EMFILE diagnostics = %+v", diagnostics)
	}
	if diagnostics.DescriptorPressure {
		t.Fatalf("descriptor pressure remained set after the emergency denial recovered: %+v", diagnostics)
	}
	if diagnostics.OutstandingDescriptors != 0 {
		t.Fatalf("EMFILE emergency descriptor accounting leaked: %+v", diagnostics)
	}
}

func TestReaderPollAndReadFailuresEnterFatalStateAndCloseGroup(t *testing.T) {
	for _, test := range []struct {
		name string
		set  func(*fanotifySource)
		want string
	}{
		{
			name: "poll",
			set: func(source *fanotifySource) {
				source.poll = func([]unix.PollFd, int) (int, error) {
					return 0, unix.EIO
				}
			},
			want: "poll",
		},
		{
			name: "read",
			set: func(source *fanotifySource) {
				source.poll = func([]unix.PollFd, int) (int, error) {
					return 1, nil
				}
				source.read = func(int, []byte) (int, error) {
					return 0, unix.EIO
				}
			},
			want: "read",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := newReaderTestSource(8)
			test.set(source)

			err := source.Run(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
				t.Fatal("fatal reader failure reached policy")
				return nil
			}))
			if !errors.Is(err, unix.EIO) {
				t.Fatalf("reader error = %v, want EIO", err)
			}

			diagnostics := source.ReaderDiagnostics()
			if !diagnostics.Fatal || !diagnostics.Degraded || !diagnostics.Exited || diagnostics.Running {
				t.Fatalf("reader diagnostics after fatal %s failure = %+v", test.name, diagnostics)
			}
			if diagnostics.FatalError == "" || !strings.Contains(diagnostics.FatalError, test.want) {
				t.Fatalf("fatal error = %q, want %q", diagnostics.FatalError, test.want)
			}
			response := source.ResponseDiagnostics()
			if !response.Sealed || !response.Closed {
				t.Fatalf("response group was not sealed and closed after fatal %s failure: %+v", test.name, response)
			}
		})
	}
}

func TestQueueOverflowDetectedWithoutUsableDescriptor(t *testing.T) {
	source := newReaderTestSource(8)
	handled := 0
	source.handleEvents(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		handled++
		return nil
	}), fanotifyEventBytes(unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   unix.FAN_NOFD,
		Mask: unix.FAN_Q_OVERFLOW,
	}))

	diagnostics := source.ReaderDiagnostics()
	if diagnostics.QueueOverflowCount != 1 || !diagnostics.Degraded || diagnostics.OutstandingDescriptors != 0 {
		t.Fatalf("overflow diagnostics = %+v", diagnostics)
	}
	if handled != 0 {
		t.Fatalf("overflow without descriptor reached handler %d times", handled)
	}
}

func TestMalformedVisiblePermissionEventsAreDeniedAndFatal(t *testing.T) {
	metadataSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	tests := []struct {
		name string
		meta unix.FanotifyEventMetadata
		want string
	}{
		{
			name: "invalid event length",
			meta: unix.FanotifyEventMetadata{
				Event_len:    uint32(metadataSize - 1),
				Metadata_len: uint16(metadataSize),
				Vers:         unix.FANOTIFY_METADATA_VERSION,
				Fd:           201,
				Mask:         unix.FAN_OPEN_PERM,
			},
			want: "invalid fanotify event length",
		},
		{
			name: "invalid metadata length",
			meta: unix.FanotifyEventMetadata{
				Event_len:    uint32(metadataSize),
				Metadata_len: uint16(metadataSize - 1),
				Vers:         unix.FANOTIFY_METADATA_VERSION,
				Fd:           202,
				Mask:         unix.FAN_OPEN_PERM,
			},
			want: "invalid fanotify metadata length",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := newReaderTestSource(1)
			var response unix.FanotifyResponse
			source.responses.write = func(_ int, bytes []byte) (int, error) {
				response = *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0]))
				return len(bytes), nil
			}
			policyCalls := 0
			err := source.handleEvents(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
				policyCalls++
				return nil
			}), fanotifyEventBytes(tc.meta))

			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("batch error = %v, want %q", err, tc.want)
			}
			if response.Fd != tc.meta.Fd || response.Response != unix.FAN_DENY {
				t.Fatalf("malformed event response = %+v, want fd %d deny", response, tc.meta.Fd)
			}
			diagnostics := source.ReaderDiagnostics()
			if diagnostics.OutstandingDescriptors != 0 || !diagnostics.Fatal || !diagnostics.Degraded {
				t.Fatalf("malformed event diagnostics = %+v, want fatal without accounting leak", diagnostics)
			}
			if policyCalls != 0 || !source.responses.draining.Load() {
				t.Fatalf("policy calls=%d draining=%v, want 0/true", policyCalls, source.responses.draining.Load())
			}
		})
	}
}

func TestMalformedVisibleNonPermissionFDIsClosedAndReleased(t *testing.T) {
	metadataSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	source := newReaderTestSource(1)
	closed := make(map[int]int)
	source.responses.close = func(fd int) error {
		closed[fd]++
		return nil
	}

	err := source.handleEvents(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		t.Fatal("malformed nonpermission event reached policy")
		return nil
	}), fanotifyEventBytes(unix.FanotifyEventMetadata{
		Event_len:    uint32(metadataSize - 1),
		Metadata_len: uint16(metadataSize),
		Vers:         unix.FANOTIFY_METADATA_VERSION,
		Fd:           203,
	}))
	if err == nil || closed[203] != 1 || closed[99] != 1 {
		t.Fatalf("batch error=%v closes=%+v, want event and fatal group each closed once", err, closed)
	}
	if diagnostics := source.ReaderDiagnostics(); diagnostics.OutstandingDescriptors != 0 {
		t.Fatalf("malformed nonpermission accounting = %+v, want released", diagnostics)
	}
}

func TestOverflowDetectedBeforeVisibleFDHandling(t *testing.T) {
	metadataSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	source := newReaderTestSource(1)
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		diagnostics := source.ReaderDiagnostics()
		if diagnostics.QueueOverflowCount != 1 || diagnostics.OutstandingDescriptors != 1 {
			t.Fatalf("diagnostics during malformed overflow response = %+v, want overflow recorded before FD handling", diagnostics)
		}
		return len(bytes), nil
	}

	err := source.handleEvents(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		t.Fatal("malformed overflow event reached policy")
		return nil
	}), fanotifyEventBytes(unix.FanotifyEventMetadata{
		Event_len:    uint32(metadataSize - 1),
		Metadata_len: uint16(metadataSize),
		Vers:         unix.FANOTIFY_METADATA_VERSION,
		Fd:           204,
		Mask:         unix.FAN_Q_OVERFLOW | unix.FAN_OPEN_PERM,
	}))
	if err == nil {
		t.Fatal("malformed overflow batch returned nil error")
	}
	diagnostics := source.ReaderDiagnostics()
	if diagnostics.QueueOverflowCount != 1 || diagnostics.OutstandingDescriptors != 0 {
		t.Fatalf("final malformed overflow diagnostics = %+v", diagnostics)
	}
}

func TestValidEarlierEventsAreResolvedBeforeMalformedBatchReturns(t *testing.T) {
	metadataSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	source := newReaderTestSource(3)
	var responses []unix.FanotifyResponse
	closed := make(map[int]int)
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		responses = append(responses, *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0])))
		return len(bytes), nil
	}
	source.responses.close = func(fd int) error {
		closed[fd]++
		return nil
	}
	policyCalls := 0
	err := source.handleEvents(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		policyCalls++
		return nil
	}), fanotifyEventBytes(
		unix.FanotifyEventMetadata{
			Vers: unix.FANOTIFY_METADATA_VERSION,
			Fd:   301,
			Mask: unix.FAN_OPEN_PERM,
		},
		unix.FanotifyEventMetadata{
			Event_len:    uint32(metadataSize - 1),
			Metadata_len: uint16(metadataSize),
			Vers:         unix.FANOTIFY_METADATA_VERSION,
			Fd:           302,
			Mask:         unix.FAN_OPEN_PERM,
		},
		// This valid-looking record is in an unframed tail. The parser must
		// not guess its boundary or descriptor location after malformed 302.
		unix.FanotifyEventMetadata{
			Vers: unix.FANOTIFY_METADATA_VERSION,
			Fd:   303,
			Mask: unix.FAN_OPEN_PERM,
		},
	))
	if err == nil || !strings.Contains(err.Error(), "unparseable") {
		t.Fatalf("valid-plus-malformed batch error = %v, want explicit unparseable-tail fatal error", err)
	}
	if policyCalls != 0 {
		t.Fatalf("policy calls = %d, want fatal batch to bypass policy", policyCalls)
	}
	if len(responses) != 2 {
		t.Fatalf("responses = %+v, want only safely identified descriptors denied", responses)
	}
	responded := map[int32]uint32{}
	for _, response := range responses {
		if _, exists := responded[response.Fd]; exists {
			t.Fatalf("duplicate response for fd %d: %+v", response.Fd, responses)
		}
		responded[response.Fd] = response.Response
	}
	if responded[301] != unix.FAN_DENY || responded[302] != unix.FAN_DENY {
		t.Fatalf("responses = %+v, want fds 301 and 302 denied", responses)
	}
	if _, exists := responded[303]; exists {
		t.Fatalf("unframed tail fd 303 was guessed and responded: %+v", responses)
	}
	if closed[301] != 1 || closed[302] != 1 {
		t.Fatalf("event descriptor closes = %+v, want fds 301 and 302 exactly once", closed)
	}
	diagnostics := source.ReaderDiagnostics()
	if diagnostics.OutstandingDescriptors != 0 || diagnostics.PeakOutstandingDescriptors != 2 || !diagnostics.Fatal || !diagnostics.Degraded {
		t.Fatalf("valid-plus-malformed diagnostics = %+v", diagnostics)
	}
	if !strings.Contains(diagnostics.FatalError, "unparseable") || !source.ResponseDiagnostics().Closed {
		t.Fatalf("fatal tail/group diagnostics = %+v response=%+v", diagnostics, source.ResponseDiagnostics())
	}
}

func TestMetadataVersionMismatchTerminatesSourceBeforeLaterPolicy(t *testing.T) {
	source := newReaderTestSource(4)
	firstBatch := fanotifyEventBytes(
		unix.FanotifyEventMetadata{
			Vers: unix.FANOTIFY_METADATA_VERSION + 1,
			Fd:   401,
			Mask: unix.FAN_OPEN_PERM,
		},
		unix.FanotifyEventMetadata{
			Vers: unix.FANOTIFY_METADATA_VERSION,
			Fd:   402,
			Mask: unix.FAN_OPEN_PERM,
		},
	)
	secondBatch := fanotifyEventBytes(unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   403,
		Mask: unix.FAN_OPEN_PERM,
	})
	readCalls := 0
	source.poll = func([]unix.PollFd, int) (int, error) { return 1, nil }
	source.read = func(_ int, bytes []byte) (int, error) {
		readCalls++
		batch := secondBatch
		if readCalls == 1 {
			batch = firstBatch
		}
		copy(bytes, batch)
		return len(batch), nil
	}
	var responses []unix.FanotifyResponse
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		responses = append(responses, *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0])))
		return len(bytes), nil
	}
	policyCalls := 0
	err := source.Run(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		policyCalls++
		return nil
	}))

	if err == nil || !strings.Contains(err.Error(), "metadata version mismatch") {
		t.Fatalf("source error = %v, want metadata version mismatch", err)
	}
	if readCalls != 1 || policyCalls != 0 {
		t.Fatalf("read calls=%d policy calls=%d, want source stop after first read without policy", readCalls, policyCalls)
	}
	if len(responses) != 1 || responses[0].Fd != 401 || responses[0].Response != unix.FAN_DENY {
		t.Fatalf("fatal mismatch responses = %+v, want only safely identified fd 401 denied", responses)
	}
	diagnostics := source.ReaderDiagnostics()
	if !diagnostics.Fatal || !diagnostics.Degraded || !strings.Contains(diagnostics.FatalError, "metadata version mismatch") || !strings.Contains(diagnostics.FatalError, "unparseable") {
		t.Fatalf("metadata mismatch diagnostics = %+v", diagnostics)
	}
	if diagnostics.OutstandingDescriptors != 0 || !source.responses.draining.Load() {
		t.Fatalf("metadata mismatch accounting/draining = %+v draining=%v", diagnostics, source.responses.draining.Load())
	}
}

func TestMetadataVersionMismatchFatalScanResolvesWholeBatch(t *testing.T) {
	metadataSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	source := newReaderTestSource(4)
	firstBatch := fanotifyEventBytes(
		unix.FanotifyEventMetadata{
			Vers: unix.FANOTIFY_METADATA_VERSION,
			Fd:   411,
			Mask: unix.FAN_OPEN_PERM,
		},
		unix.FanotifyEventMetadata{
			// A mismatched version makes this length untrusted even though it
			// appears to span the returned buffer.
			Event_len:    uint32(metadataSize * 3),
			Metadata_len: uint16(metadataSize),
			Vers:         unix.FANOTIFY_METADATA_VERSION + 1,
			Fd:           412,
			Mask:         unix.FAN_OPEN_PERM,
		},
		unix.FanotifyEventMetadata{
			Vers: unix.FANOTIFY_METADATA_VERSION,
			Fd:   413,
			Mask: unix.FAN_OPEN_PERM,
		},
	)
	secondBatch := fanotifyEventBytes(unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   414,
		Mask: unix.FAN_OPEN_PERM,
	})
	readCalls := 0
	source.poll = func([]unix.PollFd, int) (int, error) { return 1, nil }
	source.read = func(_ int, bytes []byte) (int, error) {
		readCalls++
		batch := secondBatch
		if readCalls == 1 {
			batch = firstBatch
		}
		copy(bytes, batch)
		return len(batch), nil
	}

	var responses []unix.FanotifyResponse
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		responses = append(responses, *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0])))
		return len(bytes), nil
	}
	policyCalls := 0
	err := source.Run(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		policyCalls++
		return nil
	}))

	if err == nil || !strings.Contains(err.Error(), "metadata version mismatch") || !strings.Contains(err.Error(), "refusing untrusted event length") {
		t.Fatalf("source error = %v, want version mismatch with untrusted-length diagnostic", err)
	}
	if readCalls != 1 {
		t.Fatalf("read calls = %d, want exactly one", readCalls)
	}
	if policyCalls != 0 {
		t.Fatalf("policy calls = %d, want zero", policyCalls)
	}
	if len(responses) != 2 {
		t.Fatalf("fatal scan responses = %+v, want only safely identified denials", responses)
	}
	responded := map[int32]uint32{}
	for _, response := range responses {
		if _, exists := responded[response.Fd]; exists {
			t.Fatalf("duplicate response for fd %d: %+v", response.Fd, responses)
		}
		responded[response.Fd] = response.Response
	}
	for _, fd := range []int32{411, 412} {
		if responded[fd] != unix.FAN_DENY {
			t.Fatalf("fatal scan responses = %+v, want fd %d denied", responses, fd)
		}
	}
	if _, exists := responded[413]; exists {
		t.Fatalf("fd 413 in untrusted tail was responded: %+v", responses)
	}
	diagnostics := source.ReaderDiagnostics()
	if diagnostics.OutstandingDescriptors != 0 || diagnostics.PeakOutstandingDescriptors != 2 || !strings.Contains(diagnostics.FatalError, "unparseable") {
		t.Fatalf("fatal scan descriptor diagnostics = %+v", diagnostics)
	}
	source.accountedMu.Lock()
	accounted := len(source.accounted)
	source.accountedMu.Unlock()
	if accounted != 0 {
		t.Fatalf("accounted descriptors = %d, want zero", accounted)
	}
}

func TestUnresolvedPathDefaultsToDenyAndDegraded(t *testing.T) {
	source := newReaderTestSource(8)
	var response unix.FanotifyResponse
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		response = *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0]))
		return len(bytes), nil
	}
	source.handleEvents(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		t.Fatal("unresolved event reached policy handler")
		return nil
	}), fanotifyEventBytes(unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   987654,
		Mask: unix.FAN_OPEN_PERM,
	}))

	diagnostics := source.ReaderDiagnostics()
	if response.Response != unix.FAN_DENY || diagnostics.UnresolvedPathDenyCount != 1 || !diagnostics.Degraded {
		t.Fatalf("response=%+v diagnostics=%+v, want deny and degraded unresolved count", response, diagnostics)
	}
	if diagnostics.OutstandingDescriptors != 0 {
		t.Fatalf("unresolved descriptor remained accounted after response close: %+v", diagnostics)
	}
}

func TestCloseErrorReleasesDescriptorHeadroomAndDegradesSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "close-failure")
	if err := os.WriteFile(path, []byte("close"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	source := newReaderTestSource(1)
	source.activeScopes.Store(&scopeSnapshot{Scopes: []scopeMatch{{Configured: dir, Canonical: dir}}})
	closeCalls := 0
	source.responses.close = func(int) error {
		closeCalls++
		return unix.EIO
	}
	err = source.handleEvents(context.Background(), PendingHandlerFunc(func(_ context.Context, pending PendingEvent) error {
		return pending.Respond(VerdictAllow)
	}), fanotifyEventBytes(unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   int32(file.Fd()),
		Mask: unix.FAN_OPEN_PERM,
	}))
	if err != nil {
		t.Fatalf("valid batch error = %v", err)
	}

	diagnostics := source.ReaderDiagnostics()
	if diagnostics.OutstandingDescriptors != 0 || diagnostics.DescriptorPressure || source.descriptorHeadroom() != 1 {
		t.Fatalf("close-error descriptor accounting = %+v, headroom=%d; want released slot", diagnostics, source.descriptorHeadroom())
	}
	if !diagnostics.Degraded || diagnostics.Fatal || !strings.Contains(diagnostics.LastError, unix.EIO.Error()) {
		t.Fatalf("close-error diagnostics = %+v, want nonfatal degraded EIO", diagnostics)
	}
	if closeCalls != 1 {
		t.Fatalf("close attempts = %d, want exactly 1", closeCalls)
	}
	source.failedMu.Lock()
	failedEvents := len(source.failedEvents)
	source.failedMu.Unlock()
	if failedEvents != 0 {
		t.Fatalf("accepted response retained %d failed owners", failedEvents)
	}
}

func newFanotifyIntegrationSource(t *testing.T, paths []string) *fanotifySource {
	t.Helper()
	source, err := newFanotifySource(paths, nopLogger{})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSYS) {
			t.Skipf("fanotify unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if diagnostics := source.MountDiagnostics(); diagnostics.PartialCoverage {
		_ = source.Close()
		t.Skipf("fanotify mount mark unavailable: %+v", diagnostics)
	}
	return source
}

func newFanotifyBindMount(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := unix.Mount(root, root, "", unix.MS_BIND, ""); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bind mount unavailable: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(root, unix.MNT_DETACH) })
	return root
}

func TestFanotifyFileAndDirectoryOpenReadAndReaddir(t *testing.T) {
	root := newFanotifyBindMount(t)

	path := filepath.Join(root, "file")
	if err := os.WriteFile(path, []byte("contents"), 0o600); err != nil {
		t.Fatal(err)
	}

	source := newFanotifyIntegrationSource(t, []string{root})
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan FileEvent, 8)
	runDone := make(chan error, 1)
	go func() {
		runDone <- source.Run(ctx, PendingHandlerFunc(func(_ context.Context, pending PendingEvent) error {
			events <- *pending.Event()
			return pending.Respond(VerdictAllow)
		}))
	}()

	operationsDone := make(chan error, 1)
	go func() {
		file, err := os.Open(path)
		if err != nil {
			operationsDone <- err
			return
		}
		buffer := make([]byte, 1)
		_, err = file.Read(buffer)
		closeErr := file.Close()
		if err != nil {
			operationsDone <- err
			return
		}
		if closeErr != nil {
			operationsDone <- closeErr
			return
		}

		directory, err := os.Open(root)
		if err != nil {
			operationsDone <- err
			return
		}
		_, err = directory.Readdirnames(1)
		closeErr = directory.Close()
		if err != nil {
			operationsDone <- err
			return
		}
		operationsDone <- closeErr
	}()

	select {
	case err := <-operationsDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		_ = source.Close()
		t.Fatal("file and directory fanotify operations timed out")
	}

	// Reads through an already-open descriptor no longer produce perm events
	// (FAN_ACCESS_PERM was removed); only the opens of the file and directory
	// are intercepted, both as OpOpen.
	want := map[string]int{
		fmt.Sprintf("%s:%s", path, OpOpen): 1,
		fmt.Sprintf("%s:%s", root, OpOpen): 1,
	}
	deadline := time.After(2 * time.Second)
	for len(want) > 0 {
		select {
		case event := <-events:
			key := fmt.Sprintf("%s:%s", event.Path, event.Op)
			if count := want[key]; count <= 1 {
				delete(want, key)
			} else {
				want[key] = count - 1
			}
		case <-deadline:
			t.Fatalf("missing fanotify file/directory events: %v", want)
		}
	}

	cancel()
	_ = source.Close()
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
}

func TestFanotifyEventPathResolutionDoesNotRecurse(t *testing.T) {
	root := newFanotifyBindMount(t)
	path := filepath.Join(root, "path-resolution")
	if err := os.WriteFile(path, []byte("event"), 0o600); err != nil {
		t.Fatal(err)
	}

	source := newFanotifyIntegrationSource(t, []string{root})
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan FileEvent, 4)
	runDone := make(chan error, 1)
	go func() {
		runDone <- source.Run(ctx, PendingHandlerFunc(func(_ context.Context, pending PendingEvent) error {
			events <- *pending.Event()
			return pending.Respond(VerdictAllow)
		}))
	}()

	openDone := make(chan error, 1)
	go func() {
		file, err := os.Open(path)
		if err == nil {
			err = file.Close()
		}
		openDone <- err
	}()

	select {
	case err := <-openDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		_ = source.Close()
		t.Fatal("opening marked file blocked; event path resolution may have recursed")
	}

	select {
	case event := <-events:
		if event.Path != path || event.Op != OpOpen {
			t.Fatalf("initial event = %+v, want path %s open", event, path)
		}
	case <-time.After(time.Second):
		t.Fatal("initial marked-file event was not observed")
	}
	select {
	case event := <-events:
		t.Fatalf("path resolution produced a nested policy event: %+v", event)
	case <-time.After(200 * time.Millisecond):
	}

	cancel()
	_ = source.Close()
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
}
