//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	source.responses = newFanotifyResponseWriter(99, nopLogger{}, source.releaseEventFD)
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		return len(bytes), nil
	}
	source.responses.close = func(int) error { return nil }
	return source
}

func fanotifyEventBytes(events ...unix.FanotifyEventMetadata) []byte {
	metadataSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	buf := make([]byte, 0, len(events)*metadataSize)
	for _, event := range events {
		event.Event_len = uint32(metadataSize)
		event.Metadata_len = uint16(metadataSize)
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

func TestReaderDoesNotReadWithoutDescriptorHeadroom(t *testing.T) {
	source := newReaderTestSource(1)
	source.accountEventFD(101)
	source.poll = func([]unix.PollFd, int) (int, error) { return 1, nil }
	readCalled := make(chan int, 1)
	ctx, cancel := context.WithCancel(context.Background())
	source.read = func(_ int, bytes []byte) (int, error) {
		readCalled <- len(bytes)
		cancel()
		return 0, unix.EAGAIN
	}
	done := make(chan error, 1)
	go func() {
		done <- source.Run(ctx, PendingHandlerFunc(func(context.Context, PendingEvent) error { return nil }))
	}()

	select {
	case size := <-readCalled:
		t.Fatalf("read called with exhausted headroom using %d-byte buffer", size)
	case <-time.After(50 * time.Millisecond):
	}

	source.releaseEventFD(101)
	select {
	case size := <-readCalled:
		want := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
		if size != want {
			t.Fatalf("read buffer after one descriptor released = %d, want %d", size, want)
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not resume after descriptor headroom returned")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReaderHandlesEMFILEAsDegradedCapacityFailure(t *testing.T) {
	source := newReaderTestSource(8)
	source.poll = func([]unix.PollFd, int) (int, error) { return 1, nil }
	source.emfileRetry = time.Hour
	readCalled := make(chan struct{}, 1)
	source.read = func(int, []byte) (int, error) {
		readCalled <- struct{}{}
		return 0, unix.EMFILE
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- source.Run(ctx, PendingHandlerFunc(func(context.Context, PendingEvent) error { return nil }))
	}()

	select {
	case <-readCalled:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("reader did not attempt injected read")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	diagnostics := source.ReaderDiagnostics()
	if diagnostics.EMFILECount != 1 || !diagnostics.DescriptorPressure || !diagnostics.Degraded {
		t.Fatalf("EMFILE diagnostics = %+v", diagnostics)
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

func TestDescriptorAccountingRetainedWhenEventCloseFails(t *testing.T) {
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

	source := newReaderTestSource(8)
	source.activeScopes.Store(&scopeSnapshot{Scopes: []scopeMatch{{Configured: dir, Canonical: dir}}})
	source.responses.close = func(int) error { return unix.EIO }
	source.handleEvents(context.Background(), PendingHandlerFunc(func(_ context.Context, pending PendingEvent) error {
		return pending.Respond(VerdictAllow)
	}), fanotifyEventBytes(unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   int32(file.Fd()),
		Mask: unix.FAN_OPEN_PERM,
	}))

	if diagnostics := source.ReaderDiagnostics(); diagnostics.OutstandingDescriptors != 1 {
		t.Fatalf("close-failed descriptor accounting = %+v, want outstanding 1", diagnostics)
	}
	source.releaseEventFD(int32(file.Fd()))
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
	previous := cfgOptionInterceptReads
	cfgOptionInterceptReads = func() bool { return true }
	t.Cleanup(func() { cfgOptionInterceptReads = previous })

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

	want := map[string]int{
		fmt.Sprintf("%s:%s", path, OpOpen): 1,
		fmt.Sprintf("%s:%s", path, OpRead): 1,
		fmt.Sprintf("%s:%s", root, OpOpen): 1,
		fmt.Sprintf("%s:%s", root, OpRead): 1,
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
	previous := cfgOptionInterceptReads
	cfgOptionInterceptReads = func() bool { return false }
	t.Cleanup(func() { cfgOptionInterceptReads = previous })

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
