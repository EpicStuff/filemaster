//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/safing/portmaster/service/profile"
	"unsafe"

	"golang.org/x/sys/unix"
)

func responseVerdict(bytes []byte) Verdict {
	response := *(*unix.FanotifyResponse)(unsafe.Pointer(&bytes[0]))
	if response.Response == unix.FAN_ALLOW {
		return VerdictAllow
	}
	return VerdictDeny
}

func TestShutdownReaderDeniesPermissionEventAfterClosing(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	source := newReaderTestSource(4)
	source.SetLifecycle(lifecycle)
	responses := make(chan Verdict, 1)
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		responses <- responseVerdict(bytes)
		return len(bytes), nil
	}

	file, err := os.CreateTemp(t.TempDir(), "closing-event")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	lifecycle.BeginClosing(context.Background())
	source.handleEvent(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		t.Fatal("closing event reached normal policy")
		return nil
	}), &unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   int32(file.Fd()),
		Mask: unix.FAN_OPEN_PERM,
	})
	if verdict := <-responses; verdict != VerdictDeny {
		t.Fatalf("closing reader verdict = %v, want deny", verdict)
	}
	if diagnostics := source.ReaderDiagnostics(); diagnostics.OutstandingDescriptors != 0 {
		t.Fatalf("descriptor accounting leaked: %+v", diagnostics)
	}
}

func TestShutdownFailedMarkRemovalKeepsReaderServicingEvents(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	source := newReaderTestSource(8)
	source.fd = 99
	source.SetLifecycle(lifecycle)
	source.readerDone = make(chan struct{})
	source.readerIdle = make(chan struct{}, 1)
	source.reconcileDone = nil
	source.marks = map[int]mountedMark{
		1: {mount: mountInfo{ID: 1, MountPoint: "/"}, mask: unix.FAN_OPEN_PERM},
	}
	markAttempt := make(chan struct{}, 1)
	source.mark = func(uint, uint64, string) error {
		select {
		case markAttempt <- struct{}{}:
		default:
		}
		return unix.EIO
	}

	file, err := os.CreateTemp(t.TempDir(), "late-event")
	if err != nil {
		t.Fatal(err)
	}
	closedEventFD := atomic.Bool{}
	source.responses.close = func(fd int) error {
		if fd == int(file.Fd()) {
			closedEventFD.Store(true)
		}
		return nil
	}
	responses := make(chan Verdict, 1)
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		responses <- responseVerdict(bytes)
		return len(bytes), nil
	}

	emit := make(chan struct{})
	var emitted atomic.Bool
	source.poll = func([]unix.PollFd, int) (int, error) {
		if source.responses.closed.Load() {
			return 1, nil
		}
		<-emit
		return 1, nil
	}
	eventBytes := fanotifyEventBytes(unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   int32(file.Fd()),
		Mask: unix.FAN_OPEN_PERM,
	})
	source.read = func(_ int, buffer []byte) (int, error) {
		if source.responses.closed.Load() {
			return 0, unix.EBADF
		}
		if emitted.CompareAndSwap(false, true) {
			return copy(buffer, eventBytes), nil
		}
		return 0, unix.EAGAIN
	}
	go func() {
		_ = source.Run(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
			t.Error("event reached policy during Closing")
			return nil
		}))
	}()

	fileAccess := newShutdownTestFileAccess(source, lifecycle)
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- fileAccess.Shutdown(ctx) }()
	<-markAttempt
	if source.readerExited.Load() {
		t.Fatal("reader exited while failed marks could generate events")
	}
	close(emit)
	if verdict := <-responses; verdict != VerdictDeny {
		t.Fatalf("late event verdict = %v, want deny", verdict)
	}
	if !closedEventFD.Load() {
		t.Fatal("late event descriptor was not closed")
	}
	if err := <-result; err == nil {
		t.Fatal("partial mark removal shutdown unexpectedly succeeded")
	}
	diagnostics := fileAccess.ShutdownDiagnostics()
	if diagnostics.Marks.Complete || len(diagnostics.Marks.Failures) != 1 {
		t.Fatalf("mark removal failure missing: %+v", diagnostics.Marks)
	}
	if !diagnostics.Source.GroupClosed || !diagnostics.Source.ReaderExited {
		t.Fatalf("deadline cleanup did not close and join reader: %+v", diagnostics.Source)
	}
}

func TestShutdownSuccessfulMarkRemovalDrainsThenClosesReader(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	source := newReaderTestSource(4)
	source.fd = 99
	source.SetLifecycle(lifecycle)
	source.readerDone = make(chan struct{})
	source.readerIdle = make(chan struct{}, 1)
	source.marks = map[int]mountedMark{
		2: {mount: mountInfo{ID: 2, MountPoint: "/tmp"}, mask: unix.FAN_OPEN_PERM},
	}
	source.mark = func(uint, uint64, string) error { return nil }
	source.poll = func([]unix.PollFd, int) (int, error) {
		if source.responses.closed.Load() {
			return 1, nil
		}
		return 0, nil
	}
	source.read = func(int, []byte) (int, error) { return 0, unix.EBADF }
	go func() {
		_ = source.Run(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
			return errors.New("unexpected policy event")
		}))
	}()

	fileAccess := newShutdownTestFileAccess(source, lifecycle)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := fileAccess.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown failed: %v; diagnostics=%+v", err, fileAccess.ShutdownDiagnostics())
	}
	diagnostics := fileAccess.ShutdownDiagnostics()
	if !diagnostics.Marks.Complete || !diagnostics.Source.GroupClosed || !diagnostics.Source.ReaderExited {
		t.Fatalf("successful closure incomplete: %+v", diagnostics)
	}
	if diagnostics.Source.OutstandingDescriptors != 0 || len(diagnostics.Unresolved) != 0 {
		t.Fatalf("successful shutdown leaked ownership: %+v", diagnostics)
	}
}

func TestShutdownDeadlineWithBlockedMarkOperationStillClosesGroup(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	source := newReaderTestSource(2)
	source.fd = 99
	source.SetLifecycle(lifecycle)
	source.marks = map[int]mountedMark{
		3: {mount: mountInfo{ID: 3, MountPoint: "/tmp"}, mask: unix.FAN_OPEN_PERM},
	}
	started := make(chan struct{})
	release := make(chan struct{})
	source.mark = func(uint, uint64, string) error {
		close(started)
		<-release
		return nil
	}
	fileAccess := newShutdownTestFileAccess(source, lifecycle)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- fileAccess.Shutdown(ctx) }()
	<-started
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked mark shutdown unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked mark operation prevented bounded group closure")
	}
	if !fileAccess.ShutdownDiagnostics().Source.GroupClosed {
		t.Fatalf("group was not closed at deadline: %+v", fileAccess.ShutdownDiagnostics())
	}
	close(release)
}

func TestShutdownResponseWriterOwnershipAndNoWriteAfterClosure(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	writer := newFanotifyResponseWriter(99, nopLogger{}, nil)
	writer.lifecycle = lifecycle
	started := make(chan struct{})
	release := make(chan struct{})
	var writes atomic.Int64
	writer.write = func(_ int, bytes []byte) (int, error) {
		writes.Add(1)
		close(started)
		<-release
		return len(bytes), nil
	}
	writer.close = func(int) error { return nil }
	result := make(chan responseResult, 1)
	go func() { result <- writer.respond(42, VerdictDeny) }()
	<-started
	diagnostics := writer.Diagnostics()
	if diagnostics.CurrentFD != 42 || diagnostics.CurrentVerdict != VerdictDeny {
		t.Fatalf("current response ownership missing: %+v", diagnostics)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := writer.SealAndWait(ctx); err == nil {
		t.Fatal("blocked response unexpectedly drained")
	}
	cancel()
	close(release)
	if response := <-result; !response.accepted {
		t.Fatalf("response was not accepted: %+v", response)
	}
	if err := writer.SealAndWait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := writer.CloseGroup(); err != nil {
		t.Fatal(err)
	}
	second := writer.respond(43, VerdictDeny)
	if second.accepted || second.err == nil {
		t.Fatalf("post-close response unexpectedly accepted: %+v", second)
	}
	if writes.Load() != 1 {
		t.Fatalf("kernel writes = %d, want one before closure", writes.Load())
	}
}

func TestShutdownResponseFailureRemainsExplicitlyOwned(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	source := newReaderTestSource(2)
	source.SetLifecycle(lifecycle)
	source.responses.write = func(int, []byte) (int, error) { return 0, unix.EIO }
	file, err := os.CreateTemp(t.TempDir(), "failed-response")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	source.handleEvent(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		return nil
	}), &unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   int32(file.Fd()),
		Mask: unix.FAN_OPEN_PERM,
	})
	diagnostics := source.ReaderDiagnostics()
	if diagnostics.OutstandingDescriptors != 1 || len(diagnostics.FailedResponseDescriptors) != 1 {
		t.Fatalf("failed response owner not retained: %+v", diagnostics)
	}
	if source.ResponseDiagnostics().FatalError == "" {
		t.Fatal("response fatal state not visible")
	}
}

func TestShutdownMarkRemovalDoesNotPublishBlockedReconciliation(t *testing.T) {
	directory := t.TempDir()
	scope, err := activateScope(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.close()
	source := newReconciliationTestSource([]mountInfo{{ID: 1, MountPoint: "/"}}, nil)
	source.scopes[directory] = scope
	lifecycle := NewPipelineLifecycle()
	source.SetLifecycle(lifecycle)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int64
	source.mark = func(flags uint, _ uint64, _ string) error {
		if flags&unix.FAN_MARK_ADD != 0 {
			if calls.Add(1) == 1 {
				close(entered)
				<-release
			}
		}
		return nil
	}
	finished := make(chan struct{})
	go func() {
		source.reconcile()
		close(finished)
	}()
	<-entered
	closed := make(chan struct{})
	go func() {
		lifecycle.BeginClosing(context.Background())
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Closing transition waited for blocked mark operation")
	}
	close(release)
	<-finished
	if lifecycle.State() != LifecycleClosing {
		t.Fatalf("lifecycle state = %s", lifecycle.State())
	}
	if result := source.RemoveAllMarks(); !result.Complete {
		t.Fatalf("tracked in-flight mark could not be removed: %+v", result)
	}
}

func TestShutdownPromptReplyRaceCompletesEveryEntryOnce(t *testing.T) {
	for range 20 {
		lifecycle := NewPipelineLifecycle()
		prompter := &shutdownPrompt{started: make(chan struct{}), action: make(chan string, 1)}
		var releases atomic.Int64
		coordinator := newPromptCoordinator(prompter, time.Second, func(string) (func(), bool) {
			return func() { releases.Add(1) }, true
		}, func(_ context.Context, pending PendingEvent, verdict Verdict) bool {
			return pending.Respond(verdict) == nil
		}, lifecycle)
		responses := make([]<-chan Verdict, 0, 2)
		for range 2 {
			pending, response := coordinatorPending(FileEvent{Path: "/tmp/race"})
			responses = append(responses, response)
			coordinator.Admit(context.Background(), pending, nil, coordinatorSnapshot("race", 1, profile.DefaultActionAsk))
		}
		<-prompter.started
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			prompter.action <- ActionAllow
		}()
		go func() {
			defer wait.Done()
			<-start
			lifecycle.BeginClosing(context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = coordinator.Drain(ctx)
			cancel()
		}()
		close(start)
		wait.Wait()
		for _, response := range responses {
			select {
			case verdict := <-response:
				if verdict != VerdictAllow && verdict != VerdictDeny {
					t.Fatalf("invalid race verdict: %v", verdict)
				}
			case <-time.After(time.Second):
				t.Fatal("grouped event was not completed")
			}
		}
		if releases.Load() != 2 {
			t.Fatalf("accounting releases = %d, want two", releases.Load())
		}
	}
}
