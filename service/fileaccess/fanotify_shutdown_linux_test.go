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
	select {
	case <-fileAccess.shutdownFinalDone:
	case <-time.After(time.Second):
		t.Fatal("final cleanup did not continue after the bounded report")
	}
	diagnostics = fileAccess.ShutdownDiagnostics()
	if !diagnostics.Source.GroupClosed || !diagnostics.Source.ReaderExited {
		t.Fatalf("final cleanup did not close and join reader: %+v", diagnostics.Source)
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
	source.readerDone = nil
	source.readerExited.Store(true)
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
	groupClosed := make(chan struct{})
	source.responses.close = func(int) error {
		close(groupClosed)
		return nil
	}
	fileAccess := newShutdownTestFileAccess(source, lifecycle)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- fileAccess.Shutdown(ctx) }()
	<-started
	var reported error
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked mark shutdown unexpectedly succeeded")
		}
		reported = err
	case <-time.After(time.Second):
		t.Fatal("blocked mark operation prevented bounded group closure")
	}
	diagnostics := fileAccess.ShutdownDiagnostics()
	if diagnostics.FinalCleanupCompleted || lifecycle.State() != LifecycleClosing || !diagnostics.Source.ScopeCleanupPending || diagnostics.Marks.Final || !diagnostics.Marks.Pending {
		t.Fatalf("bounded report falsely completed cleanup: %+v", diagnostics)
	}
	markWorkerReported := false
	for _, owner := range diagnostics.Unresolved {
		if owner.Location == "mark_removal_worker" && owner.Count == 1 {
			markWorkerReported = true
			break
		}
	}
	if !markWorkerReported {
		t.Fatalf("blocked mark worker missing from diagnostics: %+v", diagnostics.Unresolved)
	}
	shutdownErr, ok := reported.(*ShutdownError)
	if !ok || shutdownErr.Diagnostics.Marks.Final || !shutdownErr.Diagnostics.Marks.Pending {
		t.Fatalf("bounded shutdown result misreported mark finality: %#v", reported)
	}
	if repeated := fileAccess.Shutdown(context.Background()); repeated == nil || repeated.Error() != reported.Error() {
		t.Fatalf("repeated shutdown did not retain the stable bounded result: first=%v repeated=%v", reported, repeated)
	}
	select {
	case <-groupClosed:
	case <-time.After(time.Second):
		t.Fatal("shared finalizer did not close the group while mark cleanup was blocked")
	}
	if lifecycle.State() != LifecycleClosing || !fileAccess.ShutdownDiagnostics().Source.ScopeCleanupPending {
		t.Fatalf("scope cleanup was not reported as pending: %+v", fileAccess.ShutdownDiagnostics())
	}
	close(release)
	select {
	case <-lifecycle.Closed():
	case <-time.After(time.Second):
		t.Fatal("scope cleanup release did not publish Closed")
	}
	diagnostics = fileAccess.ShutdownDiagnostics()
	if !diagnostics.Marks.Final || diagnostics.Marks.Pending || !diagnostics.Source.ScopeCleanupComplete || diagnostics.State != LifecycleClosed {
		t.Fatalf("final mark and scope cleanup state was not published: %+v", diagnostics)
	}
	for _, owner := range diagnostics.Unresolved {
		if owner.Location == "mark_removal_worker" {
			t.Fatalf("completed mark worker remained unresolved: %+v", diagnostics.Unresolved)
		}
	}
}

func TestShutdownResponseWriterOwnershipAndNoWriteAfterClosure(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	writer := newFanotifyResponseWriter(99, nopLogger{}, nil)
	writer.lifecycle = lifecycle
	started := make(chan struct{})
	release := make(chan struct{})
	var writes atomic.Int64
	writer.write = func(_ int, bytes []byte) (int, error) {
		if writes.Add(1) == 1 {
			close(started)
			<-release
		}
		return len(bytes), nil
	}
	writer.close = func(int) error { return nil }
	first := make(chan responseResult, 1)
	go func() { first <- writer.respond(42, VerdictDeny) }()
	<-started
	diagnostics := writer.Diagnostics()
	if diagnostics.CurrentFD != 42 || diagnostics.CurrentVerdict != VerdictDeny {
		t.Fatalf("current response ownership missing: %+v", diagnostics)
	}
	late := make(chan responseResult, 1)
	lateAdmitted := make(chan struct{})
	writer.afterAdmission = func(fd int32) {
		if fd == 43 {
			close(lateAdmitted)
		}
	}
	go func() { late <- writer.respond(43, VerdictDeny) }()
	<-lateAdmitted
	closeDone := make(chan error, 1)
	go func() { closeDone <- writer.SealAndCloseGroup() }()
	select {
	case err := <-closeDone:
		t.Fatalf("group closed while a response was active: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if writer.Diagnostics().Sealed {
		t.Fatal("writer sealed before it acquired exclusive response ownership")
	}
	close(release)
	if response := <-first; !response.accepted {
		t.Fatalf("response was not accepted: %+v", response)
	}
	if response := <-late; !response.accepted {
		t.Fatalf("late Closing response was not accepted: %+v", response)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	second := writer.respond(44, VerdictDeny)
	if second.accepted || second.err == nil {
		t.Fatalf("post-close response unexpectedly accepted: %+v", second)
	}
	if writes.Load() != 2 {
		t.Fatalf("kernel writes = %d, want two before closure", writes.Load())
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
	metadata := &unix.FanotifyEventMetadata{
		Vers: unix.FANOTIFY_METADATA_VERSION,
		Fd:   int32(file.Fd()),
		Mask: unix.FAN_OPEN_PERM,
	}
	if !source.accountEventFD(metadata.Fd) {
		t.Fatal("accountEventFD rejected the test descriptor")
	}
	source.handleEvent(context.Background(), PendingHandlerFunc(func(context.Context, PendingEvent) error {
		return nil
	}), metadata)
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

func TestShutdownReportDeadlineKeepsWriterUsableUntilFinalClose(t *testing.T) {
	lifecycle := NewPipelineLifecycle()
	source := newReaderTestSource(4)
	source.fd = 99
	source.SetLifecycle(lifecycle)
	source.readerDone = make(chan struct{})
	source.readerIdle = make(chan struct{}, 1)
	source.reconcileDone = nil
	source.marks = map[int]mountedMark{
		1: {mount: mountInfo{ID: 1, MountPoint: "/"}, mask: unix.FAN_OPEN_PERM},
	}
	source.mark = func(uint, uint64, string) error { return unix.EIO }

	file, err := os.CreateTemp(t.TempDir(), "late-after-report")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	lateFD := int32(file.Fd())
	activeStarted := make(chan struct{})
	activeRelease := make(chan struct{})
	lateAdmitted := make(chan struct{})
	lateVerdict := make(chan Verdict, 1)
	var writes atomic.Int64
	source.responses.afterAdmission = func(fd int32) {
		if fd == lateFD {
			close(lateAdmitted)
		}
	}
	source.responses.write = func(_ int, bytes []byte) (int, error) {
		if writes.Add(1) == 1 {
			close(activeStarted)
			<-activeRelease
		} else {
			lateVerdict <- responseVerdict(bytes)
		}
		return len(bytes), nil
	}
	groupClosed := make(chan struct{})
	source.responses.close = func(fd int) error {
		if fd == source.fd {
			close(groupClosed)
		}
		return nil
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
		Fd:   lateFD,
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
			t.Error("late Closing event reached normal policy")
			return nil
		}))
	}()

	activeResult := make(chan responseResult, 1)
	go func() { activeResult <- source.responses.respond(77, VerdictDeny) }()
	<-activeStarted
	fileAccess := newShutdownTestFileAccess(source, lifecycle)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	reportErr := fileAccess.Shutdown(ctx)
	if reportErr == nil {
		t.Fatal("active response unexpectedly completed within reporting deadline")
	}
	if diagnostics := fileAccess.ShutdownDiagnostics(); lifecycle.State() != LifecycleClosing || diagnostics.Source.Response.Sealed || diagnostics.Source.GroupClosed {
		t.Fatalf("writer/group finalized at bounded report: %+v", diagnostics)
	}

	close(emit)
	<-lateAdmitted
	close(activeRelease)
	if result := <-activeResult; !result.accepted {
		t.Fatalf("active response failed: %+v", result)
	}
	if verdict := <-lateVerdict; verdict != VerdictDeny {
		t.Fatalf("late Closing verdict = %v, want deny", verdict)
	}
	select {
	case <-groupClosed:
	case <-time.After(time.Second):
		t.Fatal("finalizer did not atomically close the group")
	}
	select {
	case <-lifecycle.Closed():
	case <-time.After(time.Second):
		t.Fatal("reader/scope cleanup did not publish Closed")
	}
	final := fileAccess.ShutdownDiagnostics()
	if !final.FinalCleanupCompleted || !final.Source.ReaderExited || !final.Source.ScopeCleanupComplete || final.Decision.Outstanding != 0 {
		t.Fatalf("final cleanup diagnostics incomplete: %+v", final)
	}
	if repeated := fileAccess.Shutdown(context.Background()); repeated != reportErr {
		t.Fatalf("repeated Shutdown result = %v, want stable %v", repeated, reportErr)
	}
	if writes.Load() != 2 {
		t.Fatalf("response writes = %d, want active and late deny", writes.Load())
	}
}

func TestShutdownScopeCleanupClosesEveryReferenceExactlyOnce(t *testing.T) {
	active, err := activateScope(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	retired, err := activateScope(t.TempDir())
	if err != nil {
		active.close()
		t.Fatal(err)
	}
	activeFD := active.refFD
	retiredFD := retired.refFD
	source := newReaderTestSource(1)
	source.scopes = map[string]*policyScope{active.Configured: active}
	source.retiredScopes = []*policyScope{retired}
	if err := source.CleanupScopes(); err != nil {
		t.Fatal(err)
	}
	for _, fd := range []int{activeFD, retiredFD} {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("scope fd %d remained open: %v", fd, err)
		}
	}

	probe, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if probe != activeFD {
		if err := unix.Dup3(probe, activeFD, unix.O_CLOEXEC); err != nil {
			unix.Close(probe)
			t.Fatal(err)
		}
		unix.Close(probe)
		probe = activeFD
	}
	defer unix.Close(probe)
	if err := source.CleanupScopes(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(probe), unix.F_GETFD, 0); err != nil {
		t.Fatalf("second cleanup closed a reused fd: %v", err)
	}
	if !source.ScopeCleanupComplete() {
		t.Fatal("scope cleanup completion was not published")
	}
}
