//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"testing"
)

func TestFakeSourceTracksUnacceptedResponseOwnership(t *testing.T) {
	source := newFakeSource([]FileEvent{{Path: "/tmp/phase8", Op: OpOpen}})
	source.response = func(FileEvent, Verdict) responseResult {
		return responseResult{err: errors.New("injected response failure")}
	}
	err := source.Run(context.Background(), PendingHandlerFunc(func(_ context.Context, pending PendingEvent) error {
		return pending.Respond(VerdictDeny)
	}))
	if err == nil {
		t.Fatal("expected unaccepted fake response to reach the source")
	}
	diagnostics := source.ReaderDiagnostics()
	if diagnostics.OutstandingDescriptors != 1 || len(diagnostics.FailedResponseDescriptors) != 1 {
		t.Fatalf("fake source hid retained ownership: %+v", diagnostics)
	}
}

func TestFakeSourceReleasesAcceptedResponseAccounting(t *testing.T) {
	source := newFakeSource([]FileEvent{{Path: "/tmp/phase8", Op: OpOpen}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- source.Run(ctx, PendingHandlerFunc(func(_ context.Context, pending PendingEvent) error {
			return pending.Respond(VerdictAllow)
		}))
	}()
	select {
	case <-done:
		t.Fatal("fake source returned before its reader lifetime ended")
	default:
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("fake source run failed: %v", err)
	}
	diagnostics := source.ReaderDiagnostics()
	if diagnostics.OutstandingDescriptors != 0 || len(diagnostics.FailedResponseDescriptors) != 0 {
		t.Fatalf("accepted fake response leaked accounting: %+v", diagnostics)
	}
}

func TestFakeSourceReportsReaderLifecycleAndGroupClosure(t *testing.T) {
	source := newFakeSource([]FileEvent{{Path: "/tmp/phase8", Op: OpOpen}})
	lifecycle := NewPipelineLifecycle()
	source.SetLifecycle(lifecycle)
	handled := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- source.Run(context.Background(), PendingHandlerFunc(func(_ context.Context, pending PendingEvent) error {
			err := pending.Respond(VerdictAllow)
			close(handled)
			return err
		}))
	}()

	<-handled
	if diagnostics := source.ReaderDiagnostics(); !diagnostics.Running || diagnostics.Exited || diagnostics.OutstandingDescriptors != 0 {
		t.Fatalf("fake source did not report its active, drained reader: %+v", diagnostics)
	}
	lifecycle.BeginClosing(context.Background())
	if lifecycle.State() != LifecycleClosing {
		t.Fatalf("lifecycle state = %s, want closing", lifecycle.State())
	}
	if diagnostics := source.ReaderDiagnostics(); !diagnostics.Running || diagnostics.Exited {
		t.Fatalf("fake reader did not remain visible while shutdown was closing: %+v", diagnostics)
	}
	if err := source.CloseGroup(); err != nil {
		t.Fatalf("close fake group: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("fake source run failed: %v", err)
	}
	if err := source.WaitReaderExit(context.Background()); err != nil {
		t.Fatalf("wait for fake reader exit: %v", err)
	}
	if diagnostics := source.ReaderDiagnostics(); diagnostics.Running || !diagnostics.Exited || diagnostics.OutstandingDescriptors != 0 {
		t.Fatalf("fake source did not report its exited, drained reader: %+v", diagnostics)
	}
	if response := source.ResponseDiagnostics(); !response.Closed {
		t.Fatalf("fake source did not report group closure: %+v", response)
	}
	lifecycle.PublishClosed(nil)
}
