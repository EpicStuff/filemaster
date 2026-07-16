package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

var ErrShortFanotifyResponse = errors.New("short fanotify response write")

type fanotifyResponseWriter struct {
	groupFD        int
	log            logger
	write          func(int, []byte) (int, error)
	close          func(int) error
	afterClose     func(int32, error)
	afterAdmission func(int32)
	lifecycle      *PipelineLifecycle

	admissionMu    sync.RWMutex
	writeMu        sync.Mutex
	sealed         atomic.Bool
	closed         atomic.Bool
	closeErr       error
	currentFD      atomic.Int64
	currentVerdict atomic.Uint32
	changed        chan struct{}

	fatalMu  sync.Mutex
	fatal    error
	draining atomic.Bool
}

func newFanotifyResponseWriter(groupFD int, log logger, afterClose func(int32, error)) *fanotifyResponseWriter {
	writer := &fanotifyResponseWriter{
		groupFD:    groupFD,
		log:        log,
		write:      unix.Write,
		close:      unix.Close,
		afterClose: afterClose,
		changed:    make(chan struct{}, 1),
	}
	writer.currentFD.Store(-1)
	return writer
}

func (writer *fanotifyResponseWriter) respond(eventFD int32, verdict Verdict) responseResult {
	response := unix.FanotifyResponse{Fd: eventFD}
	if verdict == VerdictAllow {
		response.Response = unix.FAN_ALLOW
	} else {
		response.Response = unix.FAN_DENY
	}
	responseBytes := unsafe.Slice((*byte)(unsafe.Pointer(&response)), unsafe.Sizeof(response))

	writer.admissionMu.RLock()
	defer writer.admissionMu.RUnlock()
	if writer.afterAdmission != nil {
		writer.afterAdmission(eventFD)
	}
	writer.writeMu.Lock()
	defer writer.writeMu.Unlock()
	writer.currentFD.Store(int64(eventFD))
	writer.currentVerdict.Store(uint32(verdict))
	writer.signalChanged()
	defer func() {
		writer.currentFD.Store(-1)
		writer.currentVerdict.Store(0)
		writer.signalChanged()
	}()
	if writer.sealed.Load() {
		err := fmt.Errorf("fanotify response writer is sealed")
		writer.enterFatal(err)
		return responseResult{err: err}
	}
	for {
		written, err := writer.write(writer.groupFD, responseBytes)
		if errors.Is(err, unix.EINTR) && written == 0 {
			continue
		}
		if err != nil {
			err = fmt.Errorf("write fanotify response: %w", err)
			writer.enterFatal(err)
			return responseResult{err: err}
		}
		if written != len(responseBytes) {
			err = fmt.Errorf("%w: wrote %d of %d bytes", ErrShortFanotifyResponse, written, len(responseBytes))
			writer.enterFatal(err)
			return responseResult{err: err}
		}
		break
	}

	closeErr := writer.close(int(eventFD))
	if writer.afterClose != nil {
		writer.afterClose(eventFD, closeErr)
	}
	if closeErr != nil {
		return responseResult{
			accepted: true,
			err:      fmt.Errorf("close responded fanotify event fd %d: %w", eventFD, closeErr),
		}
	}
	return responseResult{accepted: true}
}

func (writer *fanotifyResponseWriter) enterFatal(err error) {
	writer.fatalMu.Lock()
	first := writer.fatal == nil
	if first {
		writer.fatal = err
		writer.draining.Store(true)
	}
	writer.fatalMu.Unlock()
	if first {
		writer.log.Error("fanotify enforcement failure; entering controlled draining", "err", err)
		if writer.lifecycle != nil {
			writer.lifecycle.BeginClosing(context.Background())
		}
	}
}

func (writer *fanotifyResponseWriter) fatalError() error {
	writer.fatalMu.Lock()
	defer writer.fatalMu.Unlock()
	return writer.fatal
}

func (writer *fanotifyResponseWriter) signalChanged() {
	select {
	case writer.changed <- struct{}{}:
	default:
	}
}

func (writer *fanotifyResponseWriter) Diagnostics() ResponseWriterDiagnostics {
	diagnostics := ResponseWriterDiagnostics{
		Sealed:         writer.sealed.Load(),
		Closed:         writer.closed.Load(),
		CurrentFD:      int32(writer.currentFD.Load()),
		CurrentVerdict: Verdict(writer.currentVerdict.Load()),
	}
	if err := writer.fatalError(); err != nil {
		diagnostics.FatalError = err.Error()
	}
	return diagnostics
}

func (writer *fanotifyResponseWriter) WaitCurrentResponse(ctx context.Context) error {
	for writer.currentFD.Load() >= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-writer.changed:
		}
	}
	return nil
}

// SealAndCloseGroup obtains exclusive response ownership, then atomically
// prevents future writes and closes the fanotify group. Until this lock is
// acquired, Closing events may continue to send deny responses normally.
func (writer *fanotifyResponseWriter) SealAndCloseGroup() error {
	writer.admissionMu.Lock()
	defer writer.admissionMu.Unlock()
	writer.writeMu.Lock()
	defer writer.writeMu.Unlock()
	if writer.closed.Load() {
		return writer.closeErr
	}
	writer.sealed.Store(true)
	writer.signalChanged()
	// Linux fanotify(7) documents that closing the group implicitly allows
	// outstanding permission events. Callers must therefore drain or explicitly
	// report every owner before invoking this final close.
	writer.closeErr = writer.close(writer.groupFD)
	writer.closed.Store(true)
	writer.signalChanged()
	return writer.closeErr
}
