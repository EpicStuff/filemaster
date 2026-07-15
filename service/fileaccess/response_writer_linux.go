package fileaccess

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

var ErrShortFanotifyResponse = errors.New("short fanotify response write")

type fanotifyResponseWriter struct {
	groupFD    int
	log        logger
	write      func(int, []byte) (int, error)
	close      func(int) error
	afterClose func(int32, error)

	writeMu  sync.Mutex
	fatalMu  sync.Mutex
	fatal    error
	draining atomic.Bool
}

func newFanotifyResponseWriter(groupFD int, log logger, afterClose func(int32, error)) *fanotifyResponseWriter {
	return &fanotifyResponseWriter{
		groupFD:    groupFD,
		log:        log,
		write:      unix.Write,
		close:      unix.Close,
		afterClose: afterClose,
	}
}

func (writer *fanotifyResponseWriter) respond(eventFD int32, verdict Verdict) responseResult {
	response := unix.FanotifyResponse{Fd: eventFD}
	if verdict == VerdictAllow {
		response.Response = unix.FAN_ALLOW
	} else {
		response.Response = unix.FAN_DENY
	}
	responseBytes := unsafe.Slice((*byte)(unsafe.Pointer(&response)), unsafe.Sizeof(response))

	writer.writeMu.Lock()
	defer writer.writeMu.Unlock()
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
	}
}

func (writer *fanotifyResponseWriter) fatalError() error {
	writer.fatalMu.Lock()
	defer writer.fatalMu.Unlock()
	return writer.fatal
}
