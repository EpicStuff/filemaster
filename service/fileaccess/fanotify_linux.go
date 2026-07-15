//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fanotifySource is a Linux fanotify-backed Source. Mount marks collect
// kernel events while the immutable scope snapshot determines policy scope.
type fanotifySource struct {
	log logger
	fd  int

	marksMu       sync.Mutex
	scopes        map[string]*policyScope
	retiredScopes []*policyScope
	marks         map[int]mountedMark
	markMask      uint64
	pending       bool

	activeScopes atomic.Pointer[scopeSnapshot]
	diagnostics  MountDiagnostics

	mountInfo func() ([]mountInfo, error)
	mark      func(flags uint, mask uint64, path string) error

	read            func(int, []byte) (int, error)
	poll            func([]unix.PollFd, int) (int, error)
	emfileRetry     time.Duration
	descriptorLimit int64

	accountedMu        sync.Mutex
	accounted          map[int32]struct{}
	outstanding        atomic.Int64
	peakOutstanding    atomic.Int64
	descriptorReleased chan struct{}

	queueOverflows       atomic.Uint64
	readEMFILEs          atomic.Uint64
	unresolvedPathDenies atomic.Uint64
	descriptorPressure   atomic.Bool
	readerDegraded       atomic.Bool
	readerFatal          atomic.Bool
	readerDiagMu         sync.Mutex
	readerLastError      string
	readerFatalError     string

	responses    *fanotifyResponseWriter
	failedMu     sync.Mutex
	failedEvents map[int32]PendingEvent
}

const (
	fanotifyDescriptorReserve = uint64(256)
	maxFanotifyReadBuffer     = 4096
	defaultEMFILERetry        = 250 * time.Millisecond
	fanotifyPermissionEvents  = uint64(unix.FAN_OPEN_PERM | unix.FAN_ACCESS_PERM | unix.FAN_OPEN_EXEC_PERM)
)

// ReaderDiagnostics is a race-safe snapshot of fanotify reader capacity and
// enforcement failures.
type ReaderDiagnostics struct {
	DescriptorLimit            int64
	OutstandingDescriptors     int64
	PeakOutstandingDescriptors int64
	DescriptorPressure         bool
	EMFILECount                uint64
	QueueOverflowCount         uint64
	UnresolvedPathDenyCount    uint64
	Degraded                   bool
	Fatal                      bool
	LastError                  string
	FatalError                 string
}

func calculateDescriptorLimit(softLimit, reserve uint64) int64 {
	if softLimit <= reserve {
		return 0
	}
	available := softLimit - reserve
	if available > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(available)
}

func readBufferCapacity(headroom int64) int {
	if headroom <= 0 {
		return 0
	}
	metadataSize := int64(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	maxEvents := int64(maxFanotifyReadBuffer) / metadataSize
	if headroom > maxEvents {
		headroom = maxEvents
	}
	return int(headroom * metadataSize)
}

func currentDescriptorLimit() (int64, error) {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return 0, fmt.Errorf("get RLIMIT_NOFILE: %w", err)
	}
	return calculateDescriptorLimit(limit.Cur, fanotifyDescriptorReserve), nil
}

func (s *fanotifySource) descriptorHeadroom() int64 {
	headroom := s.descriptorLimit - s.outstanding.Load()
	if headroom <= 0 {
		s.descriptorPressure.Store(true)
		return 0
	}
	return headroom
}

func (s *fanotifySource) accountEventFD(fd int32) bool {
	s.accountedMu.Lock()
	if s.accounted == nil {
		s.accounted = make(map[int32]struct{})
	}
	if _, exists := s.accounted[fd]; exists {
		s.accountedMu.Unlock()
		return false
	}
	s.accounted[fd] = struct{}{}
	s.accountedMu.Unlock()

	current := s.outstanding.Add(1)
	for {
		peak := s.peakOutstanding.Load()
		if current <= peak || s.peakOutstanding.CompareAndSwap(peak, current) {
			break
		}
	}
	if current >= s.descriptorLimit {
		s.descriptorPressure.Store(true)
	}
	return true
}

func (s *fanotifySource) releaseEventFD(fd int32) {
	s.accountedMu.Lock()
	if _, exists := s.accounted[fd]; !exists {
		s.accountedMu.Unlock()
		return
	}
	delete(s.accounted, fd)
	s.accountedMu.Unlock()

	current := s.outstanding.Add(-1)
	if current < s.descriptorLimit {
		s.descriptorPressure.Store(false)
	}
	select {
	case s.descriptorReleased <- struct{}{}:
	default:
	}
}

func (s *fanotifySource) finishEventFDClose(fd int32, closeErr error) {
	// On Linux the descriptor number is released when close is attempted,
	// even if later close processing reports an error. Retrying could close an
	// unrelated descriptor that reused the same number.
	s.releaseEventFD(fd)
	if closeErr == nil {
		return
	}
	err := fmt.Errorf("close fanotify event fd %d after close attempt: %w", fd, closeErr)
	s.setReaderDegraded(err)
	s.log.Error("fanotify event descriptor close failed after release", "fd", fd, "err", closeErr)
}

func (s *fanotifySource) closeAccountedEventFD(fd int32) error {
	closeFD := unix.Close
	if s.responses != nil && s.responses.close != nil {
		closeFD = s.responses.close
	}
	closeErr := closeFD(int(fd))
	s.finishEventFDClose(fd, closeErr)
	if closeErr != nil {
		return fmt.Errorf("close fanotify event fd %d: %w", fd, closeErr)
	}
	return nil
}

func (s *fanotifySource) enterReaderFatal(err error) {
	first := s.readerFatal.CompareAndSwap(false, true)
	s.readerDegraded.Store(true)
	s.readerDiagMu.Lock()
	s.readerLastError = err.Error()
	if first {
		s.readerFatalError = err.Error()
	}
	s.readerDiagMu.Unlock()
	if s.responses != nil {
		s.responses.enterFatal(err)
	}
	if first {
		s.log.Error("fatal fanotify reader metadata failure; stopping source", "err", err)
	}
}

func (s *fanotifySource) resolveAccountedEventForFatal(meta *unix.FanotifyEventMetadata) error {
	if uint64(meta.Mask)&fanotifyPermissionEvents == 0 {
		return s.closeAccountedEventFD(meta.Fd)
	}
	if s.responses == nil {
		return errors.New("fanotify response writer unavailable while resolving fatal batch")
	}

	event := FileEvent{
		PID: meta.Pid,
		Op:  opFromMask(uint64(meta.Mask)),
	}
	pending := newPendingEvent(&event, func(verdict Verdict) responseResult {
		return s.responses.respond(meta.Fd, verdict)
	})
	responseErr := pending.Respond(VerdictDeny)
	if responseErr != nil {
		s.log.Error("fatal fanotify batch event denial failed", "fd", meta.Fd, "err", responseErr)
		if !pending.responseAccepted() {
			s.retainFailedEvent(meta.Fd, pending)
		}
	}
	return responseErr
}

func (s *fanotifySource) setReaderDegraded(err error) {
	s.readerDegraded.Store(true)
	s.readerDiagMu.Lock()
	s.readerLastError = err.Error()
	s.readerDiagMu.Unlock()
}

func (s *fanotifySource) recordQueueOverflow() {
	s.queueOverflows.Add(1)
	err := errors.New("fanotify kernel queue overflow")
	s.setReaderDegraded(err)
	s.log.Error("fanotify kernel queue overflow", "count", s.queueOverflows.Load())
}

func (s *fanotifySource) recordReadEMFILE() {
	s.readEMFILEs.Add(1)
	s.descriptorPressure.Store(true)
	err := errors.New("fanotify read reached process file descriptor limit")
	s.setReaderDegraded(err)
	s.log.Error("fanotify read descriptor exhaustion", "count", s.readEMFILEs.Load(), "outstanding", s.outstanding.Load(), "limit", s.descriptorLimit)
}

func (s *fanotifySource) recordUnresolvedPath(fd int32) {
	s.unresolvedPathDenies.Add(1)
	err := fmt.Errorf("fanotify event path unresolved for descriptor %d", fd)
	s.setReaderDegraded(err)
	s.log.Error("fanotify event path unresolved; denying", "fd", fd, "count", s.unresolvedPathDenies.Load())
}

func (s *fanotifySource) ReaderDiagnostics() ReaderDiagnostics {
	s.readerDiagMu.Lock()
	lastError := s.readerLastError
	fatalError := s.readerFatalError
	s.readerDiagMu.Unlock()
	return ReaderDiagnostics{
		DescriptorLimit:            s.descriptorLimit,
		OutstandingDescriptors:     s.outstanding.Load(),
		PeakOutstandingDescriptors: s.peakOutstanding.Load(),
		DescriptorPressure:         s.descriptorPressure.Load(),
		EMFILECount:                s.readEMFILEs.Load(),
		QueueOverflowCount:         s.queueOverflows.Load(),
		UnresolvedPathDenyCount:    s.unresolvedPathDenies.Load(),
		Degraded:                   s.readerDegraded.Load(),
		Fatal:                      s.readerFatal.Load(),
		LastError:                  lastError,
		FatalError:                 fatalError,
	}
}

// resolveMarkMask builds the perm-event mask. OPEN_PERM and
// OPEN_EXEC_PERM are always on; ACCESS_PERM is gated behind the
// InterceptReads config option (off by default because it fires per
// read() syscall and can be very chatty).
func resolveMarkMask() uint64 {
	mask := uint64(unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM | unix.FAN_ONDIR)
	if cfgOptionInterceptReads != nil && cfgOptionInterceptReads() {
		mask |= uint64(unix.FAN_ACCESS_PERM)
	}
	return mask
}

// opFromMask decodes a perm-event mask into the matching FileOp,
// most-specific first. The kernel only ever sets one perm-event bit
// per event, but a stray combination still maps deterministically.
func opFromMask(mask uint64) FileOp {
	switch {
	case mask&unix.FAN_OPEN_EXEC_PERM != 0:
		return OpExec
	case mask&unix.FAN_ACCESS_PERM != 0:
		return OpRead
	default:
		return OpOpen
	}
}

// resolveWatchPaths returns the configured watch paths. An empty
// registered config value deliberately means no paths are watched.
func resolveWatchPaths() []string {
	if cfgOptionWatchPaths != nil {
		return cfgOptionWatchPaths()
	}
	return nil
}

func newFanotifySource(paths []string, log logger) (*fanotifySource, error) {
	descriptorLimit, err := currentDescriptorLimit()
	if err != nil {
		return nil, err
	}
	if descriptorLimit == 0 {
		return nil, fmt.Errorf("fanotify descriptor capacity exhausted: RLIMIT_NOFILE must exceed reserved headroom of %d", fanotifyDescriptorReserve)
	}

	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC,
	)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("fanotify_init needs CAP_SYS_ADMIN in the init user namespace: %w", err)
		}
		return nil, fmt.Errorf("fanotify_init: %w", err)
	}

	s := &fanotifySource{
		log:                log,
		fd:                 fd,
		scopes:             make(map[string]*policyScope),
		marks:              make(map[int]mountedMark),
		markMask:           resolveMarkMask(),
		mountInfo:          readMountInfo,
		failedEvents:       make(map[int32]PendingEvent),
		read:               unix.Read,
		poll:               unix.Poll,
		emfileRetry:        defaultEMFILERetry,
		descriptorLimit:    descriptorLimit,
		accounted:          make(map[int32]struct{}),
		descriptorReleased: make(chan struct{}, 1),
		mark: func(flags uint, mask uint64, path string) error {
			return unix.FanotifyMark(fd, flags, mask, unix.AT_FDCWD, path)
		},
	}
	s.responses = newFanotifyResponseWriter(fd, log, s.finishEventFDClose)

	if err := s.SetWatchPaths(paths); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	log.Info("fanotify source ready", "paths", paths, "fd", fd, "descriptor_limit", descriptorLimit)
	return s, nil
}

func (s *fanotifySource) SetWatchPaths(paths []string) error {
	s.marksMu.Lock()
	defer s.marksMu.Unlock()

	next, err := s.prepareScopes(paths)
	if err != nil {
		return err
	}
	previous := s.scopes
	s.scopes = next
	for configured, scope := range previous {
		if next[configured] != scope {
			s.retiredScopes = append(s.retiredScopes, scope)
		}
	}
	s.pending = true
	s.activeScopes.Store(unionScopes(s.activeScopes.Load(), snapshotFromScopes(next)))
	s.reconcileLocked()
	return nil
}

// Run reads events from the fanotify fd until ctx is cancelled or the fd
// is closed, transferring each permission event to handler.
func (s *fanotifySource) Run(ctx context.Context, handler PendingHandler) error {
	if s.read == nil {
		s.read = unix.Read
	}
	if s.poll == nil {
		s.poll = unix.Poll
	}
	if s.descriptorReleased == nil {
		s.descriptorReleased = make(chan struct{}, 1)
	}
	if s.emfileRetry <= 0 {
		s.emfileRetry = defaultEMFILERetry
	}
	buf := make([]byte, readBufferCapacity(math.MaxInt64))
	pollFds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		headroom := s.descriptorHeadroom()
		if headroom == 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-s.descriptorReleased:
				continue
			}
		}

		// Short poll keeps cancellation responsive without reading more event
		// descriptors than the currently available headroom.
		n, err := s.poll(pollFds, 500)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("poll: %w", err)
		}
		if n == 0 {
			continue
		}

		read, err := s.read(s.fd, buf[:readBufferCapacity(headroom)])
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EMFILE) {
				s.recordReadEMFILE()
				select {
				case <-ctx.Done():
					return nil
				case <-s.descriptorReleased:
				case <-time.After(s.emfileRetry):
				}
				continue
			}
			if errors.Is(err, unix.EBADF) {
				// fd closed by Close().
				return nil
			}
			return fmt.Errorf("read: %w", err)
		}
		s.descriptorPressure.Store(s.outstanding.Load() >= s.descriptorLimit)
		if read <= 0 {
			continue
		}

		if err := s.handleEvents(ctx, handler, buf[:read]); err != nil {
			return err
		}
	}
}

// Close releases the fanotify fd. Safe to call from any goroutine; the
// blocking Read in Run will unwind with EBADF.
func (s *fanotifySource) Close() error {
	s.marksMu.Lock()
	for _, scope := range s.scopes {
		scope.close()
	}
	for _, scope := range s.retiredScopes {
		scope.close()
	}
	s.marksMu.Unlock()
	return unix.Close(s.fd)
}

func (s *fanotifySource) handleEvents(ctx context.Context, handler PendingHandler, buf []byte) error {
	metaLen := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	events := make([]unix.FanotifyEventMetadata, 0, len(buf)/metaLen)
	var batchErr error
	var invalidEvent *unix.FanotifyEventMetadata

	for len(buf) >= metaLen {
		// Copy the fixed metadata prefix out of the read buffer. The overflow
		// bit and visible descriptor are handled before trusting any lengths.
		meta := *(*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[0]))
		if uint64(meta.Mask)&uint64(unix.FAN_Q_OVERFLOW) != 0 {
			s.recordQueueOverflow()
		}
		if meta.Fd >= 0 {
			s.accountEventFD(meta.Fd)
		}

		eventLen := int(meta.Event_len)
		switch {
		case eventLen < metaLen:
			batchErr = fmt.Errorf("invalid fanotify event length %d: shorter than metadata length %d", eventLen, metaLen)
		case eventLen > len(buf):
			batchErr = fmt.Errorf("invalid fanotify event length %d in %d-byte read remainder", eventLen, len(buf))
		case int(meta.Metadata_len) != metaLen:
			batchErr = fmt.Errorf("invalid fanotify metadata length %d: want %d", meta.Metadata_len, metaLen)
		case meta.Vers != unix.FANOTIFY_METADATA_VERSION:
			batchErr = fmt.Errorf("fanotify metadata version mismatch: got %d, want %d", meta.Vers, unix.FANOTIFY_METADATA_VERSION)
		}
		if batchErr != nil {
			if meta.Fd >= 0 {
				invalidEvent = &meta
			}
			break
		}

		if meta.Fd >= 0 {
			events = append(events, meta)
		}
		buf = buf[eventLen:]
	}
	if batchErr == nil && len(buf) != 0 {
		batchErr = fmt.Errorf("trailing %d-byte partial fanotify metadata record", len(buf))
	}

	if batchErr != nil {
		s.enterReaderFatal(batchErr)
		var resolutionErr error
		if invalidEvent != nil {
			resolutionErr = s.resolveAccountedEventForFatal(invalidEvent)
		}
		// The fatal state makes every earlier valid event take the controlled
		// deny path. Resolve all of them before returning the batch error.
		for i := range events {
			s.handleEvent(ctx, handler, &events[i])
		}
		return errors.Join(batchErr, resolutionErr)
	}

	// Every descriptor from this read is accounted before any path
	// resolution, scope classification, response, or policy work starts.
	for i := range events {
		s.handleEvent(ctx, handler, &events[i])
	}
	return nil
}

func (s *fanotifySource) handleEvent(ctx context.Context, handler PendingHandler, meta *unix.FanotifyEventMetadata) {
	if meta.Fd < 0 {
		return
	}
	s.accountEventFD(meta.Fd)

	if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
		err := fmt.Errorf("fanotify metadata version mismatch: got %d, want %d", meta.Vers, unix.FANOTIFY_METADATA_VERSION)
		s.enterReaderFatal(err)
		_ = s.resolveAccountedEventForFatal(meta)
		return
	}

	isPerm := uint64(meta.Mask)&fanotifyPermissionEvents != 0
	if !isPerm {
		_ = s.closeAccountedEventFD(meta.Fd)
		return
	}

	// Exe resolution is the lookup chain's job (process module already
	// does richer resolution -- cmdline, env, tags). Leaving Exe empty
	// here keeps the fanotify hot path free of unrelated /proc reads.
	path, resolved := resolveEventPath(fmt.Sprintf("/proc/self/fd/%d", meta.Fd))
	event := FileEvent{
		PID:  meta.Pid,
		Path: path,
		Op:   opFromMask(uint64(meta.Mask)),
	}
	pending := newPendingEvent(&event, func(verdict Verdict) responseResult {
		return s.responses.respond(meta.Fd, verdict)
	})
	var owner PendingEvent = pending
	var responseErr error
	switch {
	case s.responses.draining.Load():
		responseErr = pending.Respond(VerdictDeny)
	case !resolved:
		s.recordUnresolvedPath(meta.Fd)
		responseErr = pending.Respond(VerdictDeny)
	case !s.pathInActiveScope(path):
		responseErr = pending.Respond(VerdictAllow)
	default:
		owner, responseErr = deliverPendingEvent(ctx, handler, pending)
	}

	verdict, decided := pending.logicalVerdict()
	verdictValue := any("pending")
	if decided {
		verdictValue = verdict
	}
	s.log.Info("fanotify event",
		"pid", event.PID,
		"path", event.Path,
		"op", event.Op,
		"perm", true,
		"verdict", verdictValue,
	)
	if responseErr != nil {
		s.log.Error("fanotify event resolution failed", "fd", meta.Fd, "err", responseErr)
		if !pending.responseAccepted() && owner != nil {
			s.retainFailedEvent(meta.Fd, owner)
		}
	}
}

func (s *fanotifySource) retainFailedEvent(eventFD int32, owner PendingEvent) {
	s.failedMu.Lock()
	defer s.failedMu.Unlock()
	if s.failedEvents == nil {
		s.failedEvents = make(map[int32]PendingEvent)
	}
	s.failedEvents[eventFD] = owner
}

func resolveEventPath(link string) (string, bool) {
	target, err := os.Readlink(link)
	if err != nil || strings.HasSuffix(target, " (deleted)") {
		return "", false
	}
	target, err = normalizePath(target)
	if err != nil {
		return "", false
	}
	return target, true
}
