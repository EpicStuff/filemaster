//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
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
	log       logger
	fd        int
	lifecycle *PipelineLifecycle

	marksMu       sync.Mutex
	scopes        map[string]*policyScope
	retiredScopes []*policyScope
	marks         map[int]mountedMark
	markMask      uint64
	pending       bool
	marksRemoved  atomic.Bool

	activeScopes atomic.Pointer[scopeSnapshot]
	diagnostics  MountDiagnostics

	mountInfo func() ([]mountInfo, error)
	mark      func(flags uint, mask uint64, path string) error

	read            func(int, []byte) (int, error)
	poll            func([]unix.PollFd, int) (int, error)
	emfileRetry     time.Duration
	descriptorLimit int64

	accountedMu         sync.Mutex
	accounted           map[int32]struct{}
	outstanding         atomic.Int64
	peakOutstanding     atomic.Int64
	decisionResponses   atomic.Uint64
	lastDecisionLatency atomic.Int64
	descriptorReleased  chan struct{}

	queueOverflows       atomic.Uint64
	readEMFILEs          atomic.Uint64
	unresolvedPathDenies atomic.Uint64
	descriptorPressure   atomic.Bool
	readerDegraded       atomic.Bool
	readerFatal          atomic.Bool
	readerRunning        atomic.Bool
	readerExited         atomic.Bool
	readerDiagMu         sync.Mutex
	readerLastError      string
	readerFatalError     string
	readerDone           chan struct{}
	readerIdle           chan struct{}
	readerDoneOnce       sync.Once
	reconcileDone        chan struct{}
	reconcileDoneOnce    sync.Once

	responses    *fanotifyResponseWriter
	failedMu     sync.Mutex
	failedEvents map[int32]PendingEvent

	groupCloseOnce sync.Once
	groupCloseErr  error

	scopeCleanupOnce     sync.Once
	scopeCleanupErr      error
	scopeCleanupComplete atomic.Bool
}

const (
	fanotifyDescriptorReserve = uint64(256)
	maxFanotifyReadBuffer     = 4096
	defaultEMFILERetry        = 250 * time.Millisecond
	fanotifyPermissionEvents  = uint64(unix.FAN_OPEN_PERM | unix.FAN_ACCESS_PERM | unix.FAN_OPEN_EXEC_PERM)
)

// ReaderDiagnostics is a race-safe snapshot of fanotify reader capacity and
// enforcement failures.
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

// SetDescriptorBudget limits fanotify event descriptors below the RLIMIT
// derived capacity. It is called before Run starts and can never enlarge the
// safety margin reserved by Phase 3.
func (s *fanotifySource) SetDescriptorBudget(limit int64) {
	if limit > 0 && limit < s.descriptorLimit {
		s.descriptorLimit = limit
	}
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
	pending := s.newFanotifyPendingEvent(&event, meta.Fd)
	responseErr := pending.Respond(VerdictDeny)
	if responseErr != nil {
		s.log.Error("fatal fanotify batch event denial failed", "fd", meta.Fd, "err", responseErr)
	}
	return responseErr
}

func (s *fanotifySource) newFanotifyPendingEvent(event *FileEvent, eventFD int32) *pendingEventOwner {
	started := time.Now()
	return newPendingEventWithFailureSink(event, func(verdict Verdict) responseResult {
		result := s.responses.respond(eventFD, verdict)
		if result.accepted {
			s.lastDecisionLatency.Store(time.Since(started).Nanoseconds())
			s.decisionResponses.Add(1)
		}
		return result
	}, func(owner PendingEvent) {
		s.retainFailedEvent(eventFD, owner)
	})
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
	s.accountedMu.Lock()
	accounted := make([]int32, 0, len(s.accounted))
	for fd := range s.accounted {
		accounted = append(accounted, fd)
	}
	s.accountedMu.Unlock()
	s.failedMu.Lock()
	failed := make([]int32, 0, len(s.failedEvents))
	for fd := range s.failedEvents {
		failed = append(failed, fd)
	}
	s.failedMu.Unlock()
	sort.Slice(accounted, func(i, j int) bool { return accounted[i] < accounted[j] })
	sort.Slice(failed, func(i, j int) bool { return failed[i] < failed[j] })
	return ReaderDiagnostics{
		DescriptorLimit:            s.descriptorLimit,
		OutstandingDescriptors:     s.outstanding.Load(),
		PeakOutstandingDescriptors: s.peakOutstanding.Load(),
		DecisionResponseCount:      s.decisionResponses.Load(),
		LastDecisionLatencyNanos:   s.lastDecisionLatency.Load(),
		AccountedDescriptors:       accounted,
		FailedResponseDescriptors:  failed,
		DescriptorPressure:         s.descriptorPressure.Load(),
		EMFILECount:                s.readEMFILEs.Load(),
		QueueOverflowCount:         s.queueOverflows.Load(),
		UnresolvedPathDenyCount:    s.unresolvedPathDenies.Load(),
		Running:                    s.readerRunning.Load(),
		Exited:                     s.readerExited.Load(),
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

	lifecycle := NewPipelineLifecycle()
	s := &fanotifySource{
		log:                log,
		fd:                 fd,
		lifecycle:          lifecycle,
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
		readerDone:         make(chan struct{}),
		readerIdle:         make(chan struct{}, 1),
		reconcileDone:      make(chan struct{}),
		mark: func(flags uint, mask uint64, path string) error {
			return unix.FanotifyMark(fd, flags, mask, unix.AT_FDCWD, path)
		},
	}
	s.responses = newFanotifyResponseWriter(fd, log, s.finishEventFDClose)
	s.responses.lifecycle = lifecycle

	if err := s.SetWatchPaths(paths); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	log.Info("fanotify source ready", "paths", paths, "fd", fd, "descriptor_limit", descriptorLimit)
	return s, nil
}

func (s *fanotifySource) SetLifecycle(lifecycle *PipelineLifecycle) {
	if lifecycle == nil {
		return
	}
	s.lifecycle = lifecycle
	if s.responses != nil {
		s.responses.lifecycle = lifecycle
	}
}

func (s *fanotifySource) SetWatchPaths(paths []string) error {
	s.marksMu.Lock()
	defer s.marksMu.Unlock()
	if !s.lifecycle.IsRunning() {
		return ErrFileAccessClosing
	}

	next, err := s.prepareScopes(paths)
	if err != nil {
		return err
	}
	published := s.lifecycle.whileRunning(func() {
		previous := s.scopes
		s.scopes = next
		for configured, scope := range previous {
			if next[configured] != scope {
				s.retiredScopes = append(s.retiredScopes, scope)
			}
		}
		s.pending = true
		s.activeScopes.Store(unionScopes(s.activeScopes.Load(), snapshotFromScopes(next)))
	})
	if !published {
		closeNewScopes(next, s.scopes)
		return ErrFileAccessClosing
	}
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
	if s.readerDone == nil {
		s.readerDone = make(chan struct{})
	}
	if s.readerIdle == nil {
		s.readerIdle = make(chan struct{}, 1)
	}
	if s.emfileRetry <= 0 {
		s.emfileRetry = defaultEMFILERetry
	}
	s.readerRunning.Store(true)
	s.readerExited.Store(false)
	defer func() {
		s.readerRunning.Store(false)
		s.readerExited.Store(true)
		s.readerDoneOnce.Do(func() { close(s.readerDone) })
	}()
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

		n, err := s.poll(pollFds, 500)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("poll: %w", err)
		}
		if n == 0 {
			if !s.lifecycle.IsRunning() && s.marksRemoved.Load() && s.outstanding.Load() == 0 {
				select {
				case s.readerIdle <- struct{}{}:
				default:
				}
			}
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
func (s *fanotifySource) WaitReaderDrained(ctx context.Context) error {
	if !s.marksRemoved.Load() {
		return errors.New("fanotify marks remain active")
	}
	if !s.readerRunning.Load() {
		if s.outstanding.Load() == 0 {
			return nil
		}
		return errors.New("fanotify reader is not running with outstanding descriptors")
	}
	for {
		if s.outstanding.Load() == 0 {
			select {
			case <-s.readerIdle:
				return nil
			default:
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.readerIdle:
			if s.outstanding.Load() == 0 {
				return nil
			}
		case <-s.descriptorReleased:
		}
	}
}

func (s *fanotifySource) WaitReaderExit(ctx context.Context) error {
	if s.readerDone == nil {
		return nil
	}
	select {
	case <-s.readerDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *fanotifySource) ResponseDiagnostics() ResponseWriterDiagnostics {
	if s.responses == nil {
		return ResponseWriterDiagnostics{CurrentFD: -1}
	}
	return s.responses.Diagnostics()
}

func (s *fanotifySource) CloseGroup() error {
	s.groupCloseOnce.Do(func() {
		if s.responses != nil {
			_ = s.responses.WaitCurrentResponse(context.Background())
			s.groupCloseErr = s.responses.SealAndCloseGroup()
		} else {
			s.groupCloseErr = unix.Close(s.fd)
		}
	})
	return s.groupCloseErr
}

func (s *fanotifySource) CleanupScopes() error {
	s.scopeCleanupOnce.Do(func() {
		s.marksMu.Lock()
		defer s.marksMu.Unlock()
		for _, scope := range s.scopes {
			scope.close()
		}
		for _, scope := range s.retiredScopes {
			scope.close()
		}
		s.scopes = nil
		s.retiredScopes = nil
		s.scopeCleanupComplete.Store(true)
	})
	return s.scopeCleanupErr
}

func (s *fanotifySource) ScopeCleanupComplete() bool {
	return s.scopeCleanupComplete.Load()
}

func (s *fanotifySource) Close() error {
	return errors.Join(s.CloseGroup(), s.CleanupScopes())
}

func (s *fanotifySource) handleEvents(ctx context.Context, handler PendingHandler, buf []byte) error {
	metaLen := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	events := make([]unix.FanotifyEventMetadata, 0, len(buf)/metaLen)
	var batchErr error

	for len(buf) >= metaLen {
		// The fixed metadata prefix is the only safe information until this
		// record's version and framing have both been validated. Account a
		// visible descriptor before any routing, but never use an untrusted
		// Event_len to locate another record.
		meta := *(*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[0]))
		if uint64(meta.Mask)&uint64(unix.FAN_Q_OVERFLOW) != 0 {
			s.recordQueueOverflow()
		}
		if meta.Fd >= 0 {
			s.accountEventFD(meta.Fd)
			events = append(events, meta)
		}

		if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
			batchErr = fmt.Errorf(
				"fanotify metadata version mismatch: got %d, want %d; refusing untrusted event length and leaving %d-byte tail unparseable",
				meta.Vers,
				unix.FANOTIFY_METADATA_VERSION,
				len(buf)-metaLen,
			)
			break
		}

		eventLen := int(meta.Event_len)
		var structuralErr error
		switch {
		case eventLen < metaLen:
			structuralErr = fmt.Errorf("invalid fanotify event length %d: shorter than metadata length %d", eventLen, metaLen)
		case eventLen > len(buf):
			structuralErr = fmt.Errorf("invalid fanotify event length %d in %d-byte read remainder", eventLen, len(buf))
		case int(meta.Metadata_len) != metaLen:
			structuralErr = fmt.Errorf("invalid fanotify metadata length %d: want %d", meta.Metadata_len, metaLen)
		}
		if structuralErr != nil {
			batchErr = fmt.Errorf("%w; refusing malformed record boundary and leaving %d-byte tail unparseable", structuralErr, len(buf)-metaLen)
			break
		}

		// Both the compatible metadata version and framing are now trusted, so
		// advancing by Event_len preserves the complete-batch accounting
		// guarantee for valid kernel buffers.
		buf = buf[eventLen:]
	}
	if batchErr == nil && len(buf) != 0 {
		batchErr = fmt.Errorf("trailing %d-byte partial fanotify metadata record is unparseable", len(buf))
	}

	if batchErr != nil {
		s.enterReaderFatal(batchErr)
		var resolutionErr error
		// No safely identified event from a fatal batch may reach path
		// resolution, scope classification, or policy. Resolve every accounted
		// descriptor through the controlled deny/close path before closing the
		// group; an unframed tail is intentionally reported, not guessed at.
		for i := range events {
			resolutionErr = errors.Join(resolutionErr, s.resolveAccountedEventForFatal(&events[i]))
		}
		groupErr := s.CloseGroup()
		if groupErr != nil {
			groupErr = fmt.Errorf("close fanotify group after fatal malformed batch: %w", groupErr)
		}
		return errors.Join(batchErr, resolutionErr, groupErr)
	}

	// Every descriptor from this valid read is accounted before any path
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
	// handleEvents has already validated this metadata and accounted its
	// descriptor. Routing must never perform accounting: that invariant keeps
	// descriptor ownership ahead of path resolution and policy work.

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
	pending := s.newFanotifyPendingEvent(&event, meta.Fd)
	var responseErr error
	switch {
	case !s.lifecycle.IsRunning():
		responseErr = pending.Respond(VerdictDeny)
	case s.responses.draining.Load():
		responseErr = pending.Respond(VerdictDeny)
	case !resolved:
		s.recordUnresolvedPath(meta.Fd)
		responseErr = pending.Respond(VerdictDeny)
	case !s.pathInActiveScope(path):
		responseErr = pending.Respond(VerdictAllow)
	default:
		_, responseErr = deliverPendingEvent(ctx, handler, pending)
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
