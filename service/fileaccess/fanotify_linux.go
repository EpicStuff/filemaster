//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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

	responses    *fanotifyResponseWriter
	failedMu     sync.Mutex
	failedEvents map[int32]PendingEvent
}

// resolveMarkMask builds the perm-event mask. OPEN_PERM and
// OPEN_EXEC_PERM are always on; ACCESS_PERM is gated behind the
// InterceptReads config option (off by default because it fires per
// read() syscall and can be very chatty).
func resolveMarkMask() uint64 {
	mask := uint64(unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM)
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
		log:          log,
		fd:           fd,
		scopes:       make(map[string]*policyScope),
		marks:        make(map[int]mountedMark),
		markMask:     resolveMarkMask(),
		mountInfo:    readMountInfo,
		responses:    newFanotifyResponseWriter(fd, log),
		failedEvents: make(map[int32]PendingEvent),
		mark: func(flags uint, mask uint64, path string) error {
			return unix.FanotifyMark(fd, flags, mask, unix.AT_FDCWD, path)
		},
	}

	if err := s.SetWatchPaths(paths); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	log.Info("fanotify source ready", "paths", paths, "fd", fd)
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
	buf := make([]byte, 4096)
	pollFds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		// Short poll so shutdown is responsive.
		n, err := unix.Poll(pollFds, 500)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("poll: %w", err)
		}
		if n == 0 {
			continue
		}

		read, err := unix.Read(s.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				// fd closed by Close().
				return nil
			}
			return fmt.Errorf("read: %w", err)
		}
		if read <= 0 {
			continue
		}

		s.handleEvents(ctx, handler, buf[:read])
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

func (s *fanotifySource) handleEvents(ctx context.Context, handler PendingHandler, buf []byte) {
	metaLen := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for len(buf) >= metaLen {
		// Copy the struct out of the buffer so we can safely reslice.
		meta := *(*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[0]))
		evLen := int(meta.Event_len)
		if evLen < metaLen || evLen > len(buf) {
			return
		}
		s.handleEvent(ctx, handler, &meta)
		buf = buf[evLen:]
	}
}

func (s *fanotifySource) handleEvent(ctx context.Context, handler PendingHandler, meta *unix.FanotifyEventMetadata) {
	if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
		s.log.Warn("fanotify metadata version mismatch",
			"got", meta.Vers,
			"want", unix.FANOTIFY_METADATA_VERSION)
		return
	}

	// FAN_NOFD (-1) means an overflow or fid-only event; nothing to do here.
	if meta.Fd < 0 {
		return
	}

	// FAN_ALL_PERM_EVENTS in x/sys/unix is OPEN|ACCESS (0x30000) -- it
	// predates OPEN_EXEC_PERM (0x40000), so check our own mask.
	const allPerm = uint64(unix.FAN_OPEN_PERM | unix.FAN_ACCESS_PERM | unix.FAN_OPEN_EXEC_PERM)
	isPerm := uint64(meta.Mask)&allPerm != 0
	if !isPerm {
		if err := unix.Close(int(meta.Fd)); err != nil {
			s.log.Warn("close non-permission fanotify event fd", "fd", meta.Fd, "err", err)
		}
		return
	}

	// Exe resolution is the lookup chain's job (process module already
	// does richer resolution -- cmdline, env, tags). Leaving Exe empty
	// here keeps the fanotify hot path free of /proc reads; the
	// ProfileHandler populates it from Process.Path before delegating
	// to the fallback or logging anything that needs it.
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
		s.log.Warn("fanotify event path unresolved", "fd", meta.Fd)
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
