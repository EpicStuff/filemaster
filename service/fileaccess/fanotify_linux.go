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
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// fanotifySource is a Linux fanotify-backed Source. Mount marks collect
// kernel events while the immutable scope snapshot determines policy scope.
type fanotifySource struct {
	log logger
	fd  int

	marksMu  sync.Mutex
	scopes   map[string]*policyScope
	marks    map[int]mountedMark
	markMask uint64
	pending  bool

	activeScopes atomic.Pointer[scopeSnapshot]
	diagnostics  MountDiagnostics

	mountInfo func() ([]mountInfo, error)
	mark      func(flags uint, mask uint64, path string) error
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
		log:       log,
		fd:        fd,
		scopes:    make(map[string]*policyScope),
		marks:     make(map[int]mountedMark),
		markMask:  resolveMarkMask(),
		mountInfo: readMountInfo,
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
	s.scopes = next
	s.pending = true
	s.activeScopes.Store(unionScopes(s.activeScopes.Load(), snapshotFromScopes(next)))
	s.reconcileLocked()
	return nil
}

// Run reads events from the fanotify fd until ctx is cancelled or the fd
// is closed, calling handler.Decide for each perm event.
func (s *fanotifySource) Run(ctx context.Context, h Handler) error {
	buf := make([]byte, 4096)
	pollFds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
	reconcileTicker := time.NewTicker(5 * time.Second)
	defer reconcileTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-reconcileTicker.C:
			s.reconcile()
			continue
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

		s.handleEvents(ctx, h, buf[:read])
	}
}

// Close releases the fanotify fd. Safe to call from any goroutine; the
// blocking Read in Run will unwind with EBADF.
func (s *fanotifySource) Close() error {
	s.marksMu.Lock()
	for _, scope := range s.scopes {
		scope.close()
	}
	s.marksMu.Unlock()
	return unix.Close(s.fd)
}

func (s *fanotifySource) handleEvents(ctx context.Context, h Handler, buf []byte) {
	metaLen := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for len(buf) >= metaLen {
		// Copy the struct out of the buffer so we can safely reslice.
		meta := *(*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[0]))
		evLen := int(meta.Event_len)
		if evLen < metaLen || evLen > len(buf) {
			return
		}
		s.handleEvent(ctx, h, &meta)
		buf = buf[evLen:]
	}
}

func (s *fanotifySource) handleEvent(ctx context.Context, h Handler, meta *unix.FanotifyEventMetadata) {
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
	defer func() { _ = unix.Close(int(meta.Fd)) }()

	// FAN_ALL_PERM_EVENTS in x/sys/unix is OPEN|ACCESS (0x30000) -- it
	// predates OPEN_EXEC_PERM (0x40000), so check our own mask.
	const allPerm = uint64(unix.FAN_OPEN_PERM | unix.FAN_ACCESS_PERM | unix.FAN_OPEN_EXEC_PERM)
	isPerm := uint64(meta.Mask)&allPerm != 0

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

	verdict := VerdictAllow
	if isPerm {
		if !resolved {
			verdict = VerdictDeny
			s.log.Warn("fanotify event path unresolved", "fd", meta.Fd)
		} else if s.pathInActiveScope(path) {
			verdict = h.Decide(ctx, &event)
		}
	}

	s.log.Info("fanotify event",
		"pid", event.PID,
		"path", event.Path,
		"op", event.Op,
		"perm", isPerm,
		"verdict", verdict,
	)

	if isPerm {
		s.respond(meta.Fd, verdict)
	}
}

func (s *fanotifySource) respond(eventFd int32, v Verdict) {
	resp := unix.FanotifyResponse{Fd: eventFd}
	if v == VerdictAllow {
		resp.Response = unix.FAN_ALLOW
	} else {
		resp.Response = unix.FAN_DENY
	}
	respBytes := unsafe.Slice((*byte)(unsafe.Pointer(&resp)), unsafe.Sizeof(resp))
	if _, err := unix.Write(s.fd, respBytes); err != nil {
		s.log.Error("fanotify response write failed", "err", err, "verdict", v)
	}
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
