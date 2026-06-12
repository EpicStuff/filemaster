//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// defaultWatchPath is used when the env var is unset; mainly so the
// demo / smoke binaries continue to work out of the box.
const defaultWatchPath = "/tmp/filemaster-test"

// envWatchPaths is the colon-separated list of directories the source
// marks. Set by ops / demo scripts; the daemon's config option
// supersedes this once we have one.
const envWatchPaths = "FM_WATCH_PATHS"

// fanotifySource is a Linux fanotify-backed Source. One fd per source;
// Run reads events from it, Close releases it. Construction does both
// fanotify_init and fanotify_mark so errors surface to module startup.
type fanotifySource struct {
	log    logger
	fd     int
	ownPID int32
}

// newPlatformSource returns the Source implementation for this OS.
// On Linux this is the fanotify-backed one, watching whatever paths
// are listed in FM_WATCH_PATHS (colon-separated) or the default if
// unset.
func newPlatformSource(log logger) (Source, error) {
	return newFanotifySource(watchPathsFromEnv(), log)
}

// watchPathsFromEnv parses FM_WATCH_PATHS or returns the single
// default. Empty entries are dropped.
func watchPathsFromEnv() []string {
	raw := os.Getenv(envWatchPaths)
	if raw == "" {
		return []string{defaultWatchPath}
	}
	var out []string
	for _, p := range strings.Split(raw, ":") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{defaultWatchPath}
	}
	return out
}

func newFanotifySource(paths []string, log logger) (*fanotifySource, error) {
	if len(paths) == 0 {
		return nil, errors.New("no watch paths configured")
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

	for _, path := range paths {
		if err := os.MkdirAll(path, 0o755); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("create watch dir %s: %w", path, err)
		}

		// Inode-scoped mark + FAN_EVENT_ON_CHILD. Do NOT use
		// FAN_MARK_MOUNT here: that marks the entire mount containing
		// the path, which on a root-fs watch dir routes every system
		// open to this daemon and freezes the host when verdicts can't
		// keep up.
		if err := unix.FanotifyMark(
			fd,
			unix.FAN_MARK_ADD,
			unix.FAN_OPEN_PERM|unix.FAN_EVENT_ON_CHILD,
			unix.AT_FDCWD,
			path,
		); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("fanotify_mark %s: %w", path, err)
		}
	}

	log.Info("fanotify source ready", "paths", paths, "fd", fd)

	return &fanotifySource{
		log:    log,
		fd:     fd,
		ownPID: int32(os.Getpid()),
	}, nil
}

// Run reads events from the fanotify fd until ctx is cancelled or the fd
// is closed, calling handler.Decide for each perm event.
func (s *fanotifySource) Run(ctx context.Context, h Handler) error {
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

		s.handleEvents(ctx, h, buf[:read])
	}
}

// Close releases the fanotify fd. Safe to call from any goroutine; the
// blocking Read in Run will unwind with EBADF.
func (s *fanotifySource) Close() error {
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

	isPerm := meta.Mask&unix.FAN_ALL_PERM_EVENTS != 0

	// Drop self-events to avoid deadlocking the daemon against itself
	// (an open inside Decide blocking on a verdict from Decide).
	if meta.Pid == s.ownPID {
		if isPerm {
			s.respond(meta.Fd, VerdictAllow)
		}
		return
	}

	event := FileEvent{
		PID:  meta.Pid,
		Exe:  readlinkSilent(fmt.Sprintf("/proc/%d/exe", meta.Pid)),
		Path: readlinkSilent(fmt.Sprintf("/proc/self/fd/%d", meta.Fd)),
		Op:   OpOpen,
	}

	verdict := VerdictAllow
	if isPerm {
		verdict = h.Decide(ctx, event)
	}

	s.log.Info("fanotify event",
		"pid", event.PID,
		"exe", event.Exe,
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

func readlinkSilent(p string) string {
	target, _ := os.Readlink(p)
	return target
}
