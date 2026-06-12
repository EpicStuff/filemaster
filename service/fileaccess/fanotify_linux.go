//go:build linux

package fileaccess

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/safing/portmaster/service/mgr"
)

// Skip events from our own PID. fanotify perm events block the caller
// until we respond, so an open inside the daemon's own handler path
// would deadlock the daemon against itself.
var ownPID = int32(os.Getpid())

// Phase-1 scaffold: hard-coded watch path, auto-allow every perm event,
// log {pid, exe, path}. No rules, no prompts, no profile lookup.
const watchPath = "/tmp/filemaster-test"

type fanotifyHandle struct {
	fd int
}

func (fa *FileAccess) startFanotify() error {
	// Make sure the watch path exists or FanotifyMark returns ENOENT.
	if err := os.MkdirAll(watchPath, 0o755); err != nil {
		return fmt.Errorf("create watch dir %s: %w", watchPath, err)
	}

	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC,
	)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("fanotify_init needs CAP_SYS_ADMIN (run as root): %w", err)
		}
		return fmt.Errorf("fanotify_init: %w", err)
	}

	// Inode-scoped mark on the directory itself + FAN_EVENT_ON_CHILD so
	// opens of immediate children come through too. Do NOT use
	// FAN_MARK_MOUNT here -- that marks the entire mount containing the
	// path, which on the root filesystem means every open on the system
	// gets routed to this daemon and the kernel will freeze every caller
	// waiting for verdicts.
	if err := unix.FanotifyMark(
		fd,
		unix.FAN_MARK_ADD,
		unix.FAN_OPEN_PERM|unix.FAN_EVENT_ON_CHILD,
		unix.AT_FDCWD,
		watchPath,
	); err != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("fanotify_mark %s: %w", watchPath, err)
	}

	fa.fan = &fanotifyHandle{fd: fd}
	fa.mgr.Info("fanotify started", "path", watchPath, "fd", fd)

	fa.mgr.Go("fanotify event loop", fa.runEventLoop)
	return nil
}

func (fa *FileAccess) stopFanotify() error {
	if fa.fan == nil {
		return nil
	}
	err := unix.Close(fa.fan.fd)
	fa.fan = nil
	return err
}

func (fa *FileAccess) runEventLoop(w *mgr.WorkerCtx) error {
	buf := make([]byte, 4096)
	pollFds := []unix.PollFd{{Fd: int32(fa.fan.fd), Events: unix.POLLIN}}

	for {
		select {
		case <-w.Done():
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

		read, err := unix.Read(fa.fan.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				// fd closed by Stop().
				return nil
			}
			return fmt.Errorf("read: %w", err)
		}
		if read <= 0 {
			continue
		}

		fa.handleEvents(w, buf[:read])
	}
}

func (fa *FileAccess) handleEvents(w *mgr.WorkerCtx, buf []byte) {
	metaLen := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for len(buf) >= metaLen {
		// Copy the struct out of the buffer so we can safely reslice.
		meta := *(*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[0]))
		evLen := int(meta.Event_len)
		if evLen < metaLen || evLen > len(buf) {
			return
		}
		fa.handleEvent(w, &meta)
		buf = buf[evLen:]
	}
}

func (fa *FileAccess) handleEvent(w *mgr.WorkerCtx, meta *unix.FanotifyEventMetadata) {
	if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
		w.Warn("fanotify metadata version mismatch",
			"got", meta.Vers,
			"want", unix.FANOTIFY_METADATA_VERSION)
		return
	}

	// FAN_NOFD (-1) means an overflow or fid-only event; nothing to do here.
	if meta.Fd < 0 {
		return
	}
	defer func() { _ = unix.Close(int(meta.Fd)) }()

	// Drop self-events to avoid deadlocking the daemon against itself.
	if meta.Pid == ownPID {
		if meta.Mask&unix.FAN_ALL_PERM_EVENTS != 0 {
			resp := unix.FanotifyResponse{Fd: meta.Fd, Response: unix.FAN_ALLOW}
			respBytes := unsafe.Slice((*byte)(unsafe.Pointer(&resp)), unsafe.Sizeof(resp))
			_, _ = unix.Write(fa.fan.fd, respBytes)
		}
		return
	}

	path, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", meta.Fd))
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", meta.Pid))

	isPerm := meta.Mask&unix.FAN_ALL_PERM_EVENTS != 0

	w.Info("fanotify event",
		"pid", meta.Pid,
		"exe", exe,
		"path", path,
		"mask", fmt.Sprintf("%#x", meta.Mask),
		"perm", isPerm,
	)

	if !isPerm {
		return
	}

	// Auto-allow for now. Kernel blocks the syscall until we write this back.
	resp := unix.FanotifyResponse{
		Fd:       meta.Fd,
		Response: unix.FAN_ALLOW,
	}
	respBytes := unsafe.Slice((*byte)(unsafe.Pointer(&resp)), unsafe.Sizeof(resp))
	if _, err := unix.Write(fa.fan.fd, respBytes); err != nil {
		w.Error("fanotify response write failed", "err", err)
	}
}
