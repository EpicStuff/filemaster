//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
//
// Each user-requested root expands to a fanotify mark per *existing*
// subdirectory at SetWatchPaths time (subdirectory recursion). New
// subdirs created after the most-recent SetWatchPaths aren't tracked
// until the next config change re-walks the tree -- accepted limit
// for now; using FAN_REPORT_FID would let us autotrack but is a
// larger refactor.
type fanotifySource struct {
	log    logger
	fd     int
	ownPID int32

	// marksMu guards roots AND markMask. fanotify_mark itself is safe
	// to call concurrently, but we keep the in-memory state under a
	// lock so two SetWatchPaths racing produce a coherent end state.
	marksMu sync.Mutex
	// roots maps each user-requested watch root to the set of paths
	// the kernel currently has marks on (always includes the root +
	// each subdirectory discovered by the walk). markRemove uses this
	// to find exactly what to unmark when a root goes away.
	roots    map[string]map[string]struct{}
	markMask uint64
}

// resolveMarkMask builds the perm-event mask. OPEN_PERM and
// OPEN_EXEC_PERM are always on; ACCESS_PERM is gated behind the
// InterceptReads config option (off by default because it fires per
// read() syscall and can be very chatty).
func resolveMarkMask() uint64 {
	mask := uint64(unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM | unix.FAN_EVENT_ON_CHILD)
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

// newPlatformSource returns the Source implementation for this OS.
// On Linux this is the fanotify-backed one. Watch paths come from, in
// priority order:
//
//  1. cfgOptionWatchPaths -- the registered StringArrayOption. In a
//     fully-booted daemon this is the only source that matters; the
//     config module overrides it from disk + UI.
//  2. FM_WATCH_PATHS env var (colon-separated). Useful for the
//     standalone smoke/demo binaries that don't bring up the config
//     module.
//  3. defaultWatchPath -- a single hardcoded directory so the
//     out-of-box demo / smoke flow keeps working without setup.
func newPlatformSource(log logger) (Source, error) {
	return newFanotifySource(resolveWatchPaths(), log)
}

// resolveWatchPaths runs the priority chain documented on
// newPlatformSource and returns the resulting path list. Always
// returns at least one entry.
func resolveWatchPaths() []string {
	if cfgOptionWatchPaths != nil {
		if v := cfgOptionWatchPaths(); len(v) > 0 {
			return v
		}
	}
	if env := watchPathsFromEnv(); env != nil {
		return env
	}
	return []string{defaultWatchPath}
}

// watchPathsFromEnv parses FM_WATCH_PATHS into a slice, or returns nil
// if unset / empty after trimming. Caller decides what to do on nil.
func watchPathsFromEnv() []string {
	raw := os.Getenv(envWatchPaths)
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ":") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
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

	s := &fanotifySource{
		log:      log,
		fd:       fd,
		ownPID:   int32(os.Getpid()),
		roots:    make(map[string]map[string]struct{}),
		markMask: resolveMarkMask(),
	}

	if err := s.SetWatchPaths(paths); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}

	log.Info("fanotify source ready", "paths", paths, "fd", fd)
	return s, nil
}

// normalizeWatchPaths trims whitespace and drops empty entries from a
// raw path list, returning a deduplicated set. Pure so tests can pin
// the diff semantics without touching the kernel.
func normalizeWatchPaths(paths []string) map[string]struct{} {
	want := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		want[p] = struct{}{}
	}
	return want
}

// diffWatchPaths returns the (add, remove) deltas needed to bring
// current up to want. Pure; tests cover the corner cases (no-op,
// overlap, full swap).
func diffWatchPaths(current, want map[string]struct{}) (toAdd, toRemove []string) {
	for p := range want {
		if _, ok := current[p]; !ok {
			toAdd = append(toAdd, p)
		}
	}
	for p := range current {
		if _, ok := want[p]; !ok {
			toRemove = append(toRemove, p)
		}
	}
	return toAdd, toRemove
}

// SetWatchPaths reconciles the current mark set with paths: walks +
// marks new roots (recursively), unmarks ones that are gone, leaves
// roots that didn't change alone. Errors per-path are joined but the
// rest of the diff is still applied. Also picks up perm-event mask
// changes (the InterceptReads toggle) by re-marking the existing
// subtree with the new mask.
func (s *fanotifySource) SetWatchPaths(paths []string) error {
	want := normalizeWatchPaths(paths)

	s.marksMu.Lock()
	defer s.marksMu.Unlock()

	var errs []error

	newMask := resolveMarkMask()
	maskChanged := newMask != s.markMask
	oldMask := s.markMask

	// Mask change: tear every existing mark down with the old mask,
	// then let the add-pass below re-mark every requested root with
	// the new mask. Kernel requires add/remove to use the same mask
	// the mark was created with.
	if maskChanged {
		for root, marked := range s.roots {
			for p := range marked {
				if err := unix.FanotifyMark(s.fd, unix.FAN_MARK_REMOVE, oldMask, unix.AT_FDCWD, p); err != nil {
					errs = append(errs, fmt.Errorf("remask remove %s: %w", p, err))
				}
			}
			// Wipe the per-root set so the add-pass walks fresh.
			s.roots[root] = make(map[string]struct{})
		}
		s.markMask = newMask
	}

	// Walk every requested root. The kernel's FAN_MARK_ADD is
	// idempotent on already-marked inodes, so re-walking an unchanged
	// root is cheap on the syscall side and lets us pick up subdirs
	// created since the last reload. Dirs that vanished get their
	// kernel mark dropped below.
	for root := range want {
		marked, err := s.walkAndMark(root)
		if err != nil {
			errs = append(errs, fmt.Errorf("add %s: %w", root, err))
		}
		previous := s.roots[root]
		if previous == nil {
			s.roots[root] = make(map[string]struct{}, len(marked))
		}
		// Drop marks for subdirs that disappeared since last walk.
		// When a watched dir is deleted, the kernel implicitly drops
		// the mark (marks are inode-keyed); a FAN_MARK_REMOVE by path
		// for the gone dir returns ENOENT, which is the desired
		// post-condition, so swallow it.
		for p := range previous {
			if _, kept := marked[p]; kept {
				continue
			}
			if err := s.markRemove(p); err != nil && !errors.Is(err, unix.ENOENT) {
				errs = append(errs, fmt.Errorf("stale %s: %w", p, err))
			}
			delete(s.roots[root], p)
		}
		// Adopt the freshly-walked set.
		added := 0
		for p := range marked {
			if _, ok := s.roots[root][p]; !ok {
				added++
			}
			s.roots[root][p] = struct{}{}
		}
		if !maskChanged && (previous == nil || added > 0) {
			s.log.Info("fanotify root marked", "root", root, "subdirs", len(marked), "newly_added", added)
		}
	}
	if maskChanged {
		var total int
		for _, m := range s.roots {
			total += len(m)
		}
		s.log.Info("fanotify mask updated", "mask", fmt.Sprintf("0x%x", newMask), "marks", total)
	}

	// Remove roots that are no longer wanted.
	for root, marked := range s.roots {
		if _, keep := want[root]; keep {
			continue
		}
		for p := range marked {
			if err := s.markRemove(p); err != nil && !errors.Is(err, unix.ENOENT) {
				// ENOENT means the kernel already dropped the mark
				// when the dir disappeared (marks are inode-keyed);
				// the post-condition is what we wanted, so swallow.
				// Other errors are surfaced and the per-root entry
				// is still dropped -- retrying every reload would be
				// noise.
				errs = append(errs, fmt.Errorf("remove %s: %w", p, err))
			}
		}
		delete(s.roots, root)
		s.log.Info("fanotify root unmarked", "root", root, "subdirs", len(marked))
	}
	return errors.Join(errs...)
}

// walkAndMark walks root recursively and adds a fanotify mark per
// existing subdirectory (including root itself). Symlinks aren't
// followed (filepath.WalkDir behavior) so we can't accidentally walk
// out of the tree. Per-path mark errors are joined; the returned set
// holds exactly the paths the kernel accepted.
func (s *fanotifySource) walkAndMark(root string) (map[string]struct{}, error) {
	return s.walkAndMarkVia(root, s.markOne)
}

// walkAndMarkVia is the test-hookable inner walker -- the production
// path passes s.markOne; tests can pass a recording stub so the walk
// semantics can be verified without a live fanotify fd.
func (s *fanotifySource) walkAndMarkVia(root string, mark func(string) error) (map[string]struct{}, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("create watch dir: %w", err)
	}

	marked := make(map[string]struct{})
	var errs []error

	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Permission denied / disappeared underneath us. Record
			// and keep walking siblings -- a single unreadable subtree
			// shouldn't void the whole root.
			errs = append(errs, walkErr)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if err := mark(p); err != nil {
			errs = append(errs, fmt.Errorf("mark %s: %w", p, err))
			return nil
		}
		marked[p] = struct{}{}
		return nil
	})
	if walkErr != nil {
		errs = append(errs, walkErr)
	}
	return marked, errors.Join(errs...)
}

// markOne adds a single fanotify mark with the current mask. Inode-
// scoped + FAN_EVENT_ON_CHILD on every subdir means we see opens of
// files in any nested directory. Do NOT use FAN_MARK_MOUNT here: that
// marks the entire mount containing the path, which on a root-fs
// watch dir routes every system open to this daemon and freezes the
// host when verdicts can't keep up.
func (s *fanotifySource) markOne(path string) error {
	return unix.FanotifyMark(
		s.fd,
		unix.FAN_MARK_ADD,
		s.markMask,
		unix.AT_FDCWD,
		path,
	)
}

func (s *fanotifySource) markRemove(path string) error {
	return unix.FanotifyMark(
		s.fd,
		unix.FAN_MARK_REMOVE,
		s.markMask,
		unix.AT_FDCWD,
		path,
	)
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

	// FAN_ALL_PERM_EVENTS in x/sys/unix is OPEN|ACCESS (0x30000) -- it
	// predates OPEN_EXEC_PERM (0x40000), so check our own mask.
	const allPerm = uint64(unix.FAN_OPEN_PERM | unix.FAN_ACCESS_PERM | unix.FAN_OPEN_EXEC_PERM)
	isPerm := uint64(meta.Mask)&allPerm != 0

	// Drop self-events to avoid deadlocking the daemon against itself
	// (an open inside Decide blocking on a verdict from Decide).
	if meta.Pid == s.ownPID {
		if isPerm {
			s.respond(meta.Fd, VerdictAllow)
		}
		return
	}

	// Exe resolution is the lookup chain's job (process module already
	// does richer resolution -- cmdline, env, tags). Leaving Exe empty
	// here keeps the fanotify hot path free of /proc reads; the
	// ProfileHandler populates it from Process.Path before delegating
	// to the fallback or logging anything that needs it.
	event := FileEvent{
		PID:  meta.Pid,
		Path: readlinkSilent(fmt.Sprintf("/proc/self/fd/%d", meta.Fd)),
		Op:   opFromMask(uint64(meta.Mask)),
	}

	verdict := VerdictAllow
	if isPerm {
		verdict = h.Decide(ctx, event)
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

func readlinkSilent(p string) string {
	target, _ := os.Readlink(p)
	return target
}
