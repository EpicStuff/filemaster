//go:build linux

package fileaccess

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"golang.org/x/sys/unix"
)

// TestWalkAndMarkVisitsSubdirs builds a small nested directory tree,
// then drives walkAndMark via a stub markOne that records every path
// the walker tried to mark (instead of actually calling the kernel).
// Confirms every directory in the tree shows up exactly once and
// symlinks aren't followed.
func TestWalkAndMarkVisitsSubdirs(t *testing.T) {
	root := t.TempDir()
	// tree:
	//   <root>/a/b/c
	//   <root>/a/skip-me-not.txt
	//   <root>/d
	//   <root>/symlink -> /etc
	mkdir(t, root, "a", "b", "c")
	mkdir(t, root, "d")
	mkfile(t, root, "a/skip-me-not.txt")
	if err := os.Symlink("/etc", filepath.Join(root, "symlink")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	visited, err := walkSubdirsRecording(root)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	want := []string{
		root,
		filepath.Join(root, "a"),
		filepath.Join(root, "a", "b"),
		filepath.Join(root, "a", "b", "c"),
		filepath.Join(root, "d"),
	}
	got := keys(visited)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("visited dirs = %v, want %v", got, want)
	}
}

// TestSetWatchPathsLiveAddRemoveSubtree drives the real source through
// SetWatchPaths with a temp root and a small subtree, verifies the
// mark count matches the subtree (root + every dir), then drops the
// root and verifies the mark count returns to zero. Requires a real
// fanotify fd, so it skips when permissions aren't available.
func TestSetWatchPathsLiveAddRemoveSubtree(t *testing.T) {
	root := t.TempDir()
	mkdir(t, root, "a", "b")
	mkdir(t, root, "a", "c")
	mkdir(t, root, "x")

	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC,
	)
	if err != nil {
		t.Skipf("fanotify_init unavailable (%v); skipping live test", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	s := &fanotifySource{
		log:      nopLogger{},
		fd:       fd,
		roots:    make(map[string]map[string]struct{}),
		markMask: uint64(unix.FAN_OPEN_PERM | unix.FAN_EVENT_ON_CHILD),
	}

	if err := s.SetWatchPaths([]string{root}); err != nil {
		t.Fatalf("set: %v", err)
	}

	// Expect: root + a + a/b + a/c + x  = 5 marks
	if got := totalMarks(s); got != 5 {
		t.Errorf("after add: %d marks, want 5", got)
	}

	if err := s.SetWatchPaths(nil); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if got := totalMarks(s); got != 0 {
		t.Errorf("after clear: %d marks, want 0", got)
	}
}

// TestSetWatchPathsLiveReloadAddsNewSubdirsOnReload confirms that a
// subdir created after the initial walk is picked up on the next
// SetWatchPaths call (the live-reload flow). This is the
// documented-limitation acceptance criterion: new subdirs don't auto-
// register, but a config commit re-walks the tree.
func TestSetWatchPathsLiveReloadAddsNewSubdirsOnReload(t *testing.T) {
	root := t.TempDir()
	mkdir(t, root, "a")

	fd, err := unix.FanotifyInit(
		unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC,
	)
	if err != nil {
		t.Skipf("fanotify_init unavailable (%v); skipping live test", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	s := &fanotifySource{
		log:      nopLogger{},
		fd:       fd,
		roots:    make(map[string]map[string]struct{}),
		markMask: uint64(unix.FAN_OPEN_PERM | unix.FAN_EVENT_ON_CHILD),
	}

	if err := s.SetWatchPaths([]string{root}); err != nil {
		t.Fatalf("initial set: %v", err)
	}
	first := totalMarks(s)
	if first != 2 { // root + a
		t.Fatalf("after first set: %d marks, want 2", first)
	}

	// New subdir created after the initial walk -- not tracked yet
	// because fanotify doesn't auto-subscribe child dirs.
	mkdir(t, root, "a", "b")
	if got := totalMarks(s); got != first {
		t.Errorf("kernel auto-marked new subdir between walks (%d vs %d); "+
			"design assumed kernel doesn't do this", got, first)
	}

	// Re-issue SetWatchPaths (this is what the live-reload hook does
	// on every config change). The walker should re-traverse the
	// unchanged root and pick up the new subdir.
	if err := s.SetWatchPaths([]string{root}); err != nil {
		t.Fatalf("reload set: %v", err)
	}
	if got := totalMarks(s); got != first+1 {
		t.Errorf("after reload: %d marks, want %d (reload should pick up new subdir)", got, first+1)
	}

	// Remove the subdir -- next reload should drop the stale mark.
	if err := os.RemoveAll(filepath.Join(root, "a", "b")); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if err := s.SetWatchPaths([]string{root}); err != nil {
		t.Fatalf("reload-after-rm: %v", err)
	}
	if got := totalMarks(s); got != first {
		t.Errorf("after rm + reload: %d marks, want %d (reload should drop stale mark)", got, first)
	}
}

// walkSubdirsRecording invokes the same walker fanotifySource uses but
// records visited dirs instead of marking them.
func walkSubdirsRecording(root string) (map[string]struct{}, error) {
	visited := make(map[string]struct{})
	s := &fanotifySource{
		log:      nopLogger{},
		roots:    make(map[string]map[string]struct{}),
		markMask: 0,
	}
	// Stand in for markOne: tests can't call fanotify_mark without a
	// live fd. Walk + record.
	_, err := s.walkAndMarkVia(root, func(p string) error {
		visited[p] = struct{}{}
		return nil
	})
	return visited, err
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func totalMarks(s *fanotifySource) int {
	s.marksMu.Lock()
	defer s.marksMu.Unlock()
	var n int
	for _, m := range s.roots {
		n += len(m)
	}
	return n
}

func mkdir(t *testing.T, root string, parts ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(append([]string{root}, parts...)...), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
}

func mkfile(t *testing.T, root, rel string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, rel), []byte("x"), 0o644); err != nil {
		t.Fatalf("writefile: %v", err)
	}
}
