//go:build linux

package fileaccess

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseMountInfo(t *testing.T) {
	mounts, err := parseMountInfo("36 25 0:32 / / rw - tmpfs tmpfs rw\n37 36 0:33 / /work\\040space rw - ext4 /dev/sda rw\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []mountInfo{{ID: 36, MountPoint: "/"}, {ID: 37, MountPoint: "/work space"}}
	if !reflect.DeepEqual(mounts, want) {
		t.Fatalf("mounts = %#v, want %#v", mounts, want)
	}
}

func TestDiscoverRequiredMountsIncludesNestedAndBindMounts(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	bind := filepath.Join(root, "bind")
	for _, path := range []string{nested, bind} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	scope, err := activateScope(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(scope.close)

	required, err := discoverRequiredMounts([]*policyScope{scope}, []mountInfo{
		{ID: 1, MountPoint: "/"},
		{ID: 2, MountPoint: nested},
		{ID: 3, MountPoint: bind},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := sortedMountIDs(required), []int{1, 2, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("required IDs = %v, want %v", got, want)
	}
}

func TestPathContainmentIsComponentAware(t *testing.T) {
	if !pathContains("/home/a", "/home/a/file") {
		t.Fatal("descendant should be in scope")
	}
	if pathContains("/home/a", "/home/abc/file") {
		t.Fatal("component prefix must not be in scope")
	}
	if !pathContains("/", "/anything") {
		t.Fatal("root must contain all absolute descendants")
	}
}

func TestConfiguredSymlinkIsResolvedAndMissingPathIsRejected(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	alias := filepath.Join(root, "alias")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	scope, err := activateScope(alias)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(scope.close)
	if scope.Configured != alias || scope.Canonical != target {
		t.Fatalf("scope = %#v, want configured %q and canonical %q", scope, alias, target)
	}

	missing := filepath.Join(root, "missing")
	if _, err := activateScope(missing); err == nil {
		t.Fatal("missing configured directory was accepted")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing path was created or stat failed unexpectedly: %v", err)
	}
}

func TestScopeReferenceRefreshesRenameAndRejectsDeletedPaths(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	renamed := filepath.Join(root, "renamed")
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}
	scope, err := activateScope(original)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(scope.close)
	if err := os.Rename(original, renamed); err != nil {
		t.Fatal(err)
	}
	if err := scope.refresh(); err != nil {
		t.Fatal(err)
	}
	if scope.Canonical != renamed {
		t.Fatalf("renamed canonical path = %q, want %q", scope.Canonical, renamed)
	}
	if err := os.Remove(renamed); err != nil {
		t.Fatal(err)
	}
	if err := scope.refresh(); err == nil {
		t.Fatal("deleted configured scope refreshed successfully")
	}
}

func TestDeletedEventPathIsUnresolved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "deleted")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, resolved := resolveEventPath("/proc/self/fd/" + strconv.Itoa(int(f.Fd()))); resolved {
		t.Fatal("deleted event path was treated as resolved")
	}
}

func TestMountReconciliationRetainsPartialCoverageAndRetries(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	failNested := true
	s := newReconciliationTestSource([]mountInfo{{ID: 1, MountPoint: "/"}, {ID: 2, MountPoint: nested}}, func(_ uint, _ uint64, path string) error {
		if path == nested && failNested {
			return errors.New("injected mark failure")
		}
		return nil
	})
	if err := s.SetWatchPaths([]string{root}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.marks[1]; !ok {
		t.Fatal("successful root mount mark was discarded")
	}
	if got := s.MountDiagnostics(); !got.PartialCoverage || !reflect.DeepEqual(got.MissingMountIDs, []int{2}) {
		t.Fatalf("partial diagnostics = %#v", got)
	}

	failNested = false
	s.reconcile()
	if got := s.MountDiagnostics(); got.PartialCoverage || len(got.MissingMountIDs) != 0 {
		t.Fatalf("retry diagnostics = %#v", got)
	}
	if _, ok := s.marks[2]; !ok {
		t.Fatal("failed mount was not retried")
	}
}

func TestScopeTransitionPublishesOnlyVerifiedNewScope(t *testing.T) {
	oldRoot := t.TempDir()
	newRoot := t.TempDir()
	var calls []string
	s := newReconciliationTestSource([]mountInfo{{ID: 1, MountPoint: "/"}, {ID: 2, MountPoint: oldRoot}, {ID: 3, MountPoint: newRoot}}, nil)
	s.mark = func(flags uint, _ uint64, path string) error {
		if flags&uint(unix.FAN_MARK_ADD) != 0 && path == newRoot {
			if !snapshotContains(s.activeScopes.Load(), oldRoot) || snapshotContains(s.activeScopes.Load(), newRoot) {
				t.Fatal("candidate scope became active before its new mount mark was verified")
			}
			if !s.pathInPendingScope(newRoot) {
				t.Fatal("candidate scope was not retained for deny-until-verified classification")
			}
		}
		if flags&uint(unix.FAN_MARK_REMOVE) != 0 && path == oldRoot && snapshotContains(s.activeScopes.Load(), oldRoot) {
			t.Fatal("obsolete mount was removed before the final scope was published")
		}
		calls = append(calls, path)
		return nil
	}
	if err := s.SetWatchPaths([]string{oldRoot}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetWatchPaths([]string{newRoot}); err != nil {
		t.Fatal(err)
	}
	if snapshotContains(s.activeScopes.Load(), oldRoot) || !snapshotContains(s.activeScopes.Load(), newRoot) {
		t.Fatal("final scope publication did not replace the old scope")
	}
	if len(calls) == 0 {
		t.Fatal("expected mount operations")
	}
}

func TestMountMaskChangesOnlyChangedBits(t *testing.T) {
	root := t.TempDir()
	var calls []struct {
		flags uint
		mask  uint64
	}
	s := newReconciliationTestSource([]mountInfo{{ID: 1, MountPoint: "/"}}, func(flags uint, mask uint64, _ string) error {
		calls = append(calls, struct {
			flags uint
			mask  uint64
		}{flags, mask})
		return nil
	})
	previous := cfgOptionInterceptReads
	cfgOptionInterceptReads = func() bool { return false }
	t.Cleanup(func() { cfgOptionInterceptReads = previous })
	if err := s.SetWatchPaths([]string{root}); err != nil {
		t.Fatal(err)
	}
	calls = nil
	cfgOptionInterceptReads = func() bool { return true }
	if err := s.SetWatchPaths([]string{root}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].flags&uint(unix.FAN_MARK_ADD) == 0 || calls[0].mask != uint64(unix.FAN_ACCESS_PERM) {
		t.Fatalf("read-mask add calls = %#v", calls)
	}
	calls = nil
	cfgOptionInterceptReads = func() bool { return false }
	if err := s.SetWatchPaths([]string{root}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].flags&uint(unix.FAN_MARK_REMOVE) == 0 || calls[0].mask != uint64(unix.FAN_ACCESS_PERM) {
		t.Fatalf("read-mask remove calls = %#v", calls)
	}
}

func newReconciliationTestSource(mounts []mountInfo, mark func(uint, uint64, string) error) *fanotifySource {
	if mark == nil {
		mark = func(uint, uint64, string) error { return nil }
	}
	return &fanotifySource{
		log:      nopLogger{},
		scopes:   make(map[string]*policyScope),
		marks:    make(map[int]mountedMark),
		markMask: resolveMarkMask(),
		mountInfo: func() ([]mountInfo, error) {
			return mounts, nil
		},
		mark: mark,
	}
}

func TestMountChangeNotificationReconcilesNestedMountImmediately(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	var mountsMu sync.Mutex
	mounts := []mountInfo{{ID: 1, MountPoint: "/"}, {ID: 2, MountPoint: root}}
	nestedMarked := make(chan struct{}, 1)
	s := newReconciliationTestSource(nil, nil)
	s.mountInfo = func() ([]mountInfo, error) {
		mountsMu.Lock()
		defer mountsMu.Unlock()
		return append([]mountInfo(nil), mounts...), nil
	}
	s.mark = func(_ uint, _ uint64, path string) error {
		if path == nested {
			select {
			case nestedMarked <- struct{}{}:
			default:
			}
		}
		return nil
	}

	scope, err := activateScope(root)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.close()
	s.scopes[root] = scope
	s.pending = true
	s.reconcile()

	ctx, cancel := context.WithCancel(context.Background())
	reconcileDone := make(chan error, 1)
	changes := make(chan struct{}, 1)
	go func() { reconcileDone <- s.runReconciliation(ctx, changes) }()

	mountsMu.Lock()
	mounts = append(mounts, mountInfo{ID: 3, MountPoint: nested})
	mountsMu.Unlock()
	changes <- struct{}{}

	select {
	case <-nestedMarked:
	case <-time.After(time.Second):
		t.Fatal("nested mount was not reconciled from the mount-change notification")
	}

	cancel()
	select {
	case err := <-reconcileDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reconciliation loop did not exit")
	}
}

func TestLateInScopeMountKeepsDynamicCoverageBreachAfterMarking(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	var mountsMu sync.Mutex
	mounts := []mountInfo{{ID: 1, MountPoint: "/"}, {ID: 2, MountPoint: root}}
	s := newReconciliationTestSource(nil, nil)
	s.lifecycle = NewPipelineLifecycle()
	s.mountInfo = func() ([]mountInfo, error) {
		mountsMu.Lock()
		defer mountsMu.Unlock()
		return append([]mountInfo(nil), mounts...), nil
	}
	scope, err := activateScope(root)
	if err != nil {
		t.Fatal(err)
	}
	defer scope.close()
	s.scopes[root] = scope
	s.marks[2] = mountedMark{mount: mounts[1], mask: s.markMask}
	s.activeScopes.Store(snapshotFromScopes(s.scopes))

	mountsMu.Lock()
	mounts = append(mounts, mountInfo{ID: 3, MountPoint: nested})
	mountsMu.Unlock()
	s.reconcile()

	diagnostics := s.MountDiagnostics()
	if !diagnostics.DynamicMountCoverageBreach || !diagnostics.PartialCoverage {
		t.Fatalf("late in-scope mount lost coverage breach: %#v", diagnostics)
	}
	if len(diagnostics.DynamicMountIDs) != 1 || diagnostics.DynamicMountIDs[0] != 3 {
		t.Fatalf("unexpected dynamic mount IDs: %#v", diagnostics.DynamicMountIDs)
	}
	if len(diagnostics.MissingMountIDs) != 0 {
		t.Fatalf("marked late mount should have prospective coverage: %#v", diagnostics.MissingMountIDs)
	}
	if diagnostics.LastError == "" {
		t.Fatal("late mount coverage breach has no actionable diagnostic")
	}

	// A clean later reconciliation cannot erase evidence that access could have
	// occurred before the new mount was marked.
	s.reconcile()
	diagnostics = s.MountDiagnostics()
	if !diagnostics.DynamicMountCoverageBreach || !diagnostics.PartialCoverage || diagnostics.LastError == "" {
		t.Fatalf("dynamic mount coverage breach was cleared after reconciliation: %#v", diagnostics)
	}
}

func TestMountReconcileFailureRecomputesCoverageDiagnostics(t *testing.T) {
	root := t.TempDir()
	s := newReconciliationTestSource([]mountInfo{{ID: 1, MountPoint: "/"}}, nil)
	if err := s.SetWatchPaths([]string{root}); err != nil {
		t.Fatal(err)
	}

	s.mountInfo = func() ([]mountInfo, error) {
		return nil, errors.New("mountinfo unavailable")
	}
	s.reconcile()

	got := s.MountDiagnostics()
	if !got.PartialCoverage || got.CoverageKnown {
		t.Fatalf("failure coverage state = %#v", got)
	}
	if got.LastError == "" {
		t.Fatal("failure diagnostics lost the mountinfo error")
	}
	if !reflect.DeepEqual(got.ConfiguredScopes, []string{root}) || !reflect.DeepEqual(got.CanonicalScopes, []string{root}) {
		t.Fatalf("failure diagnostics lost configured scope details: %#v", got)
	}
	if !reflect.DeepEqual(got.ActiveMountIDs, []int{1}) {
		t.Fatalf("failure diagnostics active mounts = %#v, want [1]", got.ActiveMountIDs)
	}
	if len(got.MissingMountIDs) != 0 {
		t.Fatalf("failure diagnostics retained stale missing mounts: %#v", got.MissingMountIDs)
	}
}

func snapshotContains(snapshot *scopeSnapshot, path string) bool {
	if snapshot == nil {
		return false
	}
	for _, scope := range snapshot.Scopes {
		if scope.Canonical == path {
			return true
		}
	}
	return false
}

func TestPhaseThreeMaskIncludesDirectoryEvents(t *testing.T) {
	previous := cfgOptionInterceptReads
	cfgOptionInterceptReads = nil
	t.Cleanup(func() { cfgOptionInterceptReads = previous })

	mask := resolveMarkMask()
	if mask&uint64(unix.FAN_ONDIR) == 0 {
		t.Fatalf("phase 3 mask = 0x%x, must include FAN_ONDIR", mask)
	}
	if mask&uint64(unix.FAN_EVENT_ON_CHILD) != 0 {
		t.Fatalf("phase 3 mount mask = 0x%x, must not include FAN_EVENT_ON_CHILD", mask)
	}
}

func TestEventScopeClassificationDoesNotAcquireReconciliationMutex(t *testing.T) {
	s := newReconciliationTestSource(nil, nil)
	s.activeScopes.Store(&scopeSnapshot{Scopes: []scopeMatch{{Canonical: "/watched"}}})
	s.marksMu.Lock()
	defer s.marksMu.Unlock()

	classified := make(chan bool, 1)
	go func() { classified <- s.pathInActiveScope("/watched/file") }()
	select {
	case inScope := <-classified:
		if !inScope {
			t.Fatal("path was not classified through the active snapshot")
		}
	case <-time.After(time.Second):
		t.Fatal("scope classification waited on the reconciliation mutex")
	}
}

func TestScopeSnapshotIsImmutableAfterSourceScopeRefresh(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	renamed := filepath.Join(root, "renamed")
	if err := os.Mkdir(original, 0o755); err != nil {
		t.Fatal(err)
	}
	scope, err := activateScope(original)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(scope.close)
	snapshot := snapshotFromScopes(map[string]*policyScope{scope.Configured: scope})
	if err := os.Rename(original, renamed); err != nil {
		t.Fatal(err)
	}
	if err := scope.refresh(); err != nil {
		t.Fatal(err)
	}
	if !snapshotContains(snapshot, original) || snapshotContains(snapshot, renamed) {
		t.Fatalf("snapshot changed after source scope refresh: %#v", snapshot)
	}
}

func TestBlockedReconciliationDoesNotBlockScopeClassification(t *testing.T) {
	oldRoot := t.TempDir()
	newRoot := t.TempDir()
	s := newReconciliationTestSource([]mountInfo{{ID: 1, MountPoint: "/"}, {ID: 2, MountPoint: oldRoot}, {ID: 3, MountPoint: newRoot}}, nil)
	if err := s.SetWatchPaths([]string{oldRoot}); err != nil {
		t.Fatal(err)
	}
	markStarted := make(chan struct{})
	releaseMark := make(chan struct{})
	s.mark = func(flags uint, _ uint64, path string) error {
		if flags&uint(unix.FAN_MARK_ADD) != 0 && path == newRoot {
			close(markStarted)
			<-releaseMark
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- s.SetWatchPaths([]string{newRoot}) }()
	select {
	case <-markStarted:
	case <-time.After(time.Second):
		t.Fatal("reconciliation did not reach the injected blocked mark")
	}

	classified := make(chan bool, 1)
	go func() { classified <- s.pathInActiveScope(filepath.Join(oldRoot, "file")) }()
	select {
	case inScope := <-classified:
		if !inScope {
			t.Fatal("union snapshot did not retain the old scope during reconciliation")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked reconciliation delayed scope classification")
	}
	close(releaseMark)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
