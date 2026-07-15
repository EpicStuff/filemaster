//go:build linux

package fileaccess

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type mountInfo struct {
	ID         int
	MountPoint string
}

type policyScope struct {
	Configured string
	Canonical  string
	refFD      int
}

// scopeMatch is immutable data used only by the event reader.
type scopeMatch struct {
	Configured string
	Canonical  string
}

type scopeSnapshot struct {
	Scopes []scopeMatch
}

type mountedMark struct {
	mount mountInfo
	mask  uint64
}

// MountDiagnostics is a compact snapshot of mount-mark coverage. It is kept
// deliberately independent from the later general diagnostics pipeline.
type MountDiagnostics struct {
	ConfiguredScopes []string
	CanonicalScopes  []string
	ActiveMountIDs   []int
	MissingMountIDs  []int
	PartialCoverage  bool
	LastError        string
}

func parseMountInfo(input string) ([]mountInfo, error) {
	scanner := bufio.NewScanner(strings.NewReader(input))
	var mounts []mountInfo
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			return nil, fmt.Errorf("malformed mountinfo line %q", scanner.Text())
		}
		id, err := strconv.Atoi(fields[0])
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("invalid mount ID %q", fields[0])
		}
		mountPoint, err := normalizePath(unescapeMountInfoPath(fields[4]))
		if err != nil {
			return nil, fmt.Errorf("mount %d path: %w", id, err)
		}
		mounts = append(mounts, mountInfo{ID: id, MountPoint: mountPoint})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read mountinfo: %w", err)
	}
	return mounts, nil
}

func unescapeMountInfoPath(path string) string {
	return strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	).Replace(path)
}

func readMountInfo() ([]mountInfo, error) {
	contents, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("read /proc/self/mountinfo: %w", err)
	}
	return parseMountInfo(string(contents))
}

func normalizePath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute")
	}
	return filepath.Clean(path), nil
}

func pathContains(scope, path string) bool {
	return path == scope || (scope == "/" || strings.HasPrefix(path, scope+"/"))
}

func activateScope(configured string) (*policyScope, error) {
	configured, err := normalizePath(strings.TrimSpace(configured))
	if err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(configured)
	if err != nil {
		return nil, fmt.Errorf("resolve configured path %q: %w", configured, err)
	}
	canonical, err = normalizePath(canonical)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(canonical)
	if err != nil {
		return nil, fmt.Errorf("stat configured path %q: %w", configured, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("configured path %q is not a directory", configured)
	}
	fd, err := unix.Open(canonical, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open configured path %q: %w", configured, err)
	}
	return &policyScope{Configured: configured, Canonical: canonical, refFD: fd}, nil
}

func (scope *policyScope) refresh() error {
	if scope.refFD < 0 {
		return errors.New("scope reference is closed")
	}
	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", scope.refFD))
	if err != nil {
		return fmt.Errorf("refresh scope %q: %w", scope.Configured, err)
	}
	if strings.HasSuffix(path, " (deleted)") {
		return fmt.Errorf("configured scope %q was deleted", scope.Configured)
	}
	path, err = normalizePath(path)
	if err != nil {
		return fmt.Errorf("refresh scope %q: %w", scope.Configured, err)
	}
	scope.Canonical = path
	return nil
}

func (scope *policyScope) close() {
	if scope.refFD >= 0 {
		_ = unix.Close(scope.refFD)
		scope.refFD = -1
	}
}

func discoverRequiredMounts(scopes []*policyScope, mounts []mountInfo) (map[int]mountInfo, error) {
	required := make(map[int]mountInfo)
	for _, scope := range scopes {
		if err := scope.refresh(); err != nil {
			return nil, err
		}
		var containing *mountInfo
		for i := range mounts {
			mount := mounts[i]
			if pathContains(scope.Canonical, mount.MountPoint) {
				required[mount.ID] = mount
			}
			if pathContains(mount.MountPoint, scope.Canonical) && (containing == nil || len(mount.MountPoint) > len(containing.MountPoint)) {
				containing = &mount
			}
		}
		if containing == nil {
			return nil, fmt.Errorf("no containing mount for configured scope %q", scope.Canonical)
		}
		required[containing.ID] = *containing
	}
	return required, nil
}

func unionScopes(current, desired *scopeSnapshot) *scopeSnapshot {
	byConfigured := make(map[string]scopeMatch)
	for _, snapshot := range []*scopeSnapshot{current, desired} {
		if snapshot == nil {
			continue
		}
		for _, scope := range snapshot.Scopes {
			byConfigured[scope.Configured] = scope
		}
	}
	configured := make([]string, 0, len(byConfigured))
	for path := range byConfigured {
		configured = append(configured, path)
	}
	sort.Strings(configured)
	union := &scopeSnapshot{Scopes: make([]scopeMatch, 0, len(configured))}
	for _, path := range configured {
		union.Scopes = append(union.Scopes, byConfigured[path])
	}
	return union
}

func sortedMountIDs(mounts map[int]mountInfo) []int {
	ids := make([]int, 0, len(mounts))
	for id := range mounts {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func snapshotFromScopes(scopes map[string]*policyScope) *scopeSnapshot {
	configured := make([]string, 0, len(scopes))
	for path := range scopes {
		configured = append(configured, path)
	}
	sort.Strings(configured)
	snapshot := &scopeSnapshot{Scopes: make([]scopeMatch, 0, len(configured))}
	for _, path := range configured {
		scope := scopes[path]
		snapshot.Scopes = append(snapshot.Scopes, scopeMatch{Configured: scope.Configured, Canonical: scope.Canonical})
	}
	return snapshot
}

func mutableScopes(scopes map[string]*policyScope) []*policyScope {
	configured := make([]string, 0, len(scopes))
	for path := range scopes {
		configured = append(configured, path)
	}
	sort.Strings(configured)
	result := make([]*policyScope, 0, len(configured))
	for _, path := range configured {
		result = append(result, scopes[path])
	}
	return result
}

func (s *fanotifySource) prepareScopes(paths []string) (map[string]*policyScope, error) {
	next := make(map[string]*policyScope, len(paths))
	for _, configured := range paths {
		if strings.TrimSpace(configured) == "" {
			continue
		}
		cleaned, err := normalizePath(strings.TrimSpace(configured))
		if err != nil {
			closeNewScopes(next, s.scopes)
			return nil, err
		}
		if _, duplicate := next[cleaned]; duplicate {
			continue
		}
		if scope := s.scopes[cleaned]; scope != nil {
			if err := scope.refresh(); err != nil {
				closeNewScopes(next, s.scopes)
				return nil, err
			}
			next[cleaned] = scope
			continue
		}
		scope, err := activateScope(cleaned)
		if err != nil {
			closeNewScopes(next, s.scopes)
			return nil, err
		}
		next[cleaned] = scope
	}
	return next, nil
}

func closeNewScopes(scopes, existing map[string]*policyScope) {
	for configured, scope := range scopes {
		if existing[configured] != scope {
			scope.close()
		}
	}
}

func (s *fanotifySource) reconcile() {
	s.marksMu.Lock()
	defer s.marksMu.Unlock()
	s.reconcileLocked()
}

// RunReconciliation is a dedicated managed loop so mount discovery and mark
// syscalls never pause the fanotify event reader.
func (s *fanotifySource) RunReconciliation(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.reconcile()
		}
	}
}

func (s *fanotifySource) reconcileLocked() {
	mounts, err := s.mountInfo()
	if err != nil {
		s.recordReconcileFailure(err)
		return
	}
	required, err := discoverRequiredMounts(mutableScopes(s.scopes), mounts)
	if err != nil {
		s.recordReconcileFailure(err)
		return
	}
	desiredSnapshot := snapshotFromScopes(s.scopes)
	if s.pending {
		s.activeScopes.Store(unionScopes(s.activeScopes.Load(), desiredSnapshot))
	} else {
		s.activeScopes.Store(desiredSnapshot)
	}

	newMask := resolveMarkMask()
	var errs []error
	for id, mount := range required {
		current, marked := s.marks[id]
		if !marked {
			if err := s.mark(uint(unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT), newMask, mount.MountPoint); err != nil {
				errs = append(errs, fmt.Errorf("add mount %d at %s: %w", id, mount.MountPoint, err))
				continue
			}
			s.marks[id] = mountedMark{mount: mount, mask: newMask}
			continue
		}
		if added := newMask &^ current.mask; added != 0 {
			if err := s.mark(uint(unix.FAN_MARK_ADD|unix.FAN_MARK_MOUNT), added, mount.MountPoint); err != nil {
				errs = append(errs, fmt.Errorf("add mask bits for mount %d: %w", id, err))
			} else {
				current.mask |= added
			}
		}
		if removed := current.mask &^ newMask; removed != 0 {
			if err := s.mark(uint(unix.FAN_MARK_REMOVE|unix.FAN_MARK_MOUNT), removed, mount.MountPoint); err != nil {
				errs = append(errs, fmt.Errorf("remove mask bits for mount %d: %w", id, err))
			} else {
				current.mask &^= removed
			}
		}
		current.mount = mount
		s.marks[id] = current
	}

	complete := len(errs) == 0
	for id := range required {
		mark, ok := s.marks[id]
		if !ok || mark.mask != newMask {
			complete = false
		}
	}
	if complete && s.pending {
		s.activeScopes.Store(desiredSnapshot)
		s.pending = false
		s.closeRetiredScopes()
	}
	if complete {
		for id, mark := range s.marks {
			if _, keep := required[id]; keep {
				continue
			}
			if err := s.mark(uint(unix.FAN_MARK_REMOVE|unix.FAN_MARK_MOUNT), mark.mask, mark.mount.MountPoint); err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.EINVAL) {
				errs = append(errs, fmt.Errorf("remove mount %d: %w", id, err))
				continue
			}
			delete(s.marks, id)
		}
	}
	s.markMask = newMask
	s.updateDiagnostics(required, errs)
}

func (s *fanotifySource) closeRetiredScopes() {
	for _, scope := range s.retiredScopes {
		scope.close()
	}
	s.retiredScopes = nil
}

func (s *fanotifySource) recordReconcileFailure(err error) {
	s.diagnostics.LastError = err.Error()
	s.diagnostics.PartialCoverage = true
	s.log.Warn("fanotify mount reconciliation failed", "err", err)
}

func (s *fanotifySource) updateDiagnostics(required map[int]mountInfo, errs []error) {
	diagnostics := MountDiagnostics{}
	for _, scope := range snapshotFromScopes(s.scopes).Scopes {
		diagnostics.ConfiguredScopes = append(diagnostics.ConfiguredScopes, scope.Configured)
		diagnostics.CanonicalScopes = append(diagnostics.CanonicalScopes, scope.Canonical)
	}
	for id, mark := range s.marks {
		if _, required := required[id]; required && mark.mask == s.markMask {
			diagnostics.ActiveMountIDs = append(diagnostics.ActiveMountIDs, id)
		}
	}
	for id := range required {
		if mark, ok := s.marks[id]; !ok || mark.mask != s.markMask {
			diagnostics.MissingMountIDs = append(diagnostics.MissingMountIDs, id)
		}
	}
	sort.Ints(diagnostics.ActiveMountIDs)
	sort.Ints(diagnostics.MissingMountIDs)
	diagnostics.PartialCoverage = len(diagnostics.MissingMountIDs) > 0
	if len(errs) > 0 {
		diagnostics.LastError = errors.Join(errs...).Error()
		missingPaths := make([]string, 0, len(diagnostics.MissingMountIDs))
		for _, id := range diagnostics.MissingMountIDs {
			missingPaths = append(missingPaths, required[id].MountPoint)
		}
		s.log.Warn("fanotify mount coverage partial", "missing_mount_ids", diagnostics.MissingMountIDs, "missing_mount_paths", missingPaths, "errors", len(errs))
	}
	s.diagnostics = diagnostics
}

func (s *fanotifySource) MountDiagnostics() MountDiagnostics {
	s.marksMu.Lock()
	defer s.marksMu.Unlock()
	diagnostics := s.diagnostics
	diagnostics.ConfiguredScopes = append([]string(nil), diagnostics.ConfiguredScopes...)
	diagnostics.CanonicalScopes = append([]string(nil), diagnostics.CanonicalScopes...)
	diagnostics.ActiveMountIDs = append([]int(nil), diagnostics.ActiveMountIDs...)
	diagnostics.MissingMountIDs = append([]int(nil), diagnostics.MissingMountIDs...)
	return diagnostics
}

func (s *fanotifySource) pathInActiveScope(path string) bool {
	snapshot := s.activeScopes.Load()
	if snapshot == nil {
		return false
	}
	for _, scope := range snapshot.Scopes {
		if pathContains(scope.Canonical, path) {
			return true
		}
	}
	return false
}
