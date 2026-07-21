//go:build linux

// Filemaster-specific: verifies Phase 2.5 mount attribution against the spec in
// docs/backend-todo-plan.md — every persisted record must carry the protected
// mount active at decision time, attribution must never guess, deepest mount
// wins, and pending reconciliation forces explicit unknown.
package fileaccess

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/safing/portmaster/service/filequery"
)

// newAttributionSource builds a fanotifySource with the given marks and pending
// state, then publishes the lock-free attribution snapshot the same way the
// reconciler does.
func newAttributionSource(pending bool, marks map[int]mountedMark) *fanotifySource {
	s := &fanotifySource{marks: marks, pending: pending}
	s.publishMountAttributionLocked()
	return s
}

func mark(id int, mountPoint string) mountedMark {
	return mountedMark{mount: mountInfo{ID: id, MountPoint: mountPoint}, mask: unix.FAN_OPEN_PERM}
}

func TestMountAttributionSingleHit(t *testing.T) {
	s := newAttributionSource(false, map[int]mountedMark{
		7: mark(7, "/home/user/enc"),
	})

	id, path := s.attributeMount("/home/user/enc/secret.txt")
	if id != 7 || path != "/home/user/enc" {
		t.Fatalf("expected (7, /home/user/enc), got (%d, %q)", id, path)
	}

	// The mount point itself is contained by the mount.
	if id, path := s.attributeMount("/home/user/enc"); id != 7 || path != "/home/user/enc" {
		t.Fatalf("mount point itself: expected (7, /home/user/enc), got (%d, %q)", id, path)
	}
}

func TestMountAttributionOutsideAnyMountIsUnknown(t *testing.T) {
	s := newAttributionSource(false, map[int]mountedMark{
		7: mark(7, "/home/user/enc"),
	})

	// A path outside every active mount must be explicit unknown, never guessed
	// to the one mount we happen to have.
	if id, path := s.attributeMount("/etc/passwd"); id != 0 || path != "" {
		t.Fatalf("outside mount: expected unknown (0, \"\"), got (%d, %q)", id, path)
	}

	// A sibling that merely shares a name prefix must not match (/home/user/encX
	// is not inside /home/user/enc).
	if id, path := s.attributeMount("/home/user/encrypted"); id != 0 || path != "" {
		t.Fatalf("prefix sibling: expected unknown (0, \"\"), got (%d, %q)", id, path)
	}
}

func TestMountAttributionNestedDeepestWins(t *testing.T) {
	s := newAttributionSource(false, map[int]mountedMark{
		1: mark(1, "/home"),
		2: mark(2, "/home/user/enc"),
	})

	// A path under the deeper mount attributes to the deeper mount, not /home.
	if id, path := s.attributeMount("/home/user/enc/file"); id != 2 || path != "/home/user/enc" {
		t.Fatalf("nested deepest: expected (2, /home/user/enc), got (%d, %q)", id, path)
	}

	// A path only under /home attributes to /home.
	if id, path := s.attributeMount("/home/other/file"); id != 1 || path != "/home" {
		t.Fatalf("shallow: expected (1, /home), got (%d, %q)", id, path)
	}
}

func TestMountAttributionBindMounts(t *testing.T) {
	// Two independent mount points (as bind mounts appear in mountinfo: distinct
	// IDs, distinct mount points). A path under one must attribute to that one.
	s := newAttributionSource(false, map[int]mountedMark{
		10: mark(10, "/mnt/a"),
		20: mark(20, "/mnt/b"),
	})

	if id, path := s.attributeMount("/mnt/a/doc"); id != 10 || path != "/mnt/a" {
		t.Fatalf("bind a: expected (10, /mnt/a), got (%d, %q)", id, path)
	}
	if id, path := s.attributeMount("/mnt/b/doc"); id != 20 || path != "/mnt/b" {
		t.Fatalf("bind b: expected (20, /mnt/b), got (%d, %q)", id, path)
	}
}

func TestMountAttributionRootCatchAllButDeeperWins(t *testing.T) {
	s := newAttributionSource(false, map[int]mountedMark{
		1: mark(1, "/"),
		2: mark(2, "/home/user/enc"),
	})

	// Deeper mount still wins over the root catch-all.
	if id, path := s.attributeMount("/home/user/enc/file"); id != 2 || path != "/home/user/enc" {
		t.Fatalf("deeper over root: expected (2, /home/user/enc), got (%d, %q)", id, path)
	}

	// A path not under the deeper mount falls back to root.
	if id, path := s.attributeMount("/var/log/syslog"); id != 1 || path != "/" {
		t.Fatalf("root catch-all: expected (1, /), got (%d, %q)", id, path)
	}
}

func TestMountAttributionPendingIsUnknown(t *testing.T) {
	// Even with marks populated, a pending reconciliation must report unknown:
	// the mount set is changing and attribution must not trust it.
	s := newAttributionSource(true, map[int]mountedMark{
		7: mark(7, "/home/user/enc"),
	})

	if id, path := s.attributeMount("/home/user/enc/secret.txt"); id != 0 || path != "" {
		t.Fatalf("pending: expected unknown (0, \"\"), got (%d, %q)", id, path)
	}
}

func TestMountAttributionUnmountReflectedAfterRepublish(t *testing.T) {
	s := newAttributionSource(false, map[int]mountedMark{
		1: mark(1, "/home"),
		2: mark(2, "/home/user/enc"),
	})

	// Baseline: deeper mount attributes.
	if id, _ := s.attributeMount("/home/user/enc/file"); id != 2 {
		t.Fatalf("baseline: expected id 2, got %d", id)
	}

	// Unmount the deeper mount and republish the snapshot.
	delete(s.marks, 2)
	s.publishMountAttributionLocked()

	// The path now attributes to the remaining ancestor mount, never to the
	// removed mount.
	if id, path := s.attributeMount("/home/user/enc/file"); id != 1 || path != "/home" {
		t.Fatalf("after unmount deeper: expected (1, /home), got (%d, %q)", id, path)
	}

	// Unmount the ancestor too: now the path is explicit unknown.
	delete(s.marks, 1)
	s.publishMountAttributionLocked()

	if id, path := s.attributeMount("/home/user/enc/file"); id != 0 || path != "" {
		t.Fatalf("after unmount all: expected unknown (0, \"\"), got (%d, %q)", id, path)
	}
}

func TestMountAttributionDynamicMountReflectedAfterRepublish(t *testing.T) {
	s := newAttributionSource(false, map[int]mountedMark{
		1: mark(1, "/home"),
	})

	if id, _ := s.attributeMount("/home/user/enc/file"); id != 1 {
		t.Fatalf("baseline: expected id 1, got %d", id)
	}

	// A new nested mount is discovered; after republish the deeper mount wins.
	s.marks[2] = mark(2, "/home/user/enc")
	s.publishMountAttributionLocked()

	if id, path := s.attributeMount("/home/user/enc/file"); id != 2 || path != "/home/user/enc" {
		t.Fatalf("after dynamic mount: expected (2, /home/user/enc), got (%d, %q)", id, path)
	}
}

// TestRecordingHandlerCarriesMountAttribution verifies the bridge copies the
// event's MountID/MountPath onto the persisted FileAccessRecord (spec: every
// record must carry the mount active at decision time).
func TestRecordingHandlerCarriesMountAttribution(t *testing.T) {
	feed := make(chan filequery.FileAccessRecord, 1)
	inner := HandlerFunc(func(context.Context, *FileEvent) Verdict { return VerdictAllow })
	h := NewRecordingHandler(inner, feed)

	e := &FileEvent{
		PID:       1234,
		Exe:       "/usr/bin/cat",
		Path:      "/home/user/enc/secret.txt",
		Op:        OpOpen,
		MountID:   42,
		MountPath: "/home/user/enc",
	}

	h.(interface {
		Observe(*FileEvent, Verdict)
	}).Observe(e, VerdictAllow)

	select {
	case rec := <-feed:
		if rec.MountID != 42 || rec.MountPath != "/home/user/enc" {
			t.Fatalf("record mount: expected (42, /home/user/enc), got (%d, %q)", rec.MountID, rec.MountPath)
		}
		if rec.Path != e.Path {
			t.Fatalf("record path: expected %q, got %q", e.Path, rec.Path)
		}
	default:
		t.Fatal("no record was pushed to the feed")
	}
}

// TestRecordingHandlerUnknownMountStoredExplicitly verifies an unknown mount
// (0 / "") is forwarded verbatim, not inferred (spec: unavailable attribution
// stored explicitly as unknown).
func TestRecordingHandlerUnknownMountStoredExplicitly(t *testing.T) {
	feed := make(chan filequery.FileAccessRecord, 1)
	h := NewRecordingHandler(HandlerFunc(func(context.Context, *FileEvent) Verdict { return VerdictAllow }), feed)

	e := &FileEvent{
		PID:  1,
		Path: "/etc/passwd",
		Op:   OpOpen,
		// MountID/MountPath left zero: unknown.
	}
	h.(interface {
		Observe(*FileEvent, Verdict)
	}).Observe(e, VerdictAllow)

	select {
	case rec := <-feed:
		if rec.MountID != 0 || rec.MountPath != "" {
			t.Fatalf("unknown mount: expected (0, \"\"), got (%d, %q)", rec.MountID, rec.MountPath)
		}
	default:
		t.Fatal("no record was pushed to the feed")
	}
}
