//go:build linux && !filemaster_test

package bpflsm

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func testEnforcer(t *testing.T, root string) *Enforcer {
	t.Helper()
	e := NewEnforcer()
	e.pinRoot = root
	e.selfTestDir = filepath.Join(t.TempDir(), "selftest")
	return e
}

func generationLinks(t *testing.T, dir string) []link.ID {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read generation %s: %v", dir, err)
	}
	var ids []link.ID
	for _, entry := range entries {
		l, err := link.LoadPinnedLink(filepath.Join(dir, entry.Name()), nil)
		if err != nil {
			continue
		}
		info, err := l.Info()
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, info.ID)
		_ = l.Close()
	}
	return ids
}

// unlinkHooksAttached counts attached links running an inode_unlink program.
func unlinkHooksAttached() (int, error) {
	it := new(link.Iterator)
	defer it.Close()
	count := 0
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil {
			continue
		}
		program, err := ebpf.NewProgramFromID(info.Program)
		if err != nil {
			continue
		}
		programInfo, err := program.Info()
		_ = program.Close()
		if err == nil && programInfo.Name == "inode_unlink" {
			count++
		}
	}
	return count, it.Err()
}

func TestEnforcerLifecycle(t *testing.T) {
	requireBPFLSM(t)
	root := "/sys/fs/bpf/filemaster-test-" + strconv.Itoa(os.Getpid())
	t.Cleanup(func() { _, _ = teardown(root) })
	baseline, err := unlinkHooksAttached()
	if err != nil {
		t.Fatal(err)
	}

	first := testEnforcer(t, root)
	if err := first.SetMode(ModeAudit); err != nil {
		t.Fatalf("start: %v", err)
	}
	status := first.Status()
	if status.State != StateActive || status.Mode != ModeAudit {
		t.Fatalf("status = %+v, want active audit", status)
	}
	for _, hook := range status.Hooks {
		if !hook.Attached {
			t.Errorf("hook %s not attached: %s", hook.Program, hook.Error)
		}
	}
	firstDir := filepath.Join(root, status.Generation)
	firstLinks := generationLinks(t, firstDir)
	if len(firstLinks) != len(Hooks) {
		t.Fatalf("generation pins %d links, want %d", len(firstLinks), len(Hooks))
	}

	// The daemon dies: its handles go away, the pinned generation keeps
	// enforcing. Plant a deny table through the pinned maps to observe it.
	first.Close()
	protectedDir := t.TempDir()
	victim := filepath.Join(protectedDir, "victim")
	if err := os.WriteFile(victim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	pinned := make(map[string]*ebpf.Map)
	for _, name := range policyMaps {
		m, err := ebpf.LoadPinnedMap(filepath.Join(firstDir, name), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		pinned[name] = m
	}
	settings := pinned["SETTINGS"]
	if err := writeBank(pinned, 1, denyDeletesTable(t, protectedDir)); err != nil {
		t.Fatal(err)
	}
	if err := settings.Put(uint32(0), encodeSettings(0, 1, fileID{}, false)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(victim); !errors.Is(err, unix.EPERM) {
		t.Fatalf("unlink under the pinned generation after Close: got %v, want EPERM", err)
	}

	// A restarted daemon hands over: at no point is the unlink hook missing.
	var gap atomic.Bool
	stop := make(chan struct{})
	polled := make(chan struct{})
	go func() {
		defer close(polled)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if count, err := unlinkHooksAttached(); err == nil && count <= baseline {
				gap.Store(true)
			}
		}
	}()
	second := testEnforcer(t, root)
	err = second.SetMode(ModeEnforce)
	close(stop)
	<-polled
	if err != nil {
		t.Fatalf("handover: %v", err)
	}
	if gap.Load() {
		t.Error("observed no attached inode_unlink program during handover")
	}
	if _, err := os.Stat(firstDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("old generation still pinned: %v", err)
	}
	if err := waitDetached(firstLinks); err != nil {
		t.Errorf("old generation links: %v", err)
	}
	if err := os.Remove(victim); err != nil {
		t.Errorf("unlink after handover to an empty policy: %v", err)
	}
	if status := second.Status(); len(status.OrphanedGenerations) > 0 {
		t.Errorf("orphaned generations: %v", status.OrphanedGenerations)
	}

	secondLinks := generationLinks(t, filepath.Join(root, second.Status().Generation))
	if err := second.SetMode(ModeOff); err != nil {
		t.Fatalf("off: %v", err)
	}
	if status := second.Status(); status.State != StateOff {
		t.Errorf("status after off = %+v", status)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pin root still present after off: %v", err)
	}
	for _, id := range secondLinks {
		if _, err := link.NewFromID(id); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("link %d still attached after off: %v", id, err)
		}
	}
}

// TestEnforcerInitialTableHandover proves the M2 startup order: an old pinned
// deny table remains effective until the replacement's initial table has been
// published, pinned, and is ready to sweep it. This would catch a brief empty-
// bank allow window during daemon restart.
func TestEnforcerInitialTableHandover(t *testing.T) {
	requireBPFLSM(t)
	root := "/sys/fs/bpf/filemaster-table-handover-" + strconv.Itoa(os.Getpid())
	t.Cleanup(func() { _, _ = teardown(root) })

	protectedDir := t.TempDir()
	victim := filepath.Join(protectedDir, "victim")
	if err := os.WriteFile(victim, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	table := denyDeletesTable(t, protectedDir)
	zero := uint32(0)
	first := NewEnforcerWithOptions(Options{
		PinRoot:     root,
		SelfTestDir: filepath.Join(t.TempDir(), "first-selftest"),
		DaemonPID:   &zero,
	})
	if err := first.SetModeWithTable(ModeEnforce, table); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if err := os.Remove(victim); !errors.Is(err, unix.EPERM) {
		t.Fatalf("old generation policy before Close: got %v, want EPERM", err)
	}
	first.Close()

	var gap atomic.Bool
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := os.Remove(victim); err == nil {
				gap.Store(true)
				return
			}
		}
	}()

	second := NewEnforcerWithOptions(Options{
		PinRoot:     root,
		SelfTestDir: filepath.Join(t.TempDir(), "second-selftest"),
		DaemonPID:   &zero,
	})
	err := second.SetModeWithTable(ModeEnforce, table)
	close(stop)
	<-done
	if err != nil {
		t.Fatalf("handover: %v", err)
	}
	defer second.SetMode(ModeOff)
	if gap.Load() {
		t.Fatal("observed an allow window while replacing a pinned deny table")
	}
	if err := os.Remove(victim); !errors.Is(err, unix.EPERM) {
		t.Fatalf("replacement generation policy: got %v, want EPERM", err)
	}
}

// denyDeletesTable denies every Write-list operation in dir and allows by
// default.
func denyDeletesTable(t *testing.T, dir string) Table {
	t.Helper()
	table, _, err := Compile(Policy{
		Scopes:       []ScopeInput{{Path: dir}},
		Rules:        []RuleInput{{List: ListWrite, Pattern: dir + "/**"}},
		DefaultAllow: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return table
}
