//go:build linux && !filemaster_test

package bpflsm

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// The BPF-4 lifecycle matrix: after each injected failure the reported
// coverage must equal what the kernel actually enforces.

func lifecycleEnforcer(t *testing.T, root string, labelling bool) *Enforcer {
	t.Helper()
	zero := uint32(0)
	return NewEnforcerWithOptions(Options{
		PinRoot:     root,
		SelfTestDir: filepath.Join(t.TempDir(), "selftest"),
		DaemonPID:   &zero,
		Labelling:   labelling,
	})
}

func lifecycleRoot(t *testing.T, name string) string {
	t.Helper()
	root := "/sys/fs/bpf/filemaster-" + name + "-" + strconv.Itoa(os.Getpid())
	t.Cleanup(func() { _, _ = teardown(root) })
	return root
}

func allowAllTable(t *testing.T, dir string) Table {
	t.Helper()
	table, _, err := Compile(Policy{
		Scopes: []ScopeInput{{Path: dir}},
		Labels: []LabelPolicy{{Label: LabelUnidentified, DefaultAllow: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestLifecycleKillDuringPublish kills a daemon after it filled the inactive
// bank with an allow-everything table and before it flipped SETTINGS to it.
// The pinned generation must keep enforcing the old (deny) bank, and a
// restarted daemon must report exactly the table it then enforces.
func TestLifecycleKillDuringPublish(t *testing.T) {
	if os.Getenv("FM_LIFECYCLE_CHILD") == "publish" {
		lifecyclePublishChild(t)
		return
	}
	requireBPFLSM(t)
	root := lifecycleRoot(t, "kill-publish")
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	touch(t, victim)

	child := exec.Command(os.Args[0], "-test.run=^TestLifecycleKillDuringPublish$", "-test.v")
	child.Env = append(os.Environ(), "FM_LIFECYCLE_CHILD=publish", "FM_LIFECYCLE_ROOT="+root, "FM_LIFECYCLE_DIR="+dir)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	filled := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if bank, ok := strings.CutPrefix(scanner.Text(), "FILLED "); ok {
				filled <- bank
				return
			}
		}
		close(filled)
	}()
	var activeBank string
	select {
	case bank, ok := <-filled:
		if !ok {
			_ = child.Wait()
			t.Fatal("child exited before filling the inactive bank")
		}
		activeBank = bank
	case <-time.After(60 * time.Second):
		_ = child.Process.Kill()
		t.Fatal("child did not fill the inactive bank")
	}
	if err := child.Process.Signal(unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()

	generations, err := os.ReadDir(root)
	if err != nil || len(generations) != 1 {
		t.Fatalf("pinned generations after SIGKILL: %v %v", generations, err)
	}
	settings, err := ebpf.LoadPinnedMap(filepath.Join(root, generations[0].Name(), "SETTINGS"), nil)
	if err != nil {
		t.Fatal(err)
	}
	value := make([]byte, settingsSize)
	if err := settings.Lookup(uint32(0), value); err != nil {
		t.Fatal(err)
	}
	_ = settings.Close()
	if got := strconv.FormatUint(uint64(binary.LittleEndian.Uint32(value[16:])), 10); got != activeBank {
		t.Fatalf("active bank after SIGKILL = %s, want the pre-publish bank %s", got, activeBank)
	}
	if err := os.Remove(victim); !errors.Is(err, unix.EPERM) {
		t.Fatalf("unlink after SIGKILL between bank fill and flip: %v, want EPERM (old bank)", err)
	}

	restarted := lifecycleEnforcer(t, root, false)
	if err := restarted.SetModeWithTable(ModeEnforce, allowAllTable(t, dir)); err != nil {
		t.Fatalf("restart: %v", err)
	}
	defer restarted.SetMode(ModeOff)
	status := restarted.Status()
	if status.State != StateActive || len(status.OrphanedGenerations) > 0 || len(status.Retained) > 0 {
		t.Fatalf("restarted status = %+v", status)
	}
	if remaining, _ := os.ReadDir(root); len(remaining) != 1 || remaining[0].Name() != status.Generation {
		t.Fatalf("generations after restart = %v, want only %s", remaining, status.Generation)
	}
	if err := os.Remove(victim); err != nil {
		t.Fatalf("unlink under the restarted (allow) table: %v", err)
	}
	t.Logf("lifecycle kill-during-publish: old bank %s kept enforcing after SIGKILL; restart reported and enforced its own table", activeBank)
}

func lifecyclePublishChild(t *testing.T) {
	root, dir := os.Getenv("FM_LIFECYCLE_ROOT"), os.Getenv("FM_LIFECYCLE_DIR")
	e := lifecycleEnforcer(t, root, false)
	if err := e.SetModeWithTable(ModeEnforce, denyDeletesTable(t, dir)); err != nil {
		t.Fatalf("child start: %v", err)
	}
	e.mu.Lock()
	active := e.settings.bank
	if err := writeBank(e.collection.Maps, active^1, allowAllTable(t, dir)); err != nil {
		t.Fatalf("child fill: %v", err)
	}
	os.Stdout.WriteString("FILLED " + strconv.FormatUint(uint64(active), 10) + "\n")
	time.Sleep(time.Hour)
}

// TestLifecycleAttachFailure fails one structural hook's attach: the
// generation starts, reports exactly that hook unattached, and the kernel
// enforces every other hook but not that one. A failed labelling attach
// fails the whole start; an older pinned generation then keeps enforcing and
// is reported as retained.
func TestLifecycleAttachFailure(t *testing.T) {
	requireBPFLSM(t)
	dir := t.TempDir()
	failing := ""
	defer func() { attachLSM = link.AttachLSM }()
	attachLSM = func(options link.LSMOptions) (link.Link, error) {
		if failing != "" && strings.Contains(options.Program.String(), "("+failing+")") {
			return nil, errors.New("injected attach failure")
		}
		return link.AttachLSM(options)
	}

	root := lifecycleRoot(t, "attach")
	failing = "inode_rename"
	e := lifecycleEnforcer(t, root, false)
	if err := e.SetModeWithTable(ModeEnforce, denyDeletesTable(t, dir)); err != nil {
		t.Fatalf("start with one failed hook: %v", err)
	}
	status := e.Status()
	var unattached []string
	for _, hook := range status.Hooks {
		if !hook.Attached {
			unattached = append(unattached, hook.Program+": "+hook.Error)
		}
	}
	if status.State != StateActive || len(unattached) != 1 || !strings.HasPrefix(unattached[0], "inode_rename: injected") {
		t.Fatalf("status = %s, unattached = %v; want active with only inode_rename unattached", status.State, unattached)
	}
	source, renamed, victim := filepath.Join(dir, "source"), filepath.Join(dir, "renamed"), filepath.Join(dir, "victim")
	touch(t, source)
	touch(t, victim)
	if err := os.Remove(victim); !errors.Is(err, unix.EPERM) {
		t.Fatalf("unlink with its hook attached: %v, want EPERM", err)
	}
	if err := os.Rename(source, renamed); err != nil {
		t.Fatalf("rename with its hook reported unattached: %v, want allowed (unprotected as reported)", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "new"), 0o700); !errors.Is(err, unix.EPERM) {
		t.Fatalf("mkdir with its hook attached: %v, want EPERM", err)
	}
	e.Close()

	baseline, err := unlinkHooksAttached()
	if err != nil {
		t.Fatal(err)
	}
	failing = "bprm_committed_creds"
	labelled := lifecycleEnforcer(t, root, true)
	err = labelled.SetModeWithTable(ModeEnforce, allowAllTable(t, dir))
	status = labelled.Status()
	if err == nil || status.State != StateFailed || !slices.Equal(status.Retained, []string{e.status.Generation}) {
		t.Fatalf("labelling attach failure: err=%v state=%s retained=%v, want failed retaining %s", err, status.State, status.Retained, e.status.Generation)
	}
	for _, hook := range status.Hooks {
		if hook.Attached {
			t.Errorf("hook %s reported attached after a failed start", hook.Program)
		}
	}
	if count, err := unlinkHooksAttached(); err != nil || count != baseline {
		t.Fatalf("inode_unlink programs after the failed start = %d (%v), want %d: the failed generation must detach", count, err, baseline)
	}
	if err := os.Remove(renamed); !errors.Is(err, unix.EPERM) {
		t.Fatalf("unlink while the retained generation enforces: %v, want EPERM", err)
	}
	t.Logf("lifecycle attach: rename unattached and allowed, others denied; failed labelling attach retained %v, which still denies", status.Retained)
}

// TestLifecycleVerifierFailure loads an object whose inode_unlink program
// returns an uninitialised R0, so the verifier rejects the collection.
// Without an older generation nothing is attached and nothing is denied; with
// one, it is reported as retained and still enforces.
func TestLifecycleVerifierFailure(t *testing.T) {
	requireBPFLSM(t)
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	touch(t, victim)
	root := lifecycleRoot(t, "verifier")

	original := object
	defer func() { object = original }()
	corrupt := corruptObject(t, original, "lsm/inode_unlink")

	object = corrupt
	e := lifecycleEnforcer(t, root, false)
	err := e.SetModeWithTable(ModeEnforce, denyDeletesTable(t, dir))
	status := e.Status()
	if err == nil || status.State != StateFailed || len(status.Retained) != 0 || !strings.Contains(status.Error, "load BPF LSM object") {
		t.Fatalf("corrupt object, no older generation: err=%v state=%s retained=%v error=%q", err, status.State, status.Retained, status.Error)
	}
	if err := os.Remove(victim); err != nil {
		t.Fatalf("unlink with nothing attached: %v, want allowed (reported unprotected)", err)
	}

	object = original
	old := lifecycleEnforcer(t, root, false)
	if err := old.SetModeWithTable(ModeEnforce, denyDeletesTable(t, dir)); err != nil {
		t.Fatal(err)
	}
	old.Close()
	touch(t, victim)
	object = corrupt
	e = lifecycleEnforcer(t, root, false)
	err = e.SetModeWithTable(ModeEnforce, allowAllTable(t, dir))
	status = e.Status()
	if err == nil || status.State != StateFailed || !slices.Equal(status.Retained, []string{old.status.Generation}) {
		t.Fatalf("corrupt object over an older generation: err=%v state=%s retained=%v, want failed retaining %s", err, status.State, status.Retained, old.status.Generation)
	}
	if err := os.Remove(victim); !errors.Is(err, unix.EPERM) {
		t.Fatalf("unlink while the retained generation enforces: %v, want EPERM", err)
	}
	t.Logf("lifecycle verifier: %s", strings.SplitN(status.Error, "\n", 2)[0])
}

// corruptObject overwrites the first instruction of section with exit, so
// the program returns R0 before writing it.
func corruptObject(t *testing.T, original []byte, section string) []byte {
	t.Helper()
	file, err := elf.NewFile(bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	header := file.Section(section)
	if header == nil {
		t.Fatalf("object has no %s section", section)
	}
	corrupt := bytes.Clone(original)
	if corrupt[header.Offset] == 0x18 {
		t.Fatalf("%s starts with a wide instruction", section)
	}
	copy(corrupt[header.Offset:], []byte{0x95, 0, 0, 0, 0, 0, 0, 0})
	return corrupt
}

// TestRingOverflowKeepsDenials enforces without a ring reader, so the
// decision records fill the ring and then fail to reserve. Every denied
// operation must still be denied, and every decision must be either in the
// ring or counted as a drop.
func TestRingOverflowKeepsDenials(t *testing.T) {
	requireBPFLSM(t)
	dir := t.TempDir()
	allowed, denied := filepath.Join(dir, "allowed"), filepath.Join(dir, "denied")
	for _, sub := range []string{allowed, denied} {
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	table, _, err := Compile(Policy{
		Scopes: []ScopeInput{{Path: dir}},
		Labels: []LabelPolicy{{Label: LabelUnidentified, Rules: []RuleInput{
			{List: ListWrite, Pattern: allowed + "/**", Allow: true},
			{List: ListRead, Pattern: allowed + "/**", Allow: true},
			{List: ListExecute, Pattern: allowed + "/**", Allow: true},
			{List: ListWrite, Pattern: denied + "/**"},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	root := lifecycleRoot(t, "ring")
	e := lifecycleEnforcer(t, root, false)
	if err := e.SetModeWithTable(ModeEnforce, table); err != nil {
		t.Fatal(err)
	}
	defer e.SetMode(ModeOff)

	// The self-test's decisions are recorded too; drain them first.
	reader, err := ringbuf.NewReader(e.collection.Maps["RECORDS"])
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	drain := func() int {
		count := 0
		reader.SetDeadline(time.Now().Add(time.Second))
		for {
			if _, err := reader.Read(); err != nil {
				return count
			}
			count++
		}
	}
	drain()
	dropsBefore, err := decisionDropCount(e.collection)
	if err != nil {
		t.Fatal(err)
	}

	victim := filepath.Join(denied, "victim")
	touch(t, victim)
	source := filepath.Join(allowed, "source")
	touch(t, source)
	attempts, wrong := 0, 0
	deny := func(err error) {
		attempts++
		if !errors.Is(err, unix.EPERM) {
			wrong++
		}
	}
	allow := func(err error) {
		attempts++
		if err != nil {
			t.Fatalf("allowed operation failed: %v", err)
		}
	}
	deadline := time.Now().Add(4 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		deny(os.Remove(victim))
		deny(os.Mkdir(filepath.Join(denied, "d"), 0o700))
		deny(os.Rename(victim, filepath.Join(denied, "r")))
		deny(os.Link(victim, filepath.Join(denied, "l")))
		name := filepath.Join(allowed, "n"+strconv.Itoa(i))
		allow(os.Mkdir(name, 0o700))
		allow(os.Remove(name))
		allow(os.Link(source, name))
		allow(os.Rename(name, name+"r"))
		allow(os.Remove(name + "r"))
	}
	dropsAfter, err := decisionDropCount(e.collection)
	if err != nil {
		t.Fatal(err)
	}
	drops := dropsAfter - dropsBefore
	inRing := drain()
	if wrong != 0 {
		t.Fatalf("%d of the denied operations were allowed while the ring was full", wrong)
	}
	if inRing+int(drops) != attempts {
		t.Fatalf("decisions = %d, but %d records in the ring + %d counted drops = %d", attempts, inRing, drops, inRing+int(drops))
	}
	if inRing >= attempts/2 {
		t.Fatalf("the ring held %d of %d records; it never overflowed", inRing, attempts)
	}
	t.Logf("ring overflow: %d decisions, %d records in the ring, %d counted drops, 0 denials allowed", attempts, inRing, drops)
}
