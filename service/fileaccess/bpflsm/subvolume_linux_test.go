//go:build linux && !filemaster_test

package bpflsm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestSubvolumeIdentityUnknownFailsClosed runs on a kernel whose btrfs layout
// the daemon pretends it cannot read: the kernel then sees every subvolume of
// a covered btrfs as one, so every structural operation on it must deny,
// counted and warned, while an uncovered btrfs and other filesystems are
// unaffected. It loop-mounts a btrfs image, so the VM gate enables it with
// FM_BPF_SUBVOLUMES=1.
func TestSubvolumeIdentityUnknownFailsClosed(t *testing.T) {
	if os.Getenv("FM_BPF_SUBVOLUMES") != "1" {
		t.Skip("set FM_BPF_SUBVOLUMES=1 to run the root-only btrfs subvolume test")
	}
	requireBPFLSM(t)

	base := t.TempDir()
	top := mountTestBtrfs(t, base)
	a, b := filepath.Join(top, "a"), filepath.Join(top, "b")
	command(t, "btrfs", "subvolume", "create", a)
	command(t, "btrfs", "subvolume", "create", b)
	for _, dir := range []string{filepath.Join(a, "d"), filepath.Join(b, "x")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(base, "other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}

	unknownLayout := func() (btrfsLayout, error) { return btrfsLayout{}, errors.New("unreadable for the test") }
	allowD := []RuleInput{{List: ListWrite, Pattern: filepath.Join(a, "d", "**"), Allow: true}}
	compile := func(scope string, rules []RuleInput) (Table, []CompileWarning) {
		t.Helper()
		table, warnings, err := Compile(Policy{
			Scopes: []ScopeInput{{Path: scope}},
			Labels: []LabelPolicy{{Label: LabelUnidentified, Rules: rules, DefaultAllow: true}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return table, warnings
	}
	unlink := func(path string) error {
		t.Helper()
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return os.Remove(path)
	}

	zero := uint32(0)
	root := "/sys/fs/bpf/filemaster-subvolume-unknown-" + strconv.Itoa(os.Getpid())
	t.Cleanup(func() { _, _ = teardown(root) })
	enforcer := NewEnforcerWithOptions(Options{PinRoot: root, SelfTestDir: filepath.Join(base, "selftest"), DaemonPID: &zero})
	defer enforcer.SetMode(ModeOff)

	btrfsLayoutSource = unknownLayout
	table, warnings := compile(a, allowD)
	btrfsLayoutSource = currentBtrfsLayout
	index := slices.IndexFunc(warnings, func(w CompileWarning) bool { return w.ID == "subvolume-identity-unknown" })
	if index < 0 || !slices.ContainsFunc(warnings[index].Patterns, func(p string) bool { return strings.HasPrefix(p, top+" ") }) {
		t.Fatalf("covered btrfs with an unknown layout: warnings %#v, want subvolume-identity-unknown naming %s", warnings, top)
	}
	if err := enforcer.SetModeWithTable(ModeEnforce, table); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(a, "d", "victim"), filepath.Join(b, "x", "victim"), filepath.Join(top, "victim")} {
		if err := unlink(path); !errors.Is(err, unix.EPERM) {
			t.Errorf("unknown layout, covered btrfs: unlink %s = %v, want EPERM", path, err)
		}
	}
	if err := unlink(filepath.Join(other, "victim")); err != nil {
		t.Errorf("unknown layout, other filesystem: unlink = %v, want allowed", err)
	}
	var counted uint64
	for _, count := range enforcer.Status().Undecided {
		if count.Reason == ReasonSubvolume {
			counted += count.Count
		}
	}
	if counted < 3 {
		t.Errorf("counted %d %s denials, want at least 3", counted, ReasonSubvolume)
	}

	btrfsLayoutSource = unknownLayout
	table, warnings = compile(other, []RuleInput{{List: ListWrite, Pattern: filepath.Join(other, "**")}})
	btrfsLayoutSource = currentBtrfsLayout
	if slices.ContainsFunc(warnings, func(w CompileWarning) bool { return w.ID == "subvolume-identity-unknown" }) {
		t.Errorf("uncovered btrfs with an unknown layout warned: %#v", warnings)
	}
	if err := enforcer.Publish(table); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(a, "d", "victim"), filepath.Join(b, "x", "victim")} {
		if err := unlink(path); err != nil {
			t.Errorf("unknown layout, uncovered btrfs: unlink %s = %v, want allowed", path, err)
		}
	}

	table, warnings = compile(a, allowD)
	if len(warnings) != 0 {
		t.Errorf("readable layout warned: %#v", warnings)
	}
	if err := enforcer.Publish(table); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(a, "d", "victim"), filepath.Join(b, "x", "victim")} {
		if err := unlink(path); err != nil {
			t.Errorf("readable layout: unlink %s = %v, want allowed", path, err)
		}
	}
}

// TestExecLabelsKeySubvolume learns the label of an executable in a btrfs
// subvolume, then runs the same file's copy in a snapshot, which has the same
// device, inode number and generation in another subvolume: the snapshot's
// copy must not inherit the learned label.
func TestExecLabelsKeySubvolume(t *testing.T) {
	if os.Getenv("FM_BPF_SUBVOLUMES") != "1" {
		t.Skip("set FM_BPF_SUBVOLUMES=1 to run the root-only btrfs subvolume test")
	}
	requireBPFLSM(t)
	rm, err := exec.LookPath("rm")
	if err != nil {
		t.Skip("rm is not installed")
	}
	base := t.TempDir()
	top := mountTestBtrfs(t, base)
	a, snap := filepath.Join(top, "a"), filepath.Join(top, "a-snap")
	command(t, "btrfs", "subvolume", "create", a)
	command(t, "cp", rm, filepath.Join(a, "rm"))
	command(t, "btrfs", "subvolume", "snapshot", a, snap)
	var source, copied unix.Stat_t
	if unix.Stat(filepath.Join(a, "rm"), &source) != nil || unix.Stat(filepath.Join(snap, "rm"), &copied) != nil || source.Ino != copied.Ino {
		t.Fatalf("setup: %s and its snapshot copy must share an inode number (%d, %d)", filepath.Join(a, "rm"), source.Ino, copied.Ino)
	}

	scope := filepath.Join(base, "scope")
	if err := os.Mkdir(scope, 0o700); err != nil {
		t.Fatal(err)
	}
	table, _, err := Compile(Policy{
		Scopes: []ScopeInput{{Path: scope}},
		Labels: []LabelPolicy{{Label: 1, Rules: []RuleInput{{List: ListWrite, Pattern: scope + "/**", Allow: true}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var enf *Enforcer
	var learn atomic.Bool
	pid := uint32(os.Getpid())
	enf = NewEnforcerWithOptions(Options{
		PinRoot:     "/sys/fs/bpf/filemaster-exec-subvolume-" + strconv.Itoa(os.Getpid()),
		SelfTestDir: filepath.Join(base, "selftest"),
		DaemonPID:   &pid,
		Labelling:   true,
		OnRecord: func(record Record) {
			if record.Kind == RecordExec && learn.Load() {
				_ = enf.LearnExec(record.Exe, ExecFile{}, 1)
				_ = enf.Resolve(record.TGID, record.Start, record.Seq, 1)
			}
		},
	})
	t.Cleanup(func() { _ = enf.SetMode(ModeOff) })
	if err := enf.SetModeWithTable(ModeEnforce, table); err != nil {
		t.Fatalf("enforce: %v", err)
	}
	// Without the wait a pending caller is denied at once.
	enf.SetLabelWait(false)
	deadline := time.Now().Add(5 * time.Second)
	for enf.Status().Labelling.Wait.State != WaitOffConfig && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	remove := func(binary string) bool {
		victim := filepath.Join(scope, "victim")
		if err := os.WriteFile(victim, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = exec.Command(binary, "-f", victim).Run()
		_, err := os.Stat(victim)
		return errors.Is(err, os.ErrNotExist)
	}

	learn.Store(true)
	learned := false
	for deadline := time.Now().Add(5 * time.Second); !learned && time.Now().Before(deadline); {
		learned = remove(filepath.Join(a, "rm"))
	}
	learn.Store(false)
	if !learned {
		t.Fatal("the source executable's label was never learned")
	}
	if remove(filepath.Join(snap, "rm")) {
		t.Fatal("the snapshot's copy ran with the label learned for its source")
	}
	if !remove(filepath.Join(a, "rm")) {
		t.Fatal("the source executable lost its learned label")
	}
}

// mountTestBtrfs loop-mounts a fresh btrfs below base and returns its top.
func mountTestBtrfs(t *testing.T, base string) string {
	t.Helper()
	top := filepath.Join(base, "top")
	image := filepath.Join(base, "image")
	file, err := os.Create(image)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(256 << 20); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if err := os.Mkdir(top, 0o700); err != nil {
		t.Fatal(err)
	}
	command(t, "mkfs.btrfs", "-q", "-f", image)
	command(t, "mount", "-o", "loop", image, top)
	t.Cleanup(func() {
		out, _ := exec.Command("findmnt", "-nro", "SOURCE", "--target", top).Output()
		_ = unix.Unmount(top, unix.MNT_DETACH)
		if device := strings.TrimSpace(string(out)); strings.HasPrefix(device, "/dev/loop") {
			_ = exec.Command("losetup", "-d", device).Run()
		}
	})
	return top
}

func command(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}
