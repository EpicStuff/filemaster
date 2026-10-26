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
	"testing"

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

func command(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}
