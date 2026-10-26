//go:build linux && !filemaster_test

package fileaccess

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/profile"
	"golang.org/x/sys/unix"
)

// TestStructuralBPFSubvolumes requires the kernel verdict to equal
// DecideOperation on a btrfs filesystem whose subvolumes and snapshot repeat
// inode numbers: every subvolume root is inode 256, the first directory made
// in a fresh subvolume is 257, and a snapshot keeps its source's numbers. A
// second mount of one subvolume adds a mount root that shares inode 256. It
// loop-mounts a new btrfs image, so the VM gate enables it with
// FM_BPF_SUBVOLUMES=1.
func TestStructuralBPFSubvolumes(t *testing.T) {
	if os.Getenv("FM_BPF_SUBVOLUMES") != "1" {
		t.Skip("set FM_BPF_SUBVOLUMES=1 to run the root-only btrfs subvolume test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("FM_BPF_SUBVOLUMES requires root")
	}

	base := t.TempDir()
	top := filepath.Join(base, "top")
	second := filepath.Join(base, "b-mount")
	mountBtrfs(t, filepath.Join(base, "image"), top, second)

	a, b, snap := filepath.Join(top, "a"), filepath.Join(top, "b"), filepath.Join(top, "a-snap")
	outside := filepath.Join(top, "outside")
	mustMkdirAll(t, outside)
	for _, path := range []string{filepath.Join(a, "d"), filepath.Join(b, "x")} {
		mustMkdirAll(t, path)
	}
	for _, path := range []string{filepath.Join(a, "d", "keep"), filepath.Join(b, "x", "keep")} {
		mustWriteFile(t, path)
	}
	runCommand(t, "btrfs", "subvolume", "snapshot", a, snap)
	runCommand(t, "mount", "-o", "subvol=b", btrfsDevice(t, top), second)
	t.Cleanup(func() { _ = unix.Unmount(second, unix.MNT_DETACH) })

	sameInode := func(paths ...string) {
		t.Helper()
		var first uint64
		for i, path := range paths {
			var st unix.Stat_t
			if err := unix.Stat(path, &st); err != nil {
				t.Fatal(err)
			}
			if i == 0 {
				first = st.Ino
			} else if st.Ino != first {
				t.Fatalf("setup: %s is inode %d, %s is %d; the test needs them to collide", paths[0], first, path, st.Ino)
			}
		}
	}
	sameInode(top, a, b, snap, second)
	sameInode(filepath.Join(a, "d"), filepath.Join(b, "x"), filepath.Join(snap, "d"), filepath.Join(second, "x"))

	type operation struct {
		name   string
		op     DecisionOp
		path   string
		folder bool
	}
	unlink := func(path string) operation { return operation{"unlink " + path, DecisionDelete, path, false} }
	mkdir := func(path string) operation { return operation{"mkdir " + path, DecisionCreate, path, true} }
	allowWrite := func(pattern string) PathRule { return PathRule{Pattern: pattern, Verdict: VerdictAllow} }
	denyWrite := func(pattern string) PathRule { return PathRule{Pattern: pattern, Verdict: VerdictDeny} }

	cases := []struct {
		name          string
		scopes        []string
		defaultAction uint8
		write         []PathRule
		operations    []operation
	}{
		{
			// Subvolume a is watched; b's root shares a's inode number.
			name:          "watched-subvolume-root",
			scopes:        []string{a},
			defaultAction: profile.DefaultActionBlock,
			operations: []operation{
				unlink(filepath.Join(b, "x", "victim")),
				unlink(filepath.Join(second, "x", "victim")),
				unlink(filepath.Join(snap, "d", "victim")),
				mkdir(filepath.Join(b, "new")),
				unlink(filepath.Join(a, "d", "victim")),
				mkdir(filepath.Join(a, "new")),
			},
		},
		{
			// b/x anchors an allow rule; a/d and a-snap/d share its inode number.
			name:          "rule-in-other-subvolume",
			scopes:        []string{top, second},
			defaultAction: profile.DefaultActionBlock,
			write:         []PathRule{allowWrite(filepath.Join(b, "x", "**"))},
			operations: []operation{
				unlink(filepath.Join(a, "d", "victim")),
				unlink(filepath.Join(snap, "d", "victim")),
				mkdir(filepath.Join(a, "d", "new")),
				unlink(filepath.Join(b, "x", "victim")),
				unlink(filepath.Join(second, "x", "victim")),
			},
		},
		{
			// The snapshot repeats a/d; only the source has a deny rule.
			name:          "snapshot-deny",
			scopes:        []string{top},
			defaultAction: profile.DefaultActionPermit,
			write:         []PathRule{denyWrite(filepath.Join(a, "d", "**"))},
			operations: []operation{
				unlink(filepath.Join(snap, "d", "victim")),
				mkdir(filepath.Join(snap, "d", "new")),
				unlink(filepath.Join(b, "x", "victim")),
				unlink(filepath.Join(a, "d", "victim")),
			},
		},
		{
			// The snapshot repeats a/d; only the source has an allow rule.
			name:          "snapshot-allow",
			scopes:        []string{top},
			defaultAction: profile.DefaultActionBlock,
			write:         []PathRule{allowWrite(filepath.Join(a, "d", "**"))},
			operations: []operation{
				unlink(filepath.Join(snap, "d", "victim")),
				unlink(filepath.Join(b, "x", "victim")),
				unlink(filepath.Join(a, "d", "victim")),
			},
		},
		{
			// The second mount's root is subvolume b; watching it must not cover a.
			name:          "watched-subvolume-mount",
			scopes:        []string{second},
			defaultAction: profile.DefaultActionBlock,
			operations: []operation{
				unlink(filepath.Join(a, "d", "victim")),
				unlink(filepath.Join(snap, "d", "victim")),
				unlink(filepath.Join(top, "outside", "victim")),
				unlink(filepath.Join(second, "x", "victim")),
			},
		},
	}

	zero := uint32(0)
	enforcer := bpflsm.NewEnforcerWithOptions(bpflsm.Options{
		PinRoot:     filepath.Join("/sys/fs/bpf", "filemaster-subvolumes-"+strconv.Itoa(os.Getpid())),
		SelfTestDir: filepath.Join(base, "selftest"),
		DaemonPID:   &zero,
	})
	defer func() {
		if err := enforcer.SetMode(bpflsm.ModeOff); err != nil {
			t.Errorf("detach: %v", err)
		}
	}()

	loaded := false
	var failures []string
	for _, c := range cases {
		snapshot := &DecisionSnapshot{DefaultAction: c.defaultAction, Write: PathRules{Rules: c.write}}
		var watch watchRuleSnapshot
		for _, scope := range c.scopes {
			watch.Rules = append(watch.Rules, watchRule{Path: scope})
		}
		table, _, err := bpflsm.Compile(bpflsm.Policy{
			Scopes: scopesFromWatchRules(&watch),
			Labels: []bpflsm.LabelPolicy{unidentifiedLabelPolicy(LookupResult{Snapshot: snapshot, DefaultAction: c.defaultAction})},
		})
		if err != nil {
			t.Fatalf("%s: compile: %v", c.name, err)
		}
		if !loaded {
			err = enforcer.SetModeWithTable(bpflsm.ModeEnforce, table)
			loaded = true
		} else {
			err = enforcer.Publish(table)
		}
		if err != nil {
			t.Fatalf("%s: publish: %v", c.name, err)
		}

		for _, operation := range c.operations {
			// The kernel decides a target at every path it is reachable at and
			// denies if any covered path denies; a path outside every scope
			// that no rule matches is not covered.
			reference := VerdictAllow
			for _, path := range []string{operation.path, aliasPath(operation.path, b, second)} {
				_, covered := snapshot.Write.decideOperation(path, operation.op, operation.folder)
				for _, scope := range c.scopes {
					covered = covered || pathContains(scope, path)
				}
				if covered && snapshot.DecideOperation(path, operation.op, operation.folder) == VerdictDeny {
					reference = VerdictDeny
				}
			}
			var got error
			if operation.op == DecisionDelete {
				// open(2) is not hooked, so the target can be made under enforcement.
				mustWriteFile(t, operation.path)
				got = os.Remove(operation.path)
			} else {
				got = os.Mkdir(operation.path, 0o700)
			}
			kernel := VerdictAllow
			if errors.Is(got, unix.EPERM) {
				kernel = VerdictDeny
			} else if got != nil {
				t.Fatalf("%s: %s: %v", c.name, operation.name, got)
			}
			outcome := "ok"
			if kernel != reference {
				outcome = "MISMATCH"
				failures = append(failures, c.name+": "+operation.name+": kernel "+verdictName(kernel)+", reference "+verdictName(reference))
			}
			t.Logf("subvolume case=%s op=%s kernel=%s reference=%s %s", c.name, strings.ReplaceAll(operation.name, base, ""), verdictName(kernel), verdictName(reference), outcome)
		}
	}
	if len(failures) > 0 {
		t.Fatalf("%d kernel verdicts differ from the engine:\n%s", len(failures), strings.Join(failures, "\n"))
	}
}

// aliasPath returns path's other name when it is inside subvolume b, which is
// also mounted at second.
func aliasPath(path, b, second string) string {
	switch {
	case pathContains(b, path):
		return second + strings.TrimPrefix(path, b)
	case pathContains(second, path):
		return b + strings.TrimPrefix(path, second)
	}
	return path
}

func verdictName(verdict Verdict) string {
	if verdict == VerdictAllow {
		return "allow"
	}
	return "deny"
}

// mountBtrfs makes a btrfs image with subvolumes a and b and mounts its top
// level at top, creating second as a mountpoint for later.
func mountBtrfs(t *testing.T, image, top, second string) {
	t.Helper()
	file, err := os.Create(image)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(256 << 20); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	runCommand(t, "mkfs.btrfs", "-q", "-f", image)
	mustMkdirAll(t, top)
	mustMkdirAll(t, second)
	runCommand(t, "mount", "-o", "loop", image, top)
	t.Cleanup(func() {
		device := btrfsDevice(t, top)
		_ = unix.Unmount(top, unix.MNT_DETACH)
		_ = exec.Command("losetup", "-d", device).Run()
	})
	runCommand(t, "btrfs", "subvolume", "create", filepath.Join(top, "a"))
	runCommand(t, "btrfs", "subvolume", "create", filepath.Join(top, "b"))
}

func btrfsDevice(t *testing.T, mountpoint string) string {
	t.Helper()
	out, err := exec.Command("findmnt", "-nro", "SOURCE", "--target", mountpoint).Output()
	if err != nil {
		t.Fatalf("findmnt %s: %v", mountpoint, err)
	}
	source := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	if i := strings.IndexByte(source, '['); i >= 0 {
		source = source[:i]
	}
	return source
}

func runCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}
