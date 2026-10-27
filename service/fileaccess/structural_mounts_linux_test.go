//go:build linux && !filemaster_test

package fileaccess

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/profile"
	"golang.org/x/sys/unix"
)

// mountCase is one policy and the operations checked under it. reference is
// computed from the engine unless an operation states its own.
type mountCase struct {
	name          string
	scopes        []string
	defaultAction uint8
	write         []PathRule
	warnings      map[string][]string
	undecided     map[string]bool
	operations    []mountOperation
}

type mountOperation struct {
	name string
	// paths are every absolute path the target is reachable at in the
	// daemon's mount namespace, for the engine reference.
	paths  []string
	op     DecisionOp
	folder bool
	// expect overrides the engine reference for a target that is by design
	// not decided at its path.
	expect *Verdict
	run    func() error
}

// TestStructuralBPFMounts checks the plan's filesystem matrix against the
// kernel: ext4 and tmpfs mounted inside a scope, a bind mount of a protected
// folder, a private mount namespace, and overlayfs. Overlay folders have no
// provable inode identity, so an overlay mount is not covered and is reported;
// the changes overlayfs makes in its upper layer are decided under that
// layer's own path. FM_BPF_MOUNTS=1 enables it, FM_BPF_DIFFERENTIAL_ROOT
// selects the filesystem the scope lives on.
func TestStructuralBPFMounts(t *testing.T) {
	if os.Getenv("FM_BPF_MOUNTS") != "1" {
		t.Skip("set FM_BPF_MOUNTS=1 to run the root-only BPF mount matrix")
	}
	if os.Geteuid() != 0 {
		t.Fatal("FM_BPF_MOUNTS requires root")
	}
	root := differentialRoot(t, 0)
	scope := filepath.Join(root, "scope")
	plain := filepath.Join(scope, "plain")
	ext4 := filepath.Join(scope, "ext4")
	tmp := filepath.Join(scope, "tmp")
	ovl := filepath.Join(scope, "ovl")
	upperScoped := filepath.Join(scope, "up2")
	layers := filepath.Join(root, "layers")
	merged2 := filepath.Join(root, "merged2")
	bindView := filepath.Join(root, "bind-view")
	nsView := filepath.Join(root, "ns-view")
	for _, dir := range []string{
		filepath.Join(plain, "allowed"), filepath.Join(plain, "covered"), ext4, tmp, ovl, merged2, bindView, nsView,
		filepath.Join(layers, "lower"), filepath.Join(layers, "upper"), filepath.Join(layers, "work"), filepath.Join(layers, "lower2"),
		filepath.Join(upperScoped, "upper"), filepath.Join(upperScoped, "work"),
	} {
		mustMkdirAll(t, dir)
	}
	image := filepath.Join(root, "ext4.img")
	file, err := os.Create(image)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	runCommand(t, "mkfs.ext4", "-q", "-F", image)
	mount := func(args ...string) {
		t.Helper()
		runCommand(t, "mount", args...)
		target := args[len(args)-1]
		t.Cleanup(func() { _ = unix.Unmount(target, unix.MNT_DETACH) })
	}
	mount("-o", "loop", image, ext4)
	mount("-t", "tmpfs", "tmpfs", tmp)
	mustWriteFile(t, filepath.Join(layers, "lower", "lower-file"))
	mustWriteFile(t, filepath.Join(layers, "upper", "upper-file"))
	mount("-t", "overlay", "overlay", "-o", "lowerdir="+filepath.Join(layers, "lower")+",upperdir="+filepath.Join(layers, "upper")+",workdir="+filepath.Join(layers, "work"), ovl)
	mustWriteFile(t, filepath.Join(layers, "lower2", "lower-file"))
	mustWriteFile(t, filepath.Join(upperScoped, "upper", "upper-file"))
	mount("-t", "overlay", "overlay", "-o", "lowerdir="+filepath.Join(layers, "lower2")+",upperdir="+filepath.Join(upperScoped, "upper")+",workdir="+filepath.Join(upperScoped, "work"), merged2)
	mount("--bind", plain, bindView)
	for _, dir := range []string{filepath.Join(ext4, "allowed"), filepath.Join(tmp, "allowed")} {
		mustMkdirAll(t, dir)
	}

	allow, deny := VerdictAllow, VerdictDeny
	remove := func(path string, aliases ...string) mountOperation {
		return mountOperation{name: "unlink " + path, paths: append([]string{path}, aliases...), op: DecisionDelete, run: func() error {
			if err := createIfAbsent(path); err != nil {
				return err
			}
			return os.Remove(path)
		}}
	}
	mkdir := func(path string, aliases ...string) mountOperation {
		return mountOperation{name: "mkdir " + path, paths: append([]string{path}, aliases...), op: DecisionCreate, folder: true, run: func() error {
			err := os.Mkdir(path, 0o700)
			if err == nil {
				_ = os.Remove(path)
			}
			return err
		}}
	}
	expect := func(operation mountOperation, verdict *Verdict) mountOperation {
		operation.expect = verdict
		return operation
	}
	// A private mount namespace: the kernel decides the object, whatever
	// path the namespace reaches it at.
	inNamespace := func(name string, verdict *Verdict, script string) mountOperation {
		return mountOperation{name: name, expect: verdict, run: func() error {
			out, err := exec.Command("unshare", "-m", "--propagation", "private", "sh", "-c", script).CombinedOutput()
			if strings.Contains(string(out), "Operation not permitted") {
				return unix.EPERM
			}
			if err != nil {
				return fmt.Errorf("%v: %s", err, out)
			}
			return nil
		}}
	}
	view := func(path string) string { return filepath.Join(bindView, strings.TrimPrefix(path, plain)) }
	allowedVictim, coveredVictim := filepath.Join(plain, "allowed", "victim"), filepath.Join(plain, "covered", "victim")
	nsTmpfs := filepath.Join(plain, "covered", "ns-tmpfs")
	mustMkdirAll(t, nsTmpfs)

	cases := []mountCase{
		{
			name:          "block-default",
			scopes:        []string{scope},
			defaultAction: profile.DefaultActionBlock,
			write: []PathRule{
				{Pattern: filepath.Join(plain, "allowed", "**"), Verdict: VerdictAllow},
				{Pattern: filepath.Join(ext4, "allowed", "**"), Verdict: VerdictAllow},
				{Pattern: filepath.Join(tmp, "allowed", "**"), Verdict: VerdictAllow},
			},
			warnings:  map[string][]string{"overlay-not-covered": {ovl + " (overlay)"}},
			undecided: map[string]bool{bpflsm.ReasonUnregisteredRoot: true},
			operations: []mountOperation{
				remove(allowedVictim, view(allowedVictim)),
				remove(coveredVictim, view(coveredVictim)),
				mkdir(filepath.Join(plain, "covered", "new"), view(filepath.Join(plain, "covered", "new"))),
				remove(view(allowedVictim), allowedVictim),
				remove(view(coveredVictim), coveredVictim),
				mkdir(view(filepath.Join(plain, "allowed", "new")), filepath.Join(plain, "allowed", "new")),
				remove(filepath.Join(ext4, "victim")),
				remove(filepath.Join(ext4, "allowed", "victim")),
				mkdir(filepath.Join(ext4, "new")),
				remove(filepath.Join(tmp, "victim")),
				remove(filepath.Join(tmp, "allowed", "victim")),
				mkdir(filepath.Join(tmp, "allowed", "new")),
				inNamespace("private namespace: bind of the scope, unlink a covered file", &deny,
					"touch "+coveredVictim+" && mount --bind "+plain+" "+nsView+" && rm -f "+filepath.Join(nsView, "covered", "victim")),
				inNamespace("private namespace: bind of the scope, unlink an allowed file", &allow,
					"touch "+allowedVictim+" && mount --bind "+plain+" "+nsView+" && rm -f "+filepath.Join(nsView, "allowed", "victim")),
				inNamespace("private namespace: own tmpfs over a covered folder (a new filesystem, not covered)", &allow,
					"mount -t tmpfs tmpfs "+nsTmpfs+" && touch "+nsTmpfs+"/f && rm "+nsTmpfs+"/f && mkdir "+nsTmpfs+"/d"),
				// The overlay mount itself is not covered (reported above);
				// its upper layer is outside every scope.
				expect(remove(filepath.Join(ovl, "upper-file")), &allow),
				expect(remove(filepath.Join(ovl, "lower-file")), &allow),
				expect(mkdir(filepath.Join(ovl, "new")), &allow),
				// The second overlay's merged view is outside every scope, but
				// its upper and work folders are in the scope: overlayfs's own
				// unlink, whiteout rename and mkdir there are decided under the
				// upper layer's paths, which deny by default.
				expect(remove(filepath.Join(merged2, "upper-file")), &deny),
				expect(remove(filepath.Join(merged2, "lower-file")), &deny),
				expect(mkdir(filepath.Join(merged2, "new")), &deny),
				// The layers themselves are ordinary folders.
				remove(filepath.Join(upperScoped, "upper", "direct")),
			},
		},
		{
			name:          "upper-layer-allowed",
			scopes:        []string{scope},
			defaultAction: profile.DefaultActionBlock,
			write:         []PathRule{{Pattern: filepath.Join(upperScoped, "**"), Verdict: VerdictAllow}},
			warnings:      map[string][]string{"overlay-not-covered": {ovl + " (overlay)"}},
			operations: []mountOperation{
				expect(remove(filepath.Join(merged2, "upper-file")), &allow),
				expect(remove(filepath.Join(merged2, "lower-file")), &allow),
				expect(mkdir(filepath.Join(merged2, "new")), &allow),
				remove(filepath.Join(upperScoped, "upper", "direct")),
				remove(filepath.Join(plain, "covered", "victim"), view(filepath.Join(plain, "covered", "victim"))),
			},
		},
	}

	zero := uint32(0)
	enforcer := bpflsm.NewEnforcerWithOptions(bpflsm.Options{
		PinRoot:     filepath.Join("/sys/fs/bpf", "filemaster-mounts-"+strconv.Itoa(os.Getpid())),
		SelfTestDir: filepath.Join(root, "selftest"),
		DaemonPID:   &zero,
	})
	defer func() {
		if err := enforcer.SetMode(bpflsm.ModeOff); err != nil {
			t.Errorf("detach: %v", err)
		}
	}()
	failures := runMountCases(t, enforcer, cases, root)
	if len(failures) > 0 {
		t.Fatalf("%d kernel verdicts or reports differ:\n%s", len(failures), strings.Join(failures, "\n"))
	}
}

func runMountCases(t *testing.T, enforcer *bpflsm.Enforcer, cases []mountCase, root string) []string {
	t.Helper()
	loaded := false
	var failures []string
	for _, c := range cases {
		snapshot := &DecisionSnapshot{DefaultAction: c.defaultAction, Write: PathRules{Rules: c.write}}
		var watch watchRuleSnapshot
		for _, scope := range c.scopes {
			watch.Rules = append(watch.Rules, watchRule{Path: scope})
		}
		table, warnings, err := bpflsm.Compile(bpflsm.Policy{
			Scopes: scopesFromWatchRules(&watch),
			Labels: []bpflsm.LabelPolicy{unidentifiedLabelPolicy(LookupResult{Snapshot: snapshot, DefaultAction: c.defaultAction})},
		})
		if err != nil {
			t.Fatalf("%s: compile: %v", c.name, err)
		}
		got := make(map[string][]string)
		for _, warning := range warnings {
			got[warning.ID] = warning.Patterns
		}
		for id, patterns := range c.warnings {
			if !slices.Equal(got[id], patterns) {
				failures = append(failures, fmt.Sprintf("%s: warning %s = %v, want %v", c.name, id, got[id], patterns))
			}
		}
		for id, patterns := range got {
			if _, ok := c.warnings[id]; !ok {
				failures = append(failures, fmt.Sprintf("%s: unexpected warning %s %v", c.name, id, patterns))
			}
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
		before := undecidedTotals(enforcer)
		for _, operation := range c.operations {
			reference := VerdictAllow
			if operation.expect != nil {
				reference = *operation.expect
			} else {
				for _, path := range operation.paths {
					_, covered := snapshot.Write.decideOperation(path, operation.op, operation.folder)
					for _, scope := range c.scopes {
						covered = covered || pathContains(scope, path)
					}
					if covered && snapshot.DecideOperation(path, operation.op, operation.folder) == VerdictDeny {
						reference = VerdictDeny
					}
				}
			}
			err := operation.run()
			kernel := VerdictAllow
			if errors.Is(err, unix.EPERM) {
				kernel = VerdictDeny
			} else if err != nil {
				t.Fatalf("%s: %s: %v", c.name, operation.name, err)
			}
			outcome := "ok"
			if kernel != reference {
				outcome = "MISMATCH"
				failures = append(failures, c.name+": "+operation.name+": kernel "+verdictName(kernel)+", want "+verdictName(reference))
			}
			t.Logf("mounts case=%s op=%s kernel=%s want=%s %s", c.name, strings.ReplaceAll(operation.name, root, ""), verdictName(kernel), verdictName(reference), outcome)
		}
		after := undecidedTotals(enforcer)
		for reason := range c.undecided {
			if after[reason] <= before[reason] {
				failures = append(failures, fmt.Sprintf("%s: undecided %s did not increase (%d)", c.name, reason, after[reason]))
			}
		}
	}
	return failures
}

func undecidedTotals(enforcer *bpflsm.Enforcer) map[string]uint64 {
	totals := make(map[string]uint64)
	for _, count := range enforcer.Status().Undecided {
		totals[count.Reason] += count.Count
	}
	return totals
}

// createIfAbsent never opens an existing file, so an overlay lower file is
// not copied up.
func createIfAbsent(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// TestStructuralBPFUnrepresentable checks the cases the kernel table cannot
// decide exactly (test requirement BPF-3): each denies, even under a policy
// that allows, and is counted and reported. A rule filepath.Match rejects never
// matches, as in the engine.
func TestStructuralBPFUnrepresentable(t *testing.T) {
	if os.Getenv("FM_BPF_MOUNTS") != "1" {
		t.Skip("set FM_BPF_MOUNTS=1 to run the root-only BPF unrepresentable-policy test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("FM_BPF_MOUNTS requires root")
	}
	root := differentialRoot(t, 1)
	over := filepath.Join(root, "over")
	deep := filepath.Join(root, "deep")
	long := filepath.Join(root, "long")
	bad := filepath.Join(root, "bad")
	for _, dir := range []string{over, deep, long, bad} {
		mustMkdirAll(t, dir)
	}
	// Every walk step adds at least two bytes ("/" and a name), so the
	// 8,192-byte relative-path limit is reached before the 4,096-step walk
	// limit: 4,100 one-letter folders and 33 255-byte names both exceed it.
	deepLeaf := nestedFolders(t, deep, "d", 4100)
	longLeaf := nestedFolders(t, long, strings.Repeat("n", 255), 33)
	defer func() {
		for _, dir := range []string{deep, long} {
			if err := os.RemoveAll(dir); err != nil {
				t.Errorf("remove %s: %v", dir, err)
			}
		}
	}()

	var rules []PathRule
	for i := range 300 {
		rules = append(rules, PathRule{Pattern: filepath.Join(over, fmt.Sprintf("f%03d", i)), Verdict: VerdictAllow})
	}
	// The valid rule makes bad an object of its own, outside the overflowed
	// contexts above it.
	rules = append(rules, PathRule{Pattern: filepath.Join(bad, "["), Verdict: VerdictAllow}, PathRule{Pattern: filepath.Join(bad, "other"), Verdict: VerdictDeny})
	allow, deny := VerdictAllow, VerdictDeny
	inLeaf := func(leaf int, run func(fd int) error) func() error {
		return func() error { return run(leaf) }
	}
	badTarget := filepath.Join(bad, "[")
	c := mountCase{
		name:          "unrepresentable",
		scopes:        []string{root},
		defaultAction: profile.DefaultActionPermit,
		write:         rules,
		warnings: map[string][]string{
			"pattern-never-matches": {filepath.Join(bad, "[")},
			"context-rule-overflow": func() []string {
				// The scope root's context can match every valid rule.
				var patterns []string
				for _, rule := range rules {
					if rule.Pattern != filepath.Join(bad, "[") {
						patterns = append(patterns, rule.Pattern)
					}
				}
				slices.Sort(patterns)
				return patterns
			}(),
		},
		undecided: map[string]bool{bpflsm.ReasonContextOverflow: true, bpflsm.ReasonPathTooLong: true},
		operations: []mountOperation{
			{name: "unlink in an overflowed context (rule allows)", expect: &deny, run: func() error {
				path := filepath.Join(over, "f001")
				if err := createIfAbsent(path); err != nil {
					return err
				}
				return os.Remove(path)
			}},
			{name: "mkdir 4,100 folders deep (default permits)", expect: &deny, run: inLeaf(deepLeaf, func(fd int) error { return unix.Mkdirat(fd, "new", 0o700) })},
			{name: "unlink 4,100 folders deep (default permits)", expect: &deny, run: inLeaf(deepLeaf, func(fd int) error { return unix.Unlinkat(fd, "leaf", 0) })},
			{name: "unlink below an 8,448-byte path (default permits)", expect: &deny, run: inLeaf(longLeaf, func(fd int) error { return unix.Unlinkat(fd, "leaf", 0) })},
			{name: "unlink a name only a rejected pattern names", expect: &allow, paths: []string{badTarget}, op: DecisionDelete, run: func() error {
				if err := createIfAbsent(badTarget); err != nil {
					return err
				}
				return os.Remove(badTarget)
			}},
		},
	}
	if (&DecisionSnapshot{DefaultAction: profile.DefaultActionPermit, Write: PathRules{Rules: rules}}).DecideOperation(badTarget, DecisionDelete, false) != VerdictAllow {
		t.Fatal("the engine no longer decides the rejected pattern's target by the default")
	}
	zero := uint32(0)
	enforcer := bpflsm.NewEnforcerWithOptions(bpflsm.Options{
		PinRoot:     filepath.Join("/sys/fs/bpf", "filemaster-unrepresentable-"+strconv.Itoa(os.Getpid())),
		SelfTestDir: filepath.Join(root, "selftest"),
		DaemonPID:   &zero,
	})
	failures := runMountCases(t, enforcer, []mountCase{c}, root)
	if err := enforcer.SetMode(bpflsm.ModeOff); err != nil {
		t.Errorf("detach: %v", err)
	}
	if len(failures) > 0 {
		t.Fatalf("%d kernel verdicts or reports differ:\n%s", len(failures), strings.Join(failures, "\n"))
	}
}

// nestedFolders makes count nested folders named name below dir, with a file
// "leaf" in the last, and returns a descriptor of the last.
func nestedFolders(t *testing.T, dir, name string, count int) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	for range count {
		if err := unix.Mkdirat(fd, name, 0o700); err != nil {
			t.Fatal(err)
		}
		next, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
		fd = next
	}
	leaf, err := unix.Openat(fd, "leaf", unix.O_CREAT|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(leaf)
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}
