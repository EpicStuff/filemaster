//go:build linux && !filemaster_test

package fileaccess

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/profile"
	"golang.org/x/sys/unix"
)

// TestStructuralBPFDifferential is intentionally opt-in: it loads BPF LSM
// programs and mutates a real filesystem. The VM gate enables it with
// FM_BPF_DIFFERENTIAL=1 and selects tmpfs or btrfs through
// FM_BPF_DIFFERENTIAL_ROOT.
func TestStructuralBPFDifferential(t *testing.T) {
	if os.Getenv("FM_BPF_DIFFERENTIAL") != "1" {
		t.Skip("set FM_BPF_DIFFERENTIAL=1 to run the root-only BPF differential test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("FM_BPF_DIFFERENTIAL requires root")
	}

	cases := []struct {
		seed          int64
		defaultAction uint8
	}{
		{seed: 101, defaultAction: profile.DefaultActionNotSet},
		{seed: 211, defaultAction: profile.DefaultActionBlock},
		{seed: 307, defaultAction: profile.DefaultActionAsk},
		{seed: 401, defaultAction: profile.DefaultActionPermit},
	}
	coverage := make(map[Verdict]map[ObjectKind]bool)
	total := 0
	for variant, test := range cases {
		root := differentialRoot(t, test.seed)
		snapshot, rules := differentialSnapshot(root, test.seed, variant, test.defaultAction)
		operations := differentialOperations(t, root, snapshot, test.seed)
		for _, rule := range rules {
			if coverage[rule.Verdict] == nil {
				coverage[rule.Verdict] = make(map[ObjectKind]bool)
			}
			coverage[rule.Verdict][rule.ObjectKind] = true
		}
		inputs, warnings := structuralObjectInputs(
			[]string{filepath.Join(root, "scope-a"), filepath.Join(root, "scope-b")},
			snapshot,
		)
		if !onlyExpectedDifferentialWarnings(warnings) {
			t.Fatalf("seed=%d unexpected compiler warnings: %#v", test.seed, warnings)
		}
		table, err := bpflsm.Compile(
			inputs,
			structuralEvaluator(LookupResult{Snapshot: snapshot, DefaultAction: test.defaultAction}),
			structuralDefaultVerdict(LookupResult{DefaultAction: test.defaultAction}),
		)
		if err != nil {
			t.Fatalf("seed=%d compile: %v", test.seed, err)
		}

		zero := uint32(0)
		pinRoot := filepath.Join("/sys/fs/bpf", "filemaster-differential-"+strconv.Itoa(os.Getpid())+"-"+strconv.Itoa(variant))
		enforcer := bpflsm.NewEnforcerWithOptions(bpflsm.Options{
			PinRoot:     pinRoot,
			SelfTestDir: filepath.Join(root, "selftest"),
			DaemonPID:   &zero,
		})
		if err := enforcer.SetModeWithTable(bpflsm.ModeEnforce, table); err != nil {
			t.Fatalf("seed=%d load/enforce: %v", test.seed, err)
		}
		func() {
			defer func() {
				if err := enforcer.SetMode(bpflsm.ModeOff); err != nil {
					t.Errorf("seed=%d detach: %v", test.seed, err)
				}
			}()
			for _, operation := range operations {
				got := operation.run()
				total++
				assertDifferentialOutcome(t, test.seed, test.defaultAction, rules, operation, got)
			}
		}()
		t.Logf("M2 differential seed=%d default=%d cases=%d mismatches=0 excluded=glob-created-later", test.seed, test.defaultAction, len(operations))
	}
	for _, verdict := range []Verdict{VerdictAllow, VerdictDeny} {
		for _, kind := range []ObjectKind{ObjectKindAny, ObjectKindFile, ObjectKindFolder} {
			if !coverage[verdict][kind] {
				t.Errorf("generated differential rules did not cover verdict=%v kind=%v", verdict, kind)
			}
		}
	}
	t.Logf("M2 differential total cases=%d mismatches=0", total)
}

func differentialRoot(t *testing.T, seed int64) string {
	t.Helper()
	parent := os.Getenv("FM_BPF_DIFFERENTIAL_ROOT")
	if parent == "" {
		return t.TempDir()
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(parent, "filemaster-m2-"+strconv.FormatInt(seed, 10)+"-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}

func differentialSnapshot(root string, seed int64, variant int, defaultAction uint8) (*DecisionSnapshot, []PathRule) {
	scopeA := filepath.Join(root, "scope-a")
	scopeB := filepath.Join(root, "scope-b")
	allowTree := filepath.Join(scopeA, "allow")
	exact := filepath.Join(scopeA, "exact-"+strconv.FormatInt(seed, 10))
	recursive := filepath.Join(scopeA, "recursive-"+strconv.FormatInt(seed, 10), "**")
	glob := filepath.Join(scopeB, "glob-"+strconv.FormatInt(seed, 10)+"-?")
	folder := filepath.Join(scopeA, "folder-"+strconv.FormatInt(seed, 10))

	makeRule := func(shape int, pattern string) PathRule {
		verdict := []Verdict{VerdictAllow, VerdictDeny}[(variant+shape)%2]
		kind := []ObjectKind{ObjectKindAny, ObjectKindFile, ObjectKindFolder}[(variant+shape)%3]
		return PathRule{Pattern: pattern, Verdict: verdict, ObjectKind: kind}
	}
	common := []PathRule{
		{Pattern: filepath.Join(allowTree, "**"), Verdict: VerdictAllow, ObjectKind: ObjectKindAny},
		makeRule(0, exact),
		makeRule(1, recursive),
		makeRule(2, glob),
		{Pattern: folder, Verdict: []Verdict{VerdictDeny, VerdictAllow}[variant%2], ObjectKind: ObjectKindFolder},
	}
	clone := func() []PathRule { return append([]PathRule(nil), common...) }
	return &DecisionSnapshot{
		DefaultAction: defaultAction,
		Read:          PathRules{Rules: clone()},
		Write:         PathRules{Rules: clone()},
		Exec:          PathRules{Rules: clone()},
	}, common
}

func onlyExpectedDifferentialWarnings(warnings []bpflsm.CompileWarning) bool {
	if len(warnings) != 1 || warnings[0].ID != "glob-future-match" {
		return false
	}
	return len(warnings[0].Patterns) == 1
}

type differentialOperation struct {
	name      string
	reference Verdict
	run       func() error
}

func differentialOperations(t *testing.T, root string, snapshot *DecisionSnapshot, seedValue int64) []differentialOperation {
	t.Helper()
	scopeA := filepath.Join(root, "scope-a")
	scopeB := filepath.Join(root, "scope-b")
	outside := filepath.Join(root, "outside")
	allow := filepath.Join(scopeA, "allow")
	seed := strconv.FormatInt(seedValue, 10)
	for _, path := range []string{scopeA, scopeB, outside, allow} {
		mustMkdirAll(t, path)
	}

	file := func(name string) string {
		path := filepath.Join(allow, name)
		mustWriteFile(t, path)
		return path
	}
	dir := func(name string) string {
		path := filepath.Join(allow, name)
		mustMkdirAll(t, path)
		return path
	}
	outsideFile := func(name string) string {
		path := filepath.Join(outside, name)
		mustWriteFile(t, path)
		return path
	}

	// Materialize each generated rule shape before compiling the table. The
	// glob case is existing-only; future glob creations are deliberately
	// excluded from this differential matrix and reported in diagnostics.
	exactRulePath := filepath.Join(scopeA, "exact-"+seed)
	mustWriteFile(t, exactRulePath)
	mustMkdirAll(t, filepath.Join(scopeA, "recursive-"+seed))
	recursiveRulePath := filepath.Join(scopeA, "recursive-"+seed, "current")
	mustWriteFile(t, recursiveRulePath)
	globRulePath := filepath.Join(scopeB, "glob-"+seed+"-a")
	mustWriteFile(t, globRulePath)
	folderRulePath := filepath.Join(scopeA, "folder-"+seed)
	mustMkdirAll(t, folderRulePath)

	unlinkAllow := file("unlink")
	rmdirAllow := dir("rmdir")
	mkdirAllow := filepath.Join(allow, "mkdir")
	linkWithinSource := file("link-within-source")
	linkWithinDest := filepath.Join(allow, "link-within-dest")
	linkIntoSource := outsideFile("link-into-source")
	linkIntoDest := filepath.Join(allow, "link-into-dest")
	linkOutSource := file("link-out-source")
	linkOutDest := filepath.Join(outside, "link-out-dest")
	linkCrossSource := file("link-cross-source")
	linkCrossDest := filepath.Join(scopeB, "link-cross-dest")
	renameWithinSource := file("rename-within-source")
	renameWithinDest := filepath.Join(allow, "rename-within-dest")
	renameIntoSource := outsideFile("rename-into-source")
	renameIntoDest := filepath.Join(allow, "rename-into-dest")
	renameOutSource := file("rename-out-source")
	renameOutDest := filepath.Join(outside, "rename-out-dest")
	renameCrossSource := file("rename-cross-source")
	renameCrossDest := filepath.Join(scopeB, "rename-cross-dest")
	renameOverSource := file("rename-over-source")
	renameOverDest := file("rename-over-dest")
	atomicTemp := file("atomic-temp")
	atomicDest := file("atomic-dest")
	exchangeLeft := file("exchange-left")
	exchangeRight := file("exchange-right")
	noreplaceSource := file("noreplace-source")
	noreplaceDest := filepath.Join(allow, "noreplace-dest")
	unlinkAt := file("unlinkat")
	rmdirAt := dir("rmdirat")
	mkdirAt := "mkdirat"
	renameAtSource := file("renameat-source")
	renameAtDest := "renameat-dest"
	linkAtSource := file("linkat-source")
	linkAtDest := "linkat-dest"

	ref := func(path string, op DecisionOp, isDir bool) Verdict {
		return snapshot.DecideOperation(path, op, isDir)
	}
	rename := func(source, destination string, destinationExists bool) Verdict {
		return snapshot.DecideRename(RenameRequest{Source: source, Dest: destination, DestExists: destinationExists})
	}
	link := func(source, destination string) Verdict {
		return snapshot.DecideHardLink(LinkRequest{Source: source, Dest: destination})
	}
	exchange := func() Verdict {
		if rename(exchangeLeft, exchangeRight, true) == VerdictDeny {
			return VerdictDeny
		}
		return rename(exchangeRight, exchangeLeft, true)
	}

	return []differentialOperation{
		{name: "unlink-exact-rule", reference: ref(exactRulePath, DecisionDelete, false), run: func() error { return os.Remove(exactRulePath) }},
		{name: "unlink-recursive-rule", reference: ref(recursiveRulePath, DecisionDelete, false), run: func() error { return os.Remove(recursiveRulePath) }},
		{name: "unlink-current-glob", reference: ref(globRulePath, DecisionDelete, false), run: func() error { return os.Remove(globRulePath) }},
		{name: "rmdir-folder-rule", reference: ref(folderRulePath, DecisionDelete, true), run: func() error { return os.Remove(folderRulePath) }},
		{name: "unlink", reference: ref(unlinkAllow, DecisionDelete, false), run: func() error { return os.Remove(unlinkAllow) }},
		{name: "rmdir", reference: ref(rmdirAllow, DecisionDelete, true), run: func() error { return os.Remove(rmdirAllow) }},
		{name: "mkdir", reference: ref(mkdirAllow, DecisionCreate, true), run: func() error { return os.Mkdir(mkdirAllow, 0o700) }},
		{name: "link-within", reference: link(linkWithinSource, linkWithinDest), run: func() error { return os.Link(linkWithinSource, linkWithinDest) }},
		{name: "link-into", reference: link(linkIntoSource, linkIntoDest), run: func() error { return os.Link(linkIntoSource, linkIntoDest) }},
		{name: "link-out", reference: link(linkOutSource, linkOutDest), run: func() error { return os.Link(linkOutSource, linkOutDest) }},
		{name: "link-cross-scope", reference: link(linkCrossSource, linkCrossDest), run: func() error { return os.Link(linkCrossSource, linkCrossDest) }},
		{name: "rename-within", reference: rename(renameWithinSource, renameWithinDest, false), run: func() error { return os.Rename(renameWithinSource, renameWithinDest) }},
		{name: "rename-into", reference: rename(renameIntoSource, renameIntoDest, false), run: func() error { return os.Rename(renameIntoSource, renameIntoDest) }},
		{name: "rename-out", reference: rename(renameOutSource, renameOutDest, false), run: func() error { return os.Rename(renameOutSource, renameOutDest) }},
		{name: "rename-cross-scope", reference: rename(renameCrossSource, renameCrossDest, false), run: func() error { return os.Rename(renameCrossSource, renameCrossDest) }},
		{name: "rename-over", reference: rename(renameOverSource, renameOverDest, true), run: func() error { return os.Rename(renameOverSource, renameOverDest) }},
		{name: "atomic-save", reference: rename(atomicTemp, atomicDest, true), run: func() error {
			if err := os.WriteFile(atomicTemp, []byte("replacement"), 0o600); err != nil {
				return err
			}
			return os.Rename(atomicTemp, atomicDest)
		}},
		{name: "rename-exchange", reference: exchange(), run: func() error {
			return unix.Renameat2(unix.AT_FDCWD, exchangeLeft, unix.AT_FDCWD, exchangeRight, unix.RENAME_EXCHANGE)
		}},
		{name: "rename-noreplace", reference: rename(noreplaceSource, noreplaceDest, false), run: func() error {
			return unix.Renameat2(unix.AT_FDCWD, noreplaceSource, unix.AT_FDCWD, noreplaceDest, unix.RENAME_NOREPLACE)
		}},
		{name: "unlinkat", reference: ref(unlinkAt, DecisionDelete, false), run: func() error {
			return withDirFD(allow, func(fd int) error { return unix.Unlinkat(fd, filepath.Base(unlinkAt), 0) })
		}},
		{name: "rmdirat", reference: ref(rmdirAt, DecisionDelete, true), run: func() error {
			return withDirFD(allow, func(fd int) error { return unix.Unlinkat(fd, filepath.Base(rmdirAt), unix.AT_REMOVEDIR) })
		}},
		{name: "mkdirat", reference: ref(filepath.Join(allow, mkdirAt), DecisionCreate, true), run: func() error {
			return withDirFD(allow, func(fd int) error { return unix.Mkdirat(fd, mkdirAt, 0o700) })
		}},
		{name: "renameat", reference: rename(renameAtSource, filepath.Join(allow, renameAtDest), false), run: func() error {
			return withDirFD(allow, func(fd int) error { return unix.Renameat(fd, filepath.Base(renameAtSource), fd, renameAtDest) })
		}},
		{name: "linkat", reference: link(linkAtSource, filepath.Join(allow, linkAtDest)), run: func() error {
			return withDirFD(allow, func(fd int) error { return unix.Linkat(fd, filepath.Base(linkAtSource), fd, linkAtDest, 0) })
		}},
	}
}

func assertDifferentialOutcome(t *testing.T, seed int64, defaultAction uint8, rules []PathRule, operation differentialOperation, got error) {
	t.Helper()
	if operation.reference == VerdictAllow && got == nil {
		return
	}
	if operation.reference == VerdictDeny && errors.Is(got, unix.EPERM) {
		return
	}
	t.Fatalf(
		"BPF/Go mismatch seed=%d default=%d operation=%s rules=%+v reference=%s syscall=%v",
		seed,
		defaultAction,
		operation.name,
		rules,
		operation.reference,
		got,
	)
}

func withDirFD(path string, run func(int) error) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return run(fd)
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path string) {
	t.Helper()
	mustMkdirAll(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%s\n", path)), 0o600); err != nil {
		t.Fatal(err)
	}
}
