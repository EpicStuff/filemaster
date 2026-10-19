//go:build linux && !filemaster_test

package fileaccess

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/profile"
	"golang.org/x/sys/unix"
)

// TestStructuralBPFDifferential generates random policies and operations and
// requires the kernel verdict to equal DecideOperation/DecideRename/
// DecideHardLink for every one. It loads BPF LSM and mutates a real
// filesystem, so the VM gate enables it with FM_BPF_DIFFERENTIAL=1 and selects
// the filesystem with FM_BPF_DIFFERENTIAL_ROOT.
func TestStructuralBPFDifferential(t *testing.T) {
	if os.Getenv("FM_BPF_DIFFERENTIAL") != "1" {
		t.Skip("set FM_BPF_DIFFERENTIAL=1 to run the root-only BPF differential test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("FM_BPF_DIFFERENTIAL requires root")
	}

	seeds := []int64{101, 211, 307, 401, 509, 613, 727, 829}
	grandTotal, grandAllow, grandDeny := 0, 0, 0
	for _, seed := range seeds {
		allow, deny := runDifferentialSeed(t, seed)
		grandTotal += allow + deny
		grandAllow += allow
		grandDeny += deny
		t.Logf("differential seed=%d cases=%d allow=%d deny=%d mismatches=0", seed, allow+deny, allow, deny)
	}
	if grandDeny*100 < grandTotal*30 {
		t.Fatalf("only %d/%d (%.0f%%) cases expected a deny, want at least 30%%", grandDeny, grandTotal, float64(grandDeny)*100/float64(grandTotal))
	}
	t.Logf("differential total=%d allow=%d deny=%d mismatches=0", grandTotal, grandAllow, grandDeny)
}

func runDifferentialSeed(t *testing.T, seed int64) (allow, deny int) {
	t.Helper()
	random := rand.New(rand.NewSource(seed))
	root := differentialRoot(t, seed)
	scopeA := filepath.Join(root, "scope-a")
	scopeB := filepath.Join(root, "scope-b")
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{scopeA, scopeB, outside} {
		mustMkdirAll(t, dir)
	}

	defaultAction := []uint8{
		profile.DefaultActionNotSet, profile.DefaultActionBlock,
		profile.DefaultActionAsk, profile.DefaultActionPermit,
	}[random.Intn(4)]
	snapshot := generateSnapshot(random, scopeA, scopeB, outside, defaultAction)

	// Materialize the current matches of each generated rule so the compiler
	// anchors them, then build every operation and its fixtures BEFORE
	// enforcing: fixture mkdirs are themselves hooked, so they must not run
	// while the policy denies them.
	for _, dir := range []string{filepath.Join(scopeA, "live"), filepath.Join(scopeB, "live")} {
		mustMkdirAll(t, dir)
	}
	var operations []differentialOperation
	for len(operations) < 500 {
		operations = append(operations, generateOperations(t, random, root, scopeA, scopeB, outside, snapshot)...)
	}
	// Pre-create the nested mountpoint (a hooked mkdir) before enforcing.
	nested := filepath.Join(scopeA, "nested-mount")
	mustMkdirAll(t, nested)

	policy := bpflsm.Policy{
		Scopes: scopesFromWatchRules(&watchRuleSnapshot{Rules: []watchRule{{Path: scopeA}, {Path: scopeB}}}),
		Labels: []bpflsm.LabelPolicy{unidentifiedLabelPolicy(LookupResult{Snapshot: snapshot, DefaultAction: defaultAction})},
	}
	table, warnings, err := bpflsm.Compile(policy)
	if err != nil {
		t.Fatalf("seed=%d compile: %v", seed, err)
	}
	for _, warning := range warnings {
		if warning.ID == "context-rule-overflow" {
			t.Fatalf("seed=%d unexpected overflow: %v", seed, warning.Patterns)
		}
	}

	zero := uint32(0)
	pinRoot := filepath.Join("/sys/fs/bpf", "filemaster-differential-"+strconv.Itoa(os.Getpid())+"-"+strconv.FormatInt(seed, 10))
	enforcer := bpflsm.NewEnforcerWithOptions(bpflsm.Options{
		PinRoot:     pinRoot,
		SelfTestDir: filepath.Join(root, "selftest"),
		DaemonPID:   &zero,
	})
	if err := enforcer.SetModeWithTable(bpflsm.ModeEnforce, table); err != nil {
		t.Fatalf("seed=%d load/enforce: %v", seed, err)
	}
	defer func() {
		if err := enforcer.SetMode(bpflsm.ModeOff); err != nil {
			t.Errorf("seed=%d detach: %v", seed, err)
		}
	}()

	// A tmpfs mounted inside a scope at test time, then a re-publish, exercises
	// the mount-root walk stop and the re-registration path. mount(2) and the
	// file creation via open(2) are not hooked, so they run under enforcement;
	// the mountpoint dir was created before enforcing.
	if err := unix.Mount("tmpfs", nested, "tmpfs", 0, "mode=0700"); err != nil {
		t.Fatalf("seed=%d mount nested tmpfs: %v", seed, err)
	}
	defer unix.Unmount(nested, unix.MNT_DETACH)
	nestedFile := filepath.Join(nested, "f")
	if err := createFile(nestedFile); err != nil {
		t.Fatalf("seed=%d create nested file: %v", seed, err)
	}
	republished, _, err := bpflsm.Compile(policy)
	if err != nil {
		t.Fatalf("seed=%d recompile after mount: %v", seed, err)
	}
	if err := enforcer.Publish(republished); err != nil {
		t.Fatalf("seed=%d republish after mount: %v", seed, err)
	}
	operations = append(operations, differentialOperation{
		name:      "nested-mount-unlink",
		reference: snapshot.DecideOperation(nestedFile, DecisionDelete, false),
		run:       func() error { return os.Remove(nestedFile) },
	})

	for _, operation := range operations {
		got := operation.run()
		if operation.reference == VerdictAllow {
			if got != nil {
				t.Fatalf("seed=%d op=%s reference=allow got=%v", seed, operation.name, got)
			}
			allow++
			continue
		}
		if !errors.Is(got, unix.EPERM) {
			t.Fatalf("seed=%d op=%s reference=deny got=%v", seed, operation.name, got)
		}
		deny++
	}
	return allow, deny
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

// generateSnapshot builds ordered, overlapping Read/Write/Execute lists that
// differ, using every rule shape, ObjectKind and the four default actions,
// including rules outside every scope and on paths that do not exist yet.
func generateSnapshot(random *rand.Rand, scopeA, scopeB, outside string, defaultAction uint8) *DecisionSnapshot {
	kinds := []ObjectKind{ObjectKindAny, ObjectKindFile, ObjectKindFolder}
	makeList := func(salt int) PathRules {
		patterns := []string{
			filepath.Join(scopeA, "live", "**"),
			filepath.Join(scopeA, "live", "exact"),
			filepath.Join(scopeA, "live", "*.txt"),
			filepath.Join(scopeA, "live", "[ab]*"),
			filepath.Join(scopeA, "live", `\*literal`),
			filepath.Join(scopeB, "live", "**"),
			filepath.Join(scopeB, "live", "d?"),
			filepath.Join(scopeA, "future", "**"),
			filepath.Join(scopeA, "future-exact"),
			filepath.Join(outside, "**"),
		}
		random.Shuffle(len(patterns), func(i, j int) { patterns[i], patterns[j] = patterns[j], patterns[i] })
		rules := make([]PathRule, 0, len(patterns))
		for i, pattern := range patterns {
			rules = append(rules, PathRule{
				Pattern:    pattern,
				Verdict:    []Verdict{VerdictAllow, VerdictDeny}[(salt+i)%2],
				ObjectKind: kinds[(salt+i)%3],
			})
		}
		return PathRules{Rules: rules}
	}
	return &DecisionSnapshot{
		DefaultAction: defaultAction,
		Read:          makeList(0),
		Write:         makeList(1),
		Exec:          makeList(2),
	}
}

type differentialOperation struct {
	name      string
	reference Verdict
	run       func() error
}

func generateOperations(t *testing.T, random *rand.Rand, root, scopeA, scopeB, outside string, snapshot *DecisionSnapshot) []differentialOperation {
	t.Helper()
	liveA := filepath.Join(scopeA, "live")
	liveB := filepath.Join(scopeB, "live")
	tag := strconv.Itoa(random.Int())

	// Materialize the current matches a few generated rules anchor on.
	mustWriteFile(t, filepath.Join(liveA, "exact"))
	mustWriteFile(t, filepath.Join(liveA, "note.txt"))
	mustWriteFile(t, filepath.Join(liveA, "about"))
	mustWriteFile(t, filepath.Join(liveB, "d1"))

	file := func(dir, name string) string {
		path := filepath.Join(dir, name+tag)
		mustWriteFile(t, path)
		return path
	}
	dir := func(parent, name string) string {
		path := filepath.Join(parent, name+tag)
		mustMkdirAll(t, path)
		return path
	}
	deepRoot := filepath.Join(liveA, "deep-"+tag)
	for i := range 110 {
		deepRoot = filepath.Join(deepRoot, "d"+strconv.Itoa(i))
	}
	mustMkdirAll(t, deepRoot)
	deepFile := filepath.Join(deepRoot, "leaf")
	mustWriteFile(t, deepFile)

	ref := func(path string, op DecisionOp, isDir bool) Verdict { return snapshot.DecideOperation(path, op, isDir) }
	rename := func(source, destination string, sourceDir, destDir, destExists bool) Verdict {
		return snapshot.DecideRename(RenameRequest{Source: source, SourceIsDir: sourceDir, Dest: destination, DestIsDir: destDir, DestExists: destExists})
	}
	link := func(source, destination string, destExists bool) Verdict {
		return snapshot.DecideHardLink(LinkRequest{Source: source, Dest: destination, DestExists: destExists})
	}

	unlinkTarget := file(liveA, "unlink-")
	rmdirTarget := dir(liveA, "rmdir-")
	mkdirTarget := filepath.Join(liveA, "mkdir-"+tag)
	folderRename := dir(liveA, "folder-src-")
	folderRenameDest := filepath.Join(liveB, "folder-dst-"+tag)
	linkSrc := file(outside, "link-src-")
	linkDest := filepath.Join(liveA, "link-dst-"+tag)
	renameOverSrc := file(liveA, "rename-over-src-")
	renameOverDest := file(liveB, "rename-over-dst-")
	exchangeLeft := file(liveA, "exchange-l-")
	exchangeRight := file(liveB, "exchange-r-")
	noreplaceSrc := file(liveA, "noreplace-src-")
	noreplaceDest := filepath.Join(liveB, "noreplace-dst-"+tag)
	atSrc := file(liveA, "at-src-")
	atDest := "at-dst-" + tag
	// Post-publish creations that match a glob / exact rule, exercised through
	// hooked operations: a folder mkdir (create) and a file unlink (delete).
	// Regular-file create via open is deliberately not hooked (plan §1), so it
	// is not used as a measured operation here.
	futureGlob := filepath.Join(scopeA, "future", "created-"+tag)
	mustMkdirAll(t, filepath.Dir(futureGlob))
	futureExact := filepath.Join(scopeA, "future-exact")

	exchangeRef := func() Verdict {
		if rename(exchangeLeft, exchangeRight, false, false, true) == VerdictDeny {
			return VerdictDeny
		}
		return rename(exchangeRight, exchangeLeft, false, false, true)
	}

	return []differentialOperation{
		{"unlink", ref(unlinkTarget, DecisionDelete, false), func() error { return os.Remove(unlinkTarget) }},
		{"rmdir", ref(rmdirTarget, DecisionDelete, true), func() error { return os.Remove(rmdirTarget) }},
		{"mkdir", ref(mkdirTarget, DecisionCreate, true), func() error { return os.Mkdir(mkdirTarget, 0o700) }},
		{"deep-unlink", ref(deepFile, DecisionDelete, false), func() error { return os.Remove(deepFile) }},
		{"link-in", link(linkSrc, linkDest, false), func() error { return os.Link(linkSrc, linkDest) }},
		{"rename-folder", rename(folderRename, folderRenameDest, true, true, false), func() error { return os.Rename(folderRename, folderRenameDest) }},
		{"rename-over", rename(renameOverSrc, renameOverDest, false, false, true), func() error { return os.Rename(renameOverSrc, renameOverDest) }},
		{"rename-exchange", exchangeRef(), func() error {
			return unix.Renameat2(unix.AT_FDCWD, exchangeLeft, unix.AT_FDCWD, exchangeRight, unix.RENAME_EXCHANGE)
		}},
		{"rename-noreplace", rename(noreplaceSrc, noreplaceDest, false, false, false), func() error {
			return unix.Renameat2(unix.AT_FDCWD, noreplaceSrc, unix.AT_FDCWD, noreplaceDest, unix.RENAME_NOREPLACE)
		}},
		{"mkdirat", ref(filepath.Join(liveA, atDest), DecisionCreate, true), func() error {
			return withDirFD(liveA, func(fd int) error { return unix.Mkdirat(fd, atDest, 0o700) })
		}},
		{"renameat", rename(atSrc, filepath.Join(liveA, atDest+"r"), false, false, false), func() error {
			return withDirFD(liveA, func(fd int) error { return unix.Renameat(fd, filepath.Base(atSrc), fd, atDest+"r") })
		}},
		{"mkdir-future-glob", ref(futureGlob, DecisionCreate, true), func() error { return os.Mkdir(futureGlob, 0o700) }},
		{"unlink-future-exact", ref(futureExact, DecisionDelete, false), func() error {
			// Idempotent create (no O_EXCL): a prior denied unlink may have left
			// the file. open is not hooked, so only the unlink is measured.
			if err := os.WriteFile(futureExact, nil, 0o600); err != nil {
				return err
			}
			return os.Remove(futureExact)
		}},
		{"unlink-live-exact", ref(filepath.Join(liveA, "exact"), DecisionDelete, false), func() error {
			defer mustWriteFile(t, filepath.Join(liveA, "exact"))
			return os.Remove(filepath.Join(liveA, "exact"))
		}},
	}
}

func createFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
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
	if err := os.MkdirAll(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path string) {
	t.Helper()
	mustMkdirAll(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%s\n", filepath.Base(path))), 0o600); err != nil {
		t.Fatal(err)
	}
}
