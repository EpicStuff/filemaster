//go:build linux && !filemaster_test

package fileaccess

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/profile"
	"golang.org/x/sys/unix"
)

// TestStructuralBPFDifferential generates random policies and operations and
// requires the kernel verdict to equal DecideInScope/DecideRename/
// DecideHardLink/DecideSymlink for every one. It loads BPF LSM and mutates a real
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
	// Each profile default (no-match under not-set, Block, Ask and Permit)
	// decides two seeds.
	defaults := []uint8{profile.DefaultActionNotSet, profile.DefaultActionBlock, profile.DefaultActionAsk, profile.DefaultActionPermit}
	grandTotal, grandAllow, grandDeny := 0, 0, 0
	// Per operation, the expected allow and deny counts, so a new operation
	// is seen to be checked both ways.
	perOperation := make(map[string]*[2]int)
	for i, seed := range seeds {
		allow, deny := runDifferentialSeed(t, seed, defaults[i%len(defaults)], perOperation)
		grandTotal += allow + deny
		grandAllow += allow
		grandDeny += deny
		t.Logf("differential seed=%d default=%d cases=%d allow=%d deny=%d mismatches=0", seed, defaults[i%len(defaults)], allow+deny, allow, deny)
	}
	if grandDeny*100 < grandTotal*30 {
		t.Fatalf("only %d/%d (%.0f%%) cases expected a deny, want at least 30%%", grandDeny, grandTotal, float64(grandDeny)*100/float64(grandTotal))
	}
	t.Logf("differential total=%d allow=%d deny=%d mismatches=0", grandTotal, grandAllow, grandDeny)
	names := make([]string, 0, len(perOperation))
	for name := range perOperation {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		t.Logf("differential op=%s allow=%d deny=%d", name, perOperation[name][0], perOperation[name][1])
	}
}

func runDifferentialSeed(t *testing.T, seed int64, defaultAction uint8, perOperation map[string]*[2]int) (allow, deny int) {
	t.Helper()
	random := rand.New(rand.NewSource(seed))
	root := differentialRoot(t, seed)
	scopeA := filepath.Join(root, "scope-a")
	scopeB := filepath.Join(root, "scope-b")
	outside := filepath.Join(root, "outside")
	excluded := filepath.Join(scopeA, "excluded")
	for _, dir := range []string{scopeA, scopeB, outside, excluded} {
		mustMkdirAll(t, dir)
	}
	watch := &watchRuleSnapshot{Rules: []watchRule{{Path: excluded, Exclude: true}, {Path: scopeA}, {Path: scopeB}}}

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
		operations = append(operations, generateOperations(t, random, root, scopeA, scopeB, outside, snapshot, watch)...)
	}
	// Pre-create the nested mountpoint (a hooked mkdir) before enforcing.
	nested := filepath.Join(scopeA, "nested-mount")
	mustMkdirAll(t, nested)

	policy := bpflsm.Policy{
		Scopes: scopesFromWatchRules(watch),
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
		reference: snapshot.DecideInScope(nestedFile, DecisionDelete, false, watch.matches),
		run:       func() error { return os.Remove(nestedFile) },
	})

	for _, operation := range operations {
		if perOperation[operation.name] == nil {
			perOperation[operation.name] = new([2]int)
		}
		if operation.reference == VerdictAllow {
			perOperation[operation.name][0]++
		} else {
			perOperation[operation.name][1]++
		}
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
			filepath.Join(scopeA, "excluded", "**"),
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

func generateOperations(t *testing.T, random *rand.Rand, root, scopeA, scopeB, outside string, snapshot *DecisionSnapshot, watch *watchRuleSnapshot) []differentialOperation {
	t.Helper()
	liveA := filepath.Join(scopeA, "live")
	liveB := filepath.Join(scopeB, "live")
	excluded := filepath.Join(scopeA, "excluded")
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

	ref := func(path string, op DecisionOp, isDir bool) Verdict {
		return snapshot.DecideInScope(path, op, isDir, watch.matches)
	}
	rename := func(source, destination string, sourceDir, destDir, destExists bool) Verdict {
		return snapshot.DecideRename(RenameRequest{Source: source, SourceIsDir: sourceDir, Dest: destination, DestIsDir: destDir, DestExists: destExists}, watch.matches)
	}
	link := func(source, destination string, destExists bool) Verdict {
		return snapshot.DecideHardLink(LinkRequest{Source: source, Dest: destination, DestExists: destExists}, watch.matches)
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

	// Hard links and renames into, out of and within a scope; an exchange of
	// a protected file with an unprotected folder; a no-replace rename onto an
	// existing file, which the VFS refuses with EEXIST before any hook.
	linkWithinSrc := file(liveA, "link-within-src-")
	linkWithinDest := filepath.Join(liveA, "link-within-dst-"+tag)
	linkOutSrc := file(liveA, "link-out-src-")
	linkOutDest := filepath.Join(outside, "link-out-dst-"+tag)
	renameInSrc := file(outside, "rename-in-src-")
	renameInDest := filepath.Join(liveA, "rename-in-dst-"+tag)
	renameOutSrc := file(liveB, "rename-out-src-")
	renameOutDest := filepath.Join(outside, "rename-out-dst-"+tag)
	renameWithinSrc := file(liveA, "rename-within-src-")
	renameWithinDest := file(liveA, "rename-within-dst-")
	exchangeFile := file(liveA, "exchange-file-")
	exchangeFolder := dir(outside, "exchange-folder-")
	noreplaceExistingSrc := file(liveA, "noreplace-existing-src-")
	noreplaceExistingDest := file(liveB, "noreplace-existing-dst-")

	// Outside every scope (an unwatched folder and an excluded one inside a
	// scope) nothing is decided, although the generated outside/** rules match
	// there: a hard link and renames there are allowed, like a profile that has
	// only Read rules on an unwatched folder.
	linkOutsideSrc := file(outside, "link-outside-src-")
	linkOutsideDest := filepath.Join(outside, "link-outside-dst-"+tag)
	renameOutsideSrc := file(outside, "rename-outside-src-")
	renameOutsideDest := file(outside, "rename-outside-dst-")
	excludedUnlink := file(excluded, "unlink-")
	excludedLinkSrc := file(excluded, "link-src-")
	excludedLinkDest := filepath.Join(excluded, "link-dst-"+tag)
	excludedRenameSrc := file(excluded, "rename-src-")
	excludedRenameDest := filepath.Join(liveA, "from-excluded-"+tag)
	excludedMkdir := filepath.Join(excluded, "mkdir-"+tag)
	unlinkOutside := file(outside, "unlink-")
	rmdirOutside := dir(outside, "rmdir-")
	mkdirOutside := filepath.Join(outside, "mkdir-"+tag)
	rmdirExcluded := dir(excluded, "rmdir-")
	mknodExcluded := filepath.Join(excluded, "fifo-"+tag)
	symlinkExcluded := filepath.Join(excluded, "symlink-"+tag)

	exchange := func(left, right string, leftDir, rightDir bool) Verdict {
		if rename(left, right, leftDir, rightDir, true) == VerdictDeny {
			return VerdictDeny
		}
		return rename(right, left, rightDir, leftDir, true)
	}
	exchangeRef := func() Verdict { return exchange(exchangeLeft, exchangeRight, false, false) }

	// FIFOs, device nodes and Unix sockets bound to a path are created through
	// inode_mknod, symlinks through inode_symlink: each is a Create of a file
	// entry, and a symlink's target (relative, absolute or dangling) is never
	// decided.
	symlink := func(destination string) Verdict {
		return snapshot.DecideSymlink(LinkRequest{Dest: destination}, watch.matches)
	}
	fifoA := filepath.Join(liveA, "fifo-"+tag)
	fifoGlob := filepath.Join(liveA, "a-fifo-"+tag)
	fifoTxt := filepath.Join(liveB, "fifo-"+tag+".txt")
	fifoOutside := filepath.Join(outside, "fifo-"+tag)
	fifoFuture := filepath.Join(scopeA, "future", "fifo-"+tag)
	socketA, socketOutside := "sock-"+tag, "sock-"+tag
	symlinkRelative := filepath.Join(liveA, "symlink-rel-"+tag)
	symlinkAbsolute := filepath.Join(liveB, "symlink-abs-"+tag)
	symlinkDangling := filepath.Join(outside, "symlink-dangling-"+tag)
	symlinkIntoScope := filepath.Join(outside, "symlink-in-"+tag)
	symlinkTxt := filepath.Join(liveA, "symlink-"+tag+".txt")
	symlinkFuture := filepath.Join(scopeA, "future", "symlink-"+tag)
	symlinkAt := "symlink-at-" + tag

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
		{"link-within", link(linkWithinSrc, linkWithinDest, false), func() error { return os.Link(linkWithinSrc, linkWithinDest) }},
		{"link-out", link(linkOutSrc, linkOutDest, false), func() error { return os.Link(linkOutSrc, linkOutDest) }},
		{"rename-in", rename(renameInSrc, renameInDest, false, false, false), func() error { return os.Rename(renameInSrc, renameInDest) }},
		{"rename-out", rename(renameOutSrc, renameOutDest, false, false, false), func() error { return os.Rename(renameOutSrc, renameOutDest) }},
		{"rename-over-within", rename(renameWithinSrc, renameWithinDest, false, false, true), func() error { return os.Rename(renameWithinSrc, renameWithinDest) }},
		{"rename-exchange-file-folder", exchange(exchangeFile, exchangeFolder, false, true), func() error {
			return unix.Renameat2(unix.AT_FDCWD, exchangeFile, unix.AT_FDCWD, exchangeFolder, unix.RENAME_EXCHANGE)
		}},
		{"rename-noreplace-existing", VerdictAllow, func() error {
			err := unix.Renameat2(unix.AT_FDCWD, noreplaceExistingSrc, unix.AT_FDCWD, noreplaceExistingDest, unix.RENAME_NOREPLACE)
			if errors.Is(err, unix.EEXIST) {
				return nil
			}
			return fmt.Errorf("RENAME_NOREPLACE onto an existing file: %v, want EEXIST", err)
		}},
		{"unlink-live-exact", ref(filepath.Join(liveA, "exact"), DecisionDelete, false), func() error {
			defer mustWriteFile(t, filepath.Join(liveA, "exact"))
			return os.Remove(filepath.Join(liveA, "exact"))
		}},
		{"link-outside", link(linkOutsideSrc, linkOutsideDest, false), func() error { return os.Link(linkOutsideSrc, linkOutsideDest) }},
		{"rename-over-outside", rename(renameOutsideSrc, renameOutsideDest, false, false, true), func() error { return os.Rename(renameOutsideSrc, renameOutsideDest) }},
		{"unlink-outside", ref(unlinkOutside, DecisionDelete, false), func() error { return os.Remove(unlinkOutside) }},
		{"rmdir-outside", ref(rmdirOutside, DecisionDelete, true), func() error { return os.Remove(rmdirOutside) }},
		{"mkdir-outside", ref(mkdirOutside, DecisionCreate, true), func() error { return os.Mkdir(mkdirOutside, 0o700) }},
		{"rmdir-excluded", ref(rmdirExcluded, DecisionDelete, true), func() error { return os.Remove(rmdirExcluded) }},
		{"mkfifo-excluded", ref(mknodExcluded, DecisionCreate, false), func() error { return unix.Mkfifo(mknodExcluded, 0o600) }},
		{"symlink-excluded", symlink(symlinkExcluded), func() error { return os.Symlink("x", symlinkExcluded) }},
		{"unlink-excluded", ref(excludedUnlink, DecisionDelete, false), func() error { return os.Remove(excludedUnlink) }},
		{"mkdir-excluded", ref(excludedMkdir, DecisionCreate, true), func() error { return os.Mkdir(excludedMkdir, 0o700) }},
		{"link-excluded", link(excludedLinkSrc, excludedLinkDest, false), func() error { return os.Link(excludedLinkSrc, excludedLinkDest) }},
		{"rename-from-excluded", rename(excludedRenameSrc, excludedRenameDest, false, false, false), func() error { return os.Rename(excludedRenameSrc, excludedRenameDest) }},
		{"mkfifo", ref(fifoA, DecisionCreate, false), func() error { return unix.Mkfifo(fifoA, 0o600) }},
		{"mkfifo-glob", ref(fifoGlob, DecisionCreate, false), func() error { return unix.Mkfifo(fifoGlob, 0o600) }},
		{"mkfifo-txt", ref(fifoTxt, DecisionCreate, false), func() error { return unix.Mkfifo(fifoTxt, 0o600) }},
		{"mkfifo-outside", ref(fifoOutside, DecisionCreate, false), func() error { return unix.Mkfifo(fifoOutside, 0o600) }},
		{"mkfifo-future-glob", ref(fifoFuture, DecisionCreate, false), func() error { return unix.Mkfifo(fifoFuture, 0o600) }},
		{"mknodat-fifo", ref(filepath.Join(liveB, "fifo-at-"+tag), DecisionCreate, false), func() error {
			return withDirFD(liveB, func(fd int) error { return unix.Mknodat(fd, "fifo-at-"+tag, unix.S_IFIFO|0o600, 0) })
		}},
		{"mknod-char", ref(filepath.Join(liveA, "char-"+tag), DecisionCreate, false), func() error {
			return unix.Mknod(filepath.Join(liveA, "char-"+tag), unix.S_IFCHR|0o600, int(unix.Mkdev(1, 3)))
		}},
		{"socket-bind", ref(filepath.Join(liveA, socketA), DecisionCreate, false), func() error { return bindUnixSocket(filepath.Join(liveA, socketA)) }},
		{"socket-bind-outside", ref(filepath.Join(outside, socketOutside), DecisionCreate, false), func() error { return bindUnixSocket(filepath.Join(outside, socketOutside)) }},
		{"symlink-relative", symlink(symlinkRelative), func() error { return os.Symlink("../outside/x", symlinkRelative) }},
		{"symlink-absolute", symlink(symlinkAbsolute), func() error { return os.Symlink(unlinkTarget, symlinkAbsolute) }},
		{"symlink-dangling", symlink(symlinkDangling), func() error { return os.Symlink("/nonexistent/"+tag, symlinkDangling) }},
		{"symlink-into-scope", symlink(symlinkIntoScope), func() error { return os.Symlink(filepath.Join(liveA, "exact"), symlinkIntoScope) }},
		{"symlink-txt", symlink(symlinkTxt), func() error { return os.Symlink("note.txt", symlinkTxt) }},
		{"symlink-future-glob", symlink(symlinkFuture), func() error { return os.Symlink("..", symlinkFuture) }},
		{"symlinkat", symlink(filepath.Join(liveA, symlinkAt)), func() error {
			return withDirFD(liveA, func(fd int) error { return unix.Symlinkat("exact", fd, symlinkAt) })
		}},
		{"symlink-existing", VerdictAllow, func() error {
			err := os.Symlink("x", filepath.Join(liveA, "exact"))
			if errors.Is(err, unix.EEXIST) {
				return nil
			}
			return fmt.Errorf("symlink onto an existing file: %v, want EEXIST", err)
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

// bindUnixSocket binds a Unix socket at path, which bind(2) creates through
// inode_mknod. sun_path holds 108 bytes, so it binds through the folder's
// descriptor.
func bindUnixSocket(path string) error {
	return withDirFD(filepath.Dir(path), func(fd int) error {
		socket, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			return err
		}
		defer unix.Close(socket)
		return unix.Bind(socket, &unix.SockaddrUnix{Name: "/proc/self/fd/" + strconv.Itoa(fd) + "/" + filepath.Base(path)})
	})
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
