//go:build linux && !filemaster_test

package fileaccess

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/safing/portmaster/service/fileaccess/bpflsm"
	"github.com/safing/portmaster/service/profile"
	"golang.org/x/sys/unix"
)

// TestStructuralBPFContention pins many threads to one CPU, all mutating a
// watched scope under deep paths and a long glob rule list, so evaluations are
// long and get preempted by other threads' hooks on the same CPU. Every
// operation's outcome must equal DecideOperation/DecideRename/DecideHardLink.
// Root-only; the VM gate enables it with FM_BPF_CONTENTION=1, sets the run
// length with FM_BPF_CONTENTION_SECONDS and the filesystem with
// FM_BPF_DIFFERENTIAL_ROOT, and the number of SCHED_FIFO preemptors (4) with
// FM_BPF_CONTENTION_PREEMPTORS.
func TestStructuralBPFContention(t *testing.T) {
	if os.Getenv("FM_BPF_CONTENTION") != "1" {
		t.Skip("set FM_BPF_CONTENTION=1 to run the root-only BPF contention test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("FM_BPF_CONTENTION requires root")
	}
	duration := 30 * time.Second
	if value := os.Getenv("FM_BPF_CONTENTION_SECONDS"); value != "" {
		seconds, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		duration = time.Duration(seconds) * time.Second
	}

	preemptors := 4
	if value := os.Getenv("FM_BPF_CONTENTION_PREEMPTORS"); value != "" {
		count, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		preemptors = count
	}

	root := differentialRoot(t, 0)
	scope := filepath.Join(root, "scope")
	deep := make([]string, 40)
	for i := range deep {
		deep[i] = fmt.Sprintf("s%02d", i)
	}
	tail := filepath.Join(append(deep, "work")...)

	type role struct {
		name     string
		nice     int
		fifo     int
		yielder  bool
		allowDir bool
	}
	var roles []role
	for i, nice := range []int{0, 0, 5, -5, 10, 0, 5, -5, 0, 10} {
		roles = append(roles, role{name: "worker-" + strconv.Itoa(i), nice: nice, allowDir: i%2 == 0})
	}
	for i := range preemptors {
		roles = append(roles, role{name: "rt-" + strconv.Itoa(i), fifo: 1 + i, allowDir: i%2 == 1})
	}
	for i := range 3 {
		roles = append(roles, role{name: "yield-" + strconv.Itoa(i), yielder: true})
	}

	var rules, workerRules []PathRule
	for i := range 100 {
		rules = append(rules, PathRule{
			Pattern: filepath.Join(scope, "*", tail, fmt.Sprintf("*q%d[0-9]", i)),
			Verdict: []Verdict{VerdictAllow, VerdictDeny}[i%2],
		})
	}
	dirs := make([]string, len(roles))
	for i, r := range roles {
		if r.yielder {
			continue
		}
		dirs[i] = filepath.Join(scope, r.name, tail)
		mustMkdirAll(t, dirs[i])
		workerRules = append(workerRules, PathRule{
			Pattern: filepath.Join(scope, r.name, "**"),
			Verdict: map[bool]Verdict{true: VerdictAllow, false: VerdictDeny}[r.allowDir],
		})
	}
	// The long glob list is on Write only, keeping the context under its rule cap.
	snapshot := &DecisionSnapshot{
		DefaultAction: profile.DefaultActionBlock,
		Read:          PathRules{Rules: workerRules},
		Write:         PathRules{Rules: append(rules, workerRules...)},
		Exec:          PathRules{Rules: workerRules},
	}

	table, warnings, err := bpflsm.Compile(bpflsm.Policy{
		Scopes: scopesFromWatchRules(&watchRuleSnapshot{Rules: []watchRule{{Path: scope}}}),
		Labels: []bpflsm.LabelPolicy{unidentifiedLabelPolicy(LookupResult{Snapshot: snapshot, DefaultAction: profile.DefaultActionBlock})},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range warnings {
		t.Fatalf("unexpected compile warning %s (%d patterns)", warning.ID, len(warning.Patterns))
	}
	zero := uint32(0)
	enforcer := bpflsm.NewEnforcerWithOptions(bpflsm.Options{
		PinRoot:     filepath.Join("/sys/fs/bpf", "filemaster-contention-"+strconv.Itoa(os.Getpid())),
		SelfTestDir: filepath.Join(root, "selftest"),
		DaemonPID:   &zero,
	})
	if err := enforcer.SetModeWithTable(bpflsm.ModeEnforce, table); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := enforcer.SetMode(bpflsm.ModeOff); err != nil {
			t.Errorf("detach: %v", err)
		}
	}()

	var (
		operations, failOpen, failClosed atomic.Uint64
		otherMu                          sync.Mutex
		other                            []string
	)
	check := func(name string, reference Verdict, got error) {
		operations.Add(1)
		switch {
		case reference == VerdictAllow && got == nil, reference == VerdictDeny && errors.Is(got, unix.EPERM):
		case reference == VerdictDeny && got == nil:
			failOpen.Add(1)
		case reference == VerdictAllow && errors.Is(got, unix.EPERM):
			failClosed.Add(1)
		default:
			otherMu.Lock()
			if len(other) < 20 {
				other = append(other, fmt.Sprintf("%s reference=%v: %v", name, reference, got))
			}
			otherMu.Unlock()
		}
	}
	exists := func(path string) bool {
		_, err := os.Lstat(path)
		return err == nil
	}
	operate := func(dir string, step int) {
		switch step % 4 {
		case 0:
			path := filepath.Join(dir, "u")
			if err := createIfMissing(path); err != nil {
				check("create", VerdictAllow, err)
				return
			}
			check("unlink", snapshot.DecideOperation(path, DecisionDelete, false), os.Remove(path))
		case 1:
			path := filepath.Join(dir, "m")
			if exists(path) {
				check("rmdir", snapshot.DecideOperation(path, DecisionDelete, true), os.Remove(path))
				return
			}
			err := os.Mkdir(path, 0o700)
			check("mkdir", snapshot.DecideOperation(path, DecisionCreate, true), err)
			if err == nil {
				check("rmdir", snapshot.DecideOperation(path, DecisionDelete, true), os.Remove(path))
			}
		case 2:
			source, destination := filepath.Join(dir, "r"), filepath.Join(dir, "s")
			if err := createIfMissing(source); err != nil {
				check("create", VerdictAllow, err)
				return
			}
			reference := snapshot.DecideRename(RenameRequest{Source: source, Dest: destination, DestExists: exists(destination)})
			check("rename", reference, os.Rename(source, destination))
		case 3:
			source, destination := filepath.Join(dir, "l"), filepath.Join(dir, "k")
			if err := createIfMissing(source); err != nil {
				check("create", VerdictAllow, err)
				return
			}
			if exists(destination) {
				check("unlink", snapshot.DecideOperation(destination, DecisionDelete, false), os.Remove(destination))
				return
			}
			check("link", snapshot.DecideHardLink(LinkRequest{Source: source, Dest: destination}), os.Link(source, destination))
		}
	}

	// A stop-the-world started on a SCHED_FIFO thread spins on CPU 0 waiting
	// for goroutines whose threads it starves there, so no garbage collection
	// may start while the threads run.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup
	setupErrors := make(chan error, len(roles))
	for i, r := range roles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Never unlocked: the thread exits with the goroutine instead of
			// returning to the runtime still SCHED_FIFO on CPU 0, where it can
			// starve a worker preempted inside a hook (an RCU stall).
			runtime.LockOSThread()
			var cpu unix.CPUSet
			cpu.Set(0)
			if err := unix.SchedSetaffinity(0, &cpu); err != nil {
				setupErrors <- fmt.Errorf("%s affinity: %w", r.name, err)
				return
			}
			if r.fifo > 0 {
				attr := unix.SchedAttr{Size: unix.SizeofSchedAttr, Policy: unix.SCHED_FIFO, Priority: uint32(r.fifo)}
				if err := unix.SchedSetAttr(0, &attr, 0); err != nil {
					setupErrors <- fmt.Errorf("%s SCHED_FIFO: %w", r.name, err)
					return
				}
			} else if err := unix.Setpriority(unix.PRIO_PROCESS, unix.Gettid(), r.nice); err != nil {
				setupErrors <- fmt.Errorf("%s nice: %w", r.name, err)
				return
			}
			random := rand.New(rand.NewSource(int64(i)))
			for step := 0; time.Now().Before(deadline); step++ {
				switch {
				case r.yielder:
					for range 100 {
						_, _, _ = unix.RawSyscall(unix.SYS_SCHED_YIELD, 0, 0, 0)
					}
				case r.fifo > 0:
					time.Sleep(time.Duration(200+random.Intn(1800)) * time.Microsecond)
					operate(dirs[i], step)
				default:
					operate(dirs[i], step)
				}
			}
		}()
	}
	wg.Wait()
	close(setupErrors)
	for err := range setupErrors {
		t.Fatal(err)
	}

	var (
		undecided  []string
		contention uint64
	)
	for _, count := range enforcer.Status().Undecided {
		undecided = append(undecided, count.Reason+"/"+count.Hook+"="+strconv.FormatUint(count.Count, 10))
		if count.Reason == bpflsm.ReasonStateContention {
			contention += count.Count
		}
	}
	t.Logf("contention operations=%d fail-open=%d fail-closed=%d other=%d state-contention=%d undecided=[%s]",
		operations.Load(), failOpen.Load(), failClosed.Load(), len(other), contention, strings.Join(undecided, " "))
	for _, line := range other {
		t.Errorf("unexpected outcome: %s", line)
	}
	if failOpen.Load() > 0 {
		t.Errorf("%d operations allowed against a deny reference", failOpen.Load())
	}
	// A decision that found every per-CPU decision state claimed denies by
	// design and is counted, so only uncounted wrong denials are mismatches.
	if failClosed.Load() > contention {
		t.Errorf("%d operations denied against an allow reference, only %d state-contention denials counted", failClosed.Load(), contention)
	}
}

func createIfMissing(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}
