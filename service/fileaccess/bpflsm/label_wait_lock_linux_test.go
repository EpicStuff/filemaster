//go:build linux && !filemaster_test

package bpflsm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLabelWaitParentLock measures what a waiting unlink costs other tasks.
// The hook runs inside vfs_unlink with the parent directory's i_rwsem held
// exclusively, so while a pending caller spins for its label, a lookup of an
// uncached name in that directory (lookup_slow takes the lock shared) waits
// too; other directories are unaffected. The stall is bounded by the wait cap.
// A resolver that itself looks up a name in that directory cannot finish
// before the cap, so the caller times out and is denied (fail closed).
func TestLabelWaitParentLock(t *testing.T) {
	requireBPFLSM(t)
	rm, err := exec.LookPath("rm")
	if err != nil {
		t.Skip("rm is not installed")
	}
	scope := t.TempDir()
	locked, other := filepath.Join(scope, "locked"), filepath.Join(scope, "other")
	for _, dir := range []string{locked, other} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	table, _, err := Compile(Policy{
		Scopes: []ScopeInput{{Path: scope}},
		Labels: []LabelPolicy{{Label: 1, Rules: []RuleInput{{List: ListWrite, Pattern: scope + "/**", Allow: true}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var enf *Enforcer
	var resolve atomic.Int32
	const (
		resolveNone = iota
		resolveLate
		resolveAfterLookup
	)
	var probe atomic.Uint64
	pid := uint32(os.Getpid())
	enf = NewEnforcerWithOptions(Options{
		PinRoot:     "/sys/fs/bpf/filemaster-wait-lock-" + strconv.Itoa(os.Getpid()),
		SelfTestDir: filepath.Join(t.TempDir(), "selftest"),
		DaemonPID:   &pid,
		Labelling:   true,
		OnRecord: func(record Record) {
			if record.Kind != RecordExec {
				return
			}
			switch resolve.Load() {
			case resolveLate:
				time.AfterFunc(10*time.Millisecond, func() { _ = enf.Resolve(record.TGID, record.Start, record.Seq, 1) })
			case resolveAfterLookup:
				go func() {
					time.Sleep(10 * time.Millisecond)
					_, _ = os.Lstat(filepath.Join(locked, "resolver-"+strconv.FormatUint(probe.Add(1), 10)))
					_ = enf.Resolve(record.TGID, record.Start, record.Seq, 1)
				}()
			}
		},
	})
	t.Cleanup(func() { _ = enf.SetMode(ModeOff) })
	if err := enf.SetModeWithTable(ModeEnforce, table); err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if wait := enf.Status().Labelling.Wait; wait.State != WaitOn {
		t.Skipf("the label wait is %s on this kernel", wait.State)
	}

	// prober looks up a fresh (uncached) name in dir every 200 µs and keeps
	// the longest lookup.
	prober := func(dir string, stop <-chan struct{}, longest *time.Duration, done *sync.WaitGroup) {
		defer done.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			start := time.Now()
			_, _ = os.Lstat(filepath.Join(dir, "probe-"+strconv.FormatUint(probe.Add(1), 10)))
			if took := time.Since(start); took > *longest {
				*longest = took
			}
			time.Sleep(200 * time.Microsecond)
		}
	}
	remove := func() (allowed bool, took, lockedStall, otherStall time.Duration) {
		victim := filepath.Join(locked, "victim")
		if err := os.WriteFile(victim, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		var done sync.WaitGroup
		done.Add(2)
		go prober(locked, stop, &lockedStall, &done)
		go prober(other, stop, &otherStall, &done)
		time.Sleep(20 * time.Millisecond)
		start := time.Now()
		_ = exec.Command(rm, "-f", victim).Run()
		took = time.Since(start)
		time.Sleep(20 * time.Millisecond)
		close(stop)
		done.Wait()
		_, err := os.Stat(victim)
		return os.IsNotExist(err), took, lockedStall, otherStall
	}

	// A resolver blocked behind the lock is neither checked to allow nor to
	// deny: only that the caller is released by the cap.
	allowedWant := map[int32]bool{resolveLate: true, resolveNone: false}
	for _, c := range []struct {
		name string
		mode int32
	}{
		{"resolved 10 ms late", resolveLate},
		{"never resolved", resolveNone},
		{"resolver looks up a name in the locked folder", resolveAfterLookup},
	} {
		resolve.Store(c.mode)
		before := enf.Status().Labelling.Wait
		allowed, took, lockedStall, otherStall := remove()
		after := enf.Status().Labelling.Wait
		t.Logf("label wait lock: %s: allowed=%v rm %v; longest lookup in the parent folder %v, in another folder %v; waits +%d resolved +%d timed out +%d",
			c.name, allowed, took.Round(time.Microsecond), lockedStall.Round(time.Microsecond), otherStall.Round(time.Microsecond),
			after.Waits-before.Waits, after.Resolved-before.Resolved, after.TimedOut-before.TimedOut)
		if want, ok := allowedWant[c.mode]; ok && allowed != want {
			t.Errorf("%s: allowed=%v, want %v", c.name, allowed, want)
		}
		if took > waitCap+50*time.Millisecond {
			t.Errorf("%s: rm took %v, longer than the %v wait cap allows", c.name, took, waitCap)
		}
		if lockedStall > waitCap+25*time.Millisecond {
			t.Errorf("%s: a lookup in the parent folder stalled %v, more than the %v wait cap", c.name, lockedStall, waitCap)
		}
		if otherStall > 20*time.Millisecond {
			t.Errorf("%s: a lookup in another folder stalled %v", c.name, otherStall)
		}
	}
}
