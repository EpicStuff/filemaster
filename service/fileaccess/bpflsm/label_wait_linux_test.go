//go:build linux && !filemaster_test

package bpflsm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestLabelWait checks the bounded label wait: an rm that deletes at once,
// before the resolver has labelled it, waits and is decided with its real
// label; with no resolver it waits out the cap and is denied under its own
// reason; with the wait turned off it is denied at once as pending. In audit
// mode a pending rm never waits: it is allowed at once and its would-deny is
// recorded as pending.
func TestLabelWait(t *testing.T) {
	requireBPFLSM(t)
	rm, err := exec.LookPath("rm")
	if err != nil {
		t.Skip("rm is not installed")
	}
	scope := t.TempDir()
	table, _, err := Compile(Policy{
		Scopes: []ScopeInput{{Path: scope}},
		Labels: []LabelPolicy{{Label: 1, Rules: []RuleInput{{List: ListWrite, Pattern: scope + "/**", Allow: true}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var enf *Enforcer
	var resolving atomic.Bool
	pid := uint32(os.Getpid())
	enf = NewEnforcerWithOptions(Options{
		PinRoot:     "/sys/fs/bpf/filemaster-wait-" + strconv.Itoa(os.Getpid()),
		SelfTestDir: filepath.Join(t.TempDir(), "selftest"),
		DaemonPID:   &pid,
		Labelling:   true,
		// Resolve 10 ms late, about the daemon's resolution time, so rm reaches
		// its unlink while still pending.
		OnRecord: func(record Record) {
			if resolving.Load() && record.Kind == RecordExec {
				time.AfterFunc(10*time.Millisecond, func() { _ = enf.Resolve(record.TGID, record.Start, record.Seq, 1) })
			}
		},
	})
	t.Cleanup(func() { _ = enf.SetMode(ModeOff) })
	if err := enf.SetModeWithTable(ModeEnforce, table); err != nil {
		t.Fatalf("enforce: %v", err)
	}
	wait := enf.Status().Labelling.Wait
	t.Logf("label wait: state %q, self-test %q, max waiters %d", wait.State, wait.SelfTest, wait.MaxWaiters)
	if wait.State != WaitOn {
		t.Skipf("the label wait is %s on this kernel", wait.State)
	}

	remove := func() (allowed bool, took time.Duration) {
		victim := filepath.Join(scope, "victim")
		if err := os.WriteFile(victim, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		_ = exec.Command(rm, "-f", victim).Run()
		took = time.Since(start)
		_, err := os.Stat(victim)
		return os.IsNotExist(err), took
	}
	undecided := func(reason string) uint64 {
		var total uint64
		for _, count := range enf.Status().Undecided {
			if count.Reason == reason {
				total += count.Count
			}
		}
		return total
	}

	resolving.Store(true)
	before := enf.Status().Labelling.Wait
	for i := 0; i < 20; i++ {
		if allowed, _ := remove(); !allowed {
			t.Fatalf("run %d: rm was denied although the resolver labels it", i)
		}
	}
	after := enf.Status().Labelling.Wait
	if after.Waits-before.Waits != 20 || after.Resolved-before.Resolved != 20 || after.TimedOut != before.TimedOut {
		t.Errorf("resolved waits: before %+v, after %+v", before, after)
	}
	t.Logf("20 resolved runs: %d waits, %v waited in all", after.Waits-before.Waits,
		time.Duration(after.WaitedNanos-before.WaitedNanos))

	resolving.Store(false)
	timeouts := undecided(ReasonWaitTimeout)
	allowed, took := remove()
	if allowed {
		t.Fatal("unresolved rm was allowed")
	}
	if got := enf.Status().Labelling.Wait.TimedOut; got != after.TimedOut+1 || undecided(ReasonWaitTimeout) != timeouts+1 {
		t.Errorf("unresolved rm: timed-out waits %d (was %d), %s count %d (was %d)",
			got, after.TimedOut, ReasonWaitTimeout, undecided(ReasonWaitTimeout), timeouts)
	}
	if took < waitCap {
		t.Errorf("unresolved rm returned after %v, before the %v wait cap", took, waitCap)
	}

	enf.SetLabelWait(false)
	deadline := time.Now().Add(5 * time.Second)
	for enf.Status().Labelling.Wait.State != WaitOffConfig && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// The heartbeat applies the switch; give it its kick.
	time.Sleep(100 * time.Millisecond)
	waits := enf.Status().Labelling.Wait.Waits
	pending := undecided(ReasonPending)
	if allowed, _ := remove(); allowed {
		t.Fatal("rm with the wait off was allowed")
	}
	if got := enf.Status().Labelling.Wait.Waits; got != waits || undecided(ReasonPending) != pending+1 {
		t.Errorf("wait off: waits %d (was %d), %s count %d (was %d)", got, waits, ReasonPending, undecided(ReasonPending), pending)
	}

	enf.SetLabelWait(true)
	deadline = time.Now().Add(5 * time.Second)
	for enf.Status().Labelling.Wait.State != WaitOn && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if err := enf.SetMode(ModeAudit); err != nil {
		t.Fatalf("audit: %v", err)
	}
	waits = enf.Status().Labelling.Wait.Waits
	pending = undecided(ReasonPending)
	wouldDeny := enf.Status().WouldDeny[operationName(OperationDelete)]
	for i := 0; i < 5; i++ {
		allowed, took := remove()
		if !allowed {
			t.Fatalf("audit run %d: pending rm was denied", i)
		}
		if took >= waitCap {
			t.Errorf("audit run %d: pending rm took %v, as long as the %v wait cap", i, took, waitCap)
		}
	}
	status := enf.Status()
	if status.Labelling.Wait.Waits != waits || undecided(ReasonPending) != pending+5 || status.WouldDeny[operationName(OperationDelete)] != wouldDeny+5 {
		t.Errorf("audit: waits %d (was %d), %s count %d (was %d), would-deny delete %d (was %d)",
			status.Labelling.Wait.Waits, waits, ReasonPending, undecided(ReasonPending), pending,
			status.WouldDeny[operationName(OperationDelete)], wouldDeny)
	}
}
