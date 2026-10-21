//go:build linux

package bpflsm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// The kernel's label-wait bounds, mirrored from label_maps.rs.
const (
	waitCap   = 50 * time.Millisecond
	waitStale = 3 * time.Second
	// heartbeatEvery keeps the heartbeat well inside waitStale.
	heartbeatEvery = time.Second
)

// LABEL_COUNTERS slots of the label wait.
const (
	counterWait = 3 + iota
	counterWaitResolved
	counterWaitTimeout
	counterWaitStale
	counterWaitBusy
	counterWaitNS
)

// Label-wait states, as diagnostics report them.
const (
	WaitOn             = "on"
	WaitOffConfig      = "off: disabled by configuration"
	WaitOffSelfTest    = "off: kernel preemption mode does not allow it"
	WaitOffSingleCPU   = "off: only one CPU is online"
	WaitOffUnavailable = "off: the self-test could not run"
	WaitOffInactive    = "off: labelling is not active"
)

// LabelWait reports the bounded label wait: a pending caller whose operation
// the pending policy would deny spins until the daemon labels it, at most
// waitCap, then is decided with its real label.
type LabelWait struct {
	// State is the effective state, one of the Wait* constants.
	State string
	// SelfTest is the preemption self-test's outcome for this generation.
	SelfTest   string
	Configured bool
	MaxWaiters uint32
	Waits      uint64
	Resolved   uint64
	TimedOut   uint64
	// SkippedStale and SkippedBusy are waits not started because the daemon's
	// heartbeat was stale, or because MaxWaiters callers were already waiting.
	SkippedStale uint64
	SkippedBusy  uint64
	WaitedNanos  uint64
}

// SetLabelWait applies the label-wait configuration; it takes effect at the
// next heartbeat, which this triggers at once.
func (e *Enforcer) SetLabelWait(enabled bool) {
	e.waitConfigured.Store(enabled)
	select {
	case e.waitKick <- struct{}{}:
	default:
	}
}

// labelWaitState is the effective state for a generation whose self-test
// returned selfTest.
func labelWaitState(configured bool, selfTest string, maxWaiters uint32) string {
	switch {
	case selfTest == "":
		return WaitOffInactive
	case selfTest != selfTestPassed:
		if selfTest == WaitOffSingleCPU {
			return WaitOffSingleCPU
		}
		if strings.HasPrefix(selfTest, "error: ") {
			return WaitOffUnavailable
		}
		return WaitOffSelfTest
	case !configured:
		return WaitOffConfig
	case maxWaiters == 0:
		return WaitOffSingleCPU
	}
	return WaitOn
}

const selfTestPassed = "passed"

// heartbeat refreshes the WAIT record every heartbeatEvery until stop is
// closed: the monotonic time proves the daemon is alive, max_waiters follows
// the online CPUs, and enabled is the configuration gated by the self-test.
func (e *Enforcer) heartbeat(wait *ebpf.Map, selfTest string, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(heartbeatEvery)
	defer ticker.Stop()
	for {
		enabled := e.waitConfigured.Load() && selfTest == selfTestPassed
		_ = wait.Put(uint32(0), encodeWaitSettings(monotonicNow(), maxWaiters(), enabled))
		select {
		case <-stop:
			_ = wait.Put(uint32(0), encodeWaitSettings(0, 0, false))
			return
		case <-ticker.C:
		case <-e.waitKick:
		}
	}
}

func monotonicNow() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}

// maxWaiters leaves one online CPU free of label waiters, so the daemon can
// always run; with one CPU nothing waits.
func maxWaiters() uint32 {
	online, err := onlineCPUs()
	if err != nil || online < 2 {
		return 0
	}
	return uint32(online - 1)
}

// onlineCPUs counts /sys/devices/system/cpu/online, a list like "0-3,5".
func onlineCPUs() (int, error) {
	data, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return 0, err
	}
	count := 0
	for _, part := range strings.Split(strings.TrimSpace(string(data)), ",") {
		first, last, isRange := strings.Cut(part, "-")
		lo, err := strconv.Atoi(first)
		if err != nil {
			return 0, err
		}
		hi := lo
		if isRange {
			if hi, err = strconv.Atoi(last); err != nil {
				return 0, err
			}
		}
		count += hi - lo + 1
	}
	return count, nil
}

// labelWaitSelfTest decides whether a label wait can be preempted on this
// kernel. The daemon itself becomes a pending caller: one thread unlinks a
// file the pending policy denies, and another thread, pinned to the same CPU,
// resolves the label a few milliseconds later. Only a preemptible spinner
// lets the resolver run, so the unlink succeeds after a resolved wait; under
// voluntary preemption the wait times out. It returns selfTestPassed, the
// reason the wait stays off, or "error: ..." when the test could not run.
func labelWaitSelfTest(collection *ebpf.Collection, dir string) string {
	if maxWaiters() == 0 {
		return WaitOffSingleCPU
	}
	result, err := runLabelWaitSelfTest(collection, dir)
	if err != nil {
		return "error: " + err.Error()
	}
	return result
}

func runLabelWaitSelfTest(collection *ebpf.Collection, dir string) (result string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=1m,mode=0700"); err != nil {
		return "", fmt.Errorf("mount self-test tmpfs: %w", err)
	}
	vault := filepath.Join(dir, "vault")
	self, err := ownIdentity()
	if err != nil {
		return "", err
	}
	settings, procs, resolved, wait := collection.Maps["SETTINGS"], collection.Maps["PROCS"], collection.Maps["RESOLVED"], collection.Maps["WAIT"]
	defer func() {
		err = errors.Join(err,
			settings.Put(uint32(0), encodeSettings(publishedSettings{})),
			wait.Put(uint32(0), encodeWaitSettings(0, 0, false)),
			writeBank(collection.Maps, 1, Table{}),
			ignoreMissing(procs.Delete(self.tgid)),
			ignoreMissing(resolved.Delete(self.tgid)),
			zeroPerCPU(collection.Maps["LABEL_COUNTERS"], labelCounters),
			zeroPerCPU(collection.Maps["COUNTERS"], hookCount*reasonCount),
			unix.Unmount(dir, unix.MNT_DETACH),
			os.Remove(dir),
		)
	}()
	if err := os.Mkdir(vault, 0o700); err != nil {
		return "", err
	}
	label := LabelPolicy{Label: LabelUnidentified, Rules: []RuleInput{{List: ListWrite, Pattern: vault + "/**", Allow: true}}}
	table, _, err := Compile(Policy{Scopes: []ScopeInput{{Path: vault}}, Labels: []LabelPolicy{label}})
	if err != nil {
		return "", err
	}
	if err := writeBank(collection.Maps, 1, table); err != nil {
		return "", err
	}
	if err := settings.Put(uint32(0), encodeSettings(publishedSettings{bank: 1, labelling: true})); err != nil {
		return "", err
	}
	cpu, err := firstAllowedCPU()
	if err != nil {
		return "", err
	}
	// The resolver could, rarely, write before the waiter starts spinning; that
	// attempt proves nothing, so it is repeated.
	for attempt := 0; attempt < 3; attempt++ {
		seq := uint64(attempt + 1)
		if err := procs.Put(self.tgid, encodeProcValue(ProcValue{Start: self.start, Seq: seq, Span: self.span, Label: labelPending})); err != nil {
			return "", err
		}
		if err := wait.Put(uint32(0), encodeWaitSettings(monotonicNow(), 1, true)); err != nil {
			return "", err
		}
		before, err := perCPUTotal(collection.Maps["LABEL_COUNTERS"], counterWait)
		if err != nil {
			return "", err
		}
		victim := filepath.Join(vault, "victim")
		if err := os.WriteFile(victim, nil, 0o600); err != nil {
			return "", err
		}
		unlinked, resolveErr := pinnedWaitRace(cpu, victim, func() error {
			return resolved.Put(self.tgid, encodeResolved(self.start, seq, LabelUnidentified))
		})
		if resolveErr != nil {
			return "", resolveErr
		}
		after, err := perCPUTotal(collection.Maps["LABEL_COUNTERS"], counterWait)
		if err != nil {
			return "", err
		}
		waited := after > before
		switch {
		case waited && unlinked == nil:
			return selfTestPassed, nil
		case waited && errors.Is(unlinked, unix.EPERM):
			return WaitOffSelfTest, nil
		case unlinked != nil && !errors.Is(unlinked, unix.EPERM):
			return "", fmt.Errorf("self-test unlink: %w", unlinked)
		}
		_ = os.Remove(victim)
		_ = resolved.Delete(self.tgid)
	}
	return "", errors.New("the label wait never started")
}

// pinnedWaitRace unlinks victim on one thread and runs resolve 5 ms later on
// another, both pinned to cpu. Both threads stay locked, so they exit with
// their goroutines instead of returning to the scheduler pinned.
func pinnedWaitRace(cpu int, victim string, resolve func() error) (unlinked, resolveErr error) {
	ready := make(chan struct{})
	unlinkDone := make(chan error, 1)
	resolveDone := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := pinThread(cpu); err != nil {
			close(ready)
			unlinkDone <- err
			return
		}
		close(ready)
		unlinkDone <- unix.Unlink(victim)
	}()
	go func() {
		runtime.LockOSThread()
		if err := pinThread(cpu); err != nil {
			resolveDone <- err
			return
		}
		<-ready
		time.Sleep(5 * time.Millisecond)
		resolveDone <- resolve()
	}()
	return <-unlinkDone, <-resolveDone
}

func pinThread(cpu int) error {
	var set unix.CPUSet
	set.Set(cpu)
	return unix.SchedSetaffinity(0, &set)
}

func firstAllowedCPU() (int, error) {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		return 0, err
	}
	for cpu := 0; cpu < len(set)*64; cpu++ {
		if set.IsSet(cpu) {
			return cpu, nil
		}
	}
	return 0, errors.New("no CPU in this thread's affinity")
}

func perCPUTotal(m *ebpf.Map, index uint32) (uint64, error) {
	values, err := perCPUValues()
	if err != nil {
		return 0, err
	}
	if err := m.Lookup(index, &values); err != nil {
		return 0, err
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return total, nil
}

func zeroPerCPU(m *ebpf.Map, slots int) error {
	values, err := perCPUValues()
	if err != nil {
		return err
	}
	for index := range slots {
		if err := m.Put(uint32(index), values); err != nil {
			return err
		}
	}
	return nil
}

func ignoreMissing(err error) error {
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// labelWaitCounters reads the wait counters into status.
func labelWaitCounters(collection *ebpf.Collection, status *LabelWait) error {
	if collection == nil || collection.Maps["LABEL_COUNTERS"] == nil {
		return nil
	}
	for index, field := range map[uint32]*uint64{
		counterWait:         &status.Waits,
		counterWaitResolved: &status.Resolved,
		counterWaitTimeout:  &status.TimedOut,
		counterWaitStale:    &status.SkippedStale,
		counterWaitBusy:     &status.SkippedBusy,
		counterWaitNS:       &status.WaitedNanos,
	} {
		total, err := perCPUTotal(collection.Maps["LABEL_COUNTERS"], index)
		if err != nil {
			return err
		}
		*field = total
	}
	return nil
}
