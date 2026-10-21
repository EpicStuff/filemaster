package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
)

// LABEL_COUNTERS slots of the label wait (label_maps.rs).
const (
	counterWait = 3 + iota
	counterWaitResolved
	counterWaitTimeout
	counterWaitStale
	counterWaitBusy
	counterWaitNS
	labelCounters
)

// waitMatrix runs the label-wait and narrowed-PENDING scenarios, each against
// a freshly started daemon, so learned labels never carry over.
func waitMatrix() {
	rm, mv := realPath(lookPath("rm")), realPath(lookPath("mv"))
	allow := map[string]any{"fileaccess": map[string]any{"writeRules": []string{"+ " + *scope + "/**"}}}
	deny := map[string]any{"fileaccess": map[string]any{"writeRules": []string{"- " + *scope + "/**"}}}
	path := func(value string) []map[string]string {
		return []map[string]string{{"Type": "path", "Operation": "equals", "Value": value}}
	}
	base := func() {
		putProfile("rm", path(rm), allow)
		putProfile("mv", path(mv), allow)
	}
	native := func(waits string) {
		immediate("rm", rm, "rm", false, true, waits)
		immediate("mv", mv, "mv", false, true, waits)
		measure("rm (fresh copy)", rm, "rm")
		measure("mv (fresh copy)", mv, "mv")
	}

	fmt.Println("== wait (a): no cmdline/env profiles ==")
	freshDaemon()
	base()
	native("none after the first exec")
	learningState()

	fmt.Println("== wait (b): an unrelated cmdline profile (^python3 -c) ==")
	freshDaemon()
	base()
	putProfile("python3 -c", []map[string]string{{"Type": "cmdline", "Operation": "regex", "Value": `^python3 -c`}}, deny)
	native("none after the first exec")
	learningState()

	fmt.Println("== wait (c): a cmdline profile for rm itself ==")
	freshDaemon()
	base()
	rmCmdline := []map[string]string{{"Type": "cmdline", "Operation": "regex", "Value": `^rm --interactive=never `}}
	putProfile("rm --interactive=never", rmCmdline, deny)
	immediate("rm -f (path profile, allow)", rm, "rm", false, true, "every run")
	immediateArgs("rm --interactive=never (cmdline profile, deny)", rm, "rm", false, false, "every run", "--interactive=never")
	immediate("mv (not claimed)", mv, "mv", false, true, "none after the first exec")
	measure("rm (fresh copy named rm)", rm, "rm")
	learningState()

	fmt.Println("== wait (d): an env profile ==")
	freshDaemon()
	base()
	envPrint := []map[string]string{{"Type": "env", "Key": "FM_LIVE_DENY", "Operation": "equals", "Value": "1"}}
	putProfile("FM_LIVE_DENY=1", envPrint, deny)
	native("every run")
	immediateEnv("FM_LIVE_DENY=1 rm (env profile, deny)", rm, "rm", false, false, "every run", []string{"FM_LIVE_DENY=1"})
	learningState()
	burst(rm)

	if !waitEnabled {
		fmt.Println("  (e) and (f) need the label wait, which is off on this kernel")
		return
	}
	fmt.Println("== wait (e): wait disabled by configuration ==")
	setLabelWait(false)
	immediate("rm (env profile present; wait off)", rm, "rm", false, false, "none")
	putProfile("rm --interactive=never", rmCmdline, deny)
	immediate("rm (cmdline profile present; wait off)", rm, "rm", false, false, "none")
	setLabelWait(true)
	immediate("rm (wait back on)", rm, "rm", false, true, "every run")

	fmt.Println("== wait (f): daemon SIGKILLed ==")
	before := waitCounters()
	must(daemon.Process.Signal(syscall.SIGKILL))
	_, _ = daemon.Process.Wait()
	daemon = nil
	start := time.Now()
	allowed, timedOut := 0, 0
	for time.Since(start) < 2*time.Second {
		if runImmediate(rm, "rm", false, nil) {
			allowed++
		}
		timedOut++
	}
	after := waitCounters()
	fmt.Printf("  first 2 s after the kill (heartbeat fresh): %d runs, %d allowed, waits +%d, timed out +%d\n",
		timedOut, allowed, after[counterWait]-before[counterWait], after[counterWaitTimeout]-before[counterWaitTimeout])
	time.Sleep(waitStale + time.Second - time.Since(start))
	before = waitCounters()
	var latencies []time.Duration
	allowed = 0
	for i := 0; i < *runs; i++ {
		begin := time.Now()
		if runImmediate(rm, "rm", false, nil) {
			allowed++
		}
		latencies = append(latencies, time.Since(begin))
	}
	after = waitCounters()
	stale := after[counterWaitStale] - before[counterWaitStale]
	report(allowed == 0 && after[counterWait] == before[counterWait] && stale == uint64(*runs),
		fmt.Sprintf("after the heartbeat went stale: %d/%d allowed, waits +%d, skipped as stale +%d, rm run time %s",
			allowed, *runs, after[counterWait]-before[counterWait], stale, quantiles(latencies)))
}

const waitStale = 3 * time.Second

// waitEnabled is whether the current daemon's label wait is on; without it,
// a pending caller is denied as before.
var waitEnabled bool

// freshDaemon stops any daemon and starts one in enforce mode on a new data
// directory.
func freshDaemon() {
	stopDaemon()
	must(os.RemoveAll(*dataDir))
	must(startDaemon("enforce"))
	must(setMode("enforce"))
	if !waitLabelled(uint32(os.Getpid()), 30*time.Second) {
		must(errors.New("the daemon did not seed this process's label"))
	}
	d, err := getDiagnostics()
	must(err)
	w := d.Structural.Labelling.Wait
	waitEnabled = w.State == "on"
	fmt.Printf("  label wait: %s (self-test %q, max waiters %d)\n", w.State, w.SelfTest, w.MaxWaiters)
	for _, warning := range d.Warnings {
		if warning.ID == "bpf-lsm-label-wait-unavailable" {
			fmt.Printf("  diagnostics warning: %s (%s)\n", warning.Message, warning.Details)
		}
	}
}

func stopDaemon() {
	if wsConn != nil {
		wsConn.Close()
		wsConn = nil
	}
	if daemon != nil && daemon.Process != nil {
		_ = daemon.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = daemon.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = daemon.Process.Kill()
		}
	}
	daemon = nil
	_ = exec.Command(*corePath, "bpf-teardown").Run()
}

func setLabelWait(enabled bool) {
	reply := dbRequest(fmt.Sprintf(`update|config:fileaccess/structuralLabelWait|J{"Value":%v}`, enabled))
	if !strings.Contains(reply, "|success") {
		must(fmt.Errorf("set label wait: %s", reply))
	}
	want := "off: disabled by configuration"
	if enabled {
		want = "on"
	}
	for i := 0; i < 50; i++ {
		if d, err := getDiagnostics(); err == nil && d.Structural.Labelling.Wait.State == want {
			// The kernel switch follows at the heartbeat this kicked.
			time.Sleep(100 * time.Millisecond)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	must(fmt.Errorf("label wait did not become %q", want))
}

func learningState() {
	if d, err := getDiagnostics(); err == nil {
		fmt.Printf("  exe-only learning: %s\n", d.Structural.Labelling.ExeLearning)
	}
}

func immediate(name, binary, argv0 string, fresh, wantAllowed bool, waits string) {
	immediateEnvArgs(name, binary, argv0, fresh, wantAllowed, waits, nil)
}

// measure is immediate for a fresh copy, which is a new profile each run: its
// resolution republishes the table, so it can outlast the wait cap, and its
// verdicts are measured rather than checked.
func measure(name, binary, argv0 string) {
	immediateEnvArgs(name, binary, argv0, true, true, "every run", nil)
}

func immediateArgs(name, binary, argv0 string, fresh, wantAllowed bool, waits string, args ...string) {
	immediateEnvArgs(name, binary, argv0, fresh, wantAllowed, waits, nil, args...)
}

func immediateEnv(name, binary, argv0 string, fresh, wantAllowed bool, waits string, env []string) {
	immediateEnvArgs(name, binary, argv0, fresh, wantAllowed, waits, env)
}

// immediateEnvArgs runs binary (or a fresh copy of it) as argv0 *runs times;
// each run deletes (rm) or moves (mv) a victim in the scope as its first
// action. A warm-up run lets the daemon learn the binary first. It reports
// the verdicts and, per run, the label wait the kernel counted.
func immediateEnvArgs(name, binary, argv0 string, fresh, wantAllowed bool, waits string, env []string, args ...string) {
	check := !fresh
	if !waitEnabled && waits == "every run" {
		wantAllowed = false
	}
	if !fresh {
		runImmediate(binary, argv0, false, env, args...)
		time.Sleep(200 * time.Millisecond)
	}
	before := waitCounters()
	allowed := 0
	var waited []time.Duration
	for i := 0; i < *runs; i++ {
		run := waitCounters()
		if runImmediate(binary, argv0, fresh, env, args...) {
			allowed++
		}
		if after := waitCounters(); after[counterWait] > run[counterWait] {
			waited = append(waited, time.Duration(after[counterWaitNS]-run[counterWaitNS]))
		}
	}
	after := waitCounters()
	want := *runs
	if !wantAllowed {
		want = 0
	}
	line := fmt.Sprintf("%s: %d/%d allowed; waits %d (resolved %d, timed out %d, busy %d, stale %d; expected %s)",
		name, allowed, *runs, after[counterWait]-before[counterWait], after[counterWaitResolved]-before[counterWaitResolved],
		after[counterWaitTimeout]-before[counterWaitTimeout], after[counterWaitBusy]-before[counterWaitBusy],
		after[counterWaitStale]-before[counterWaitStale], waits)
	if len(waited) > 0 {
		line += "; wait " + quantiles(waited)
	}
	if !check {
		fmt.Printf("  info %s\n", line)
		return
	}
	// A timed-out wait denies, fail closed; it is reported, never a wrong label.
	timedOut := int(after[counterWaitTimeout] - before[counterWaitTimeout])
	report(allowed == want || (wantAllowed && allowed+timedOut == *runs), line)
}

// runImmediate deletes or moves a fresh victim with binary run as argv0 and
// reports whether the operation happened.
func runImmediate(binary, argv0 string, fresh bool, env []string, args ...string) bool {
	if fresh {
		dir, err := os.MkdirTemp(*outside, "copy")
		must(err)
		data, err := os.ReadFile(binary)
		must(err)
		copied := filepath.Join(dir, filepath.Base(binary))
		write(copied, string(data), 0o755)
		binary = copied
	}
	dir, err := os.MkdirTemp(*scope, "imm")
	must(err)
	victim := filepath.Join(dir, "victim")
	write(victim, "", 0o644)
	argv := append([]string{argv0}, args...)
	if filepath.Base(binary) == "mv" {
		argv = append(argv, victim, filepath.Join(dir, "moved"))
	} else {
		if len(args) == 0 {
			argv = append(argv, "-f")
		}
		argv = append(argv, victim)
	}
	cmd := &exec.Cmd{Path: binary, Args: argv, Env: append(os.Environ(), env...)}
	_ = cmd.Run()
	_, err = os.Stat(victim)
	return errors.Is(err, os.ErrNotExist)
}

// burst starts more pending deleters than there are CPUs at once and samples
// the kernel's waiter count while they run.
func burst(rm string) {
	n := 4 * runtimeCPUs()
	waiters := pinnedMap("WAITERS")
	defer waiters.Close()
	var peak atomic.Uint64
	stop := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			select {
			case <-stop:
				return
			default:
			}
			var value uint64
			if waiters.Lookup(uint32(0), &value) == nil && value > peak.Load() {
				peak.Store(value)
			}
		}
	}()
	before := waitCounters()
	var wg sync.WaitGroup
	var allowed atomic.Int64
	start := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if runImmediate(rm, "rm", false, nil) {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	took := time.Since(start)
	close(stop)
	<-sampled
	after := waitCounters()
	var left uint64
	_ = waiters.Lookup(uint32(0), &left)
	d, _ := getDiagnostics()
	limit := uint64(d.Structural.Labelling.Wait.MaxWaiters)
	// WAITERS counts claims, and a losing claim passes the cap for the instant
	// before its undo, so the sampled peak may exceed it by the racing callers.
	report(left == 0 && took < 10*time.Second,
		fmt.Sprintf("burst of %d pending rm at once: %d allowed in %v; waits %d (resolved %d, timed out %d), skipped busy %d; peak sampled claims %d (cap %d), after %d",
			n, allowed.Load(), took.Round(time.Millisecond), after[counterWait]-before[counterWait],
			after[counterWaitResolved]-before[counterWaitResolved], after[counterWaitTimeout]-before[counterWaitTimeout],
			after[counterWaitBusy]-before[counterWaitBusy], peak.Load(), limit, left))
}

func runtimeCPUs() int {
	data, err := os.ReadFile("/sys/devices/system/cpu/online")
	must(err)
	count := 0
	for _, part := range strings.Split(strings.TrimSpace(string(data)), ",") {
		var lo, hi int
		if n, _ := fmt.Sscanf(part, "%d-%d", &lo, &hi); n == 2 {
			count += hi - lo + 1
		} else {
			count++
		}
	}
	return count
}

// waitCounters sums the active generation's per-CPU LABEL_COUNTERS.
func waitCounters() [labelCounters]uint64 {
	var totals [labelCounters]uint64
	m := pinnedMap("LABEL_COUNTERS")
	defer m.Close()
	count, err := ebpf.PossibleCPU()
	must(err)
	for index := range labelCounters {
		values := make([]uint64, count)
		must(m.Lookup(uint32(index), &values))
		for _, value := range values {
			totals[index] += value
		}
	}
	return totals
}

func pinnedMap(name string) *ebpf.Map {
	entries, err := os.ReadDir(pinRoot)
	must(err)
	if len(entries) == 0 {
		must(errors.New("no pinned generation"))
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinRoot, entries[len(entries)-1].Name(), name), nil)
	must(err)
	return m
}

func quantiles(samples []time.Duration) string {
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	ms := func(d time.Duration) string { return strconv.FormatFloat(float64(d)/1e6, 'f', 2, 64) }
	return fmt.Sprintf("median/p90/max %s/%s/%s ms over %d", ms(samples[len(samples)/2]),
		ms(samples[len(samples)*9/10]), ms(samples[len(samples)-1]), len(samples))
}
