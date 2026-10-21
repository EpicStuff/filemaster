// Command bpflsm-live drives a real filemaster-core daemon end to end to check
// BPF LSM process labelling (M3). Run it as root on a BPF-LSM kernel; it starts
// the daemon itself, creates per-app profiles through the daemon's database
// websocket API (the UI's path), switches structural enforcement to enforce,
// and observes the verdicts real processes get on unlink inside the watched
// scope. Profile resolution is the daemon's own GetProcessWithProfile path.
//
//	bpflsm-live -core ./filemaster-core -scope /srv/watched
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/gorilla/websocket"
	"golang.org/x/sys/unix"

	"github.com/safing/portmaster/service/profile"
)

const (
	apiBase      = "http://127.0.0.1:818/api/v1/fileaccess/diagnostics"
	pinRoot      = "/sys/fs/bpf/filemaster"
	labelPending = 0xFFFFFFFF
)

var (
	corePath  = flag.String("core", "./filemaster-core", "filemaster-core binary")
	scope     = flag.String("scope", "/srv/watched", "watched scope (created fresh)")
	outside   = flag.String("outside", "/mnt/fm-unwatched", "tmpfs mounted outside every watched mount")
	dataDir   = flag.String("data", "/tmp/fm-live", "daemon data directory (created fresh)")
	runs      = flag.Int("runs", 50, "PENDING-window samples per placement")
	debug     = flag.Bool("debug", false, "print the daemon's process record for each case")
	waitOnly  = flag.Bool("wait-only", false, "run only the label-wait matrix")
	failures  int
	daemon    *exec.Cmd
	wsConn    *websocket.Conn
	messageID int
)

func main() {
	flag.Parse()
	defer cleanup()
	must(setup())
	if *waitOnly {
		waitMatrix()
		finish()
		return
	}

	python := realPath(lookPath("python3"))
	bash := realPath(lookPath("bash"))
	perl := realPath(lookPath("perl"))
	rm := realPath(lookPath("rm"))
	allow := map[string]any{"fileaccess": map[string]any{"writeRules": []string{"+ " + *scope + "/**"}}}
	deny := map[string]any{"fileaccess": map[string]any{"writeRules": []string{"- " + *scope + "/**"}}}
	none := map[string]any{}

	scripts := filepath.Join(*scope, "scripts")
	gated := func(body string) string {
		return "import os,sys,time\nwhile not os.path.exists(sys.argv[1]): time.sleep(0.002)\n" + body + "\n"
	}
	unlinkLast := "try:\n    os.unlink(sys.argv[-1])\nexcept OSError:\n    pass"
	write(filepath.Join(scripts, "a.py"), gated(unlinkLast), 0o644)
	write(filepath.Join(scripts, "b.py"), gated(unlinkLast), 0o644)
	write(filepath.Join(scripts, "x.py"), "#!/usr/bin/python3\n"+gated(unlinkLast), 0o755)
	write(filepath.Join(scripts, "s.sh"), "#!/usr/bin/bash\nwhile [ ! -e \"$1\" ]; do sleep 0.002; done\nrm -f \"${@: -1}\"\n", 0o755)
	write(filepath.Join(scripts, "s.pl"), "#!/usr/bin/perl\nselect(undef,undef,undef,0.002) until -e $ARGV[0];\nunlink $ARGV[-1];\n", 0o755)
	write(filepath.Join(scripts, "parent.py"), gated("import subprocess\nsubprocess.call(['rm','-f',sys.argv[3]])\n"+strings.ReplaceAll(unlinkLast, "sys.argv[-1]", "sys.argv[2]")), 0o644)
	write(filepath.Join(scripts, "a2.py"), gated(unlinkLast), 0o644)
	write(filepath.Join(scripts, "b2.py"), gated(unlinkLast), 0o644)
	write(filepath.Join(scripts, "x2.py"), "#!/usr/bin/env python3\n"+gated(unlinkLast), 0o755)
	write(filepath.Join(scripts, "fmmod.py"), gated(unlinkLast), 0o644)
	// PENDING-window scripts: the very first action is the unlink.
	firstUnlink := "import os,sys\ntry:\n    os.unlink(sys.argv[1])\nexcept OSError:\n    pass\n"
	pin := filepath.Join(scripts, "pin.py")
	pout := filepath.Join(*outside, "pout.py")
	write(pin, firstUnlink, 0o644)
	write(pout, firstUnlink, 0o644)

	must(startDaemon("off"))
	tag := func(key, value string) []map[string]string {
		return []map[string]string{{"Type": "tag", "Key": key, "Operation": "equals", "Value": value}}
	}
	path := func(value string) []map[string]string {
		return []map[string]string{{"Type": "path", "Operation": "equals", "Value": value}}
	}
	cmdline := func(regex string) []map[string]string {
		return []map[string]string{{"Type": "cmdline", "Operation": "regex", "Value": regex}}
	}

	fmt.Println("== phase 1: tag and path profiles (no cmdline/env fingerprints) ==")
	// Interpreter fallbacks keep every interpreter process on a path profile, so
	// the daemon never auto-creates a tag profile that would outrank the tests'.
	putProfile("python3 (interpreter)", path(python), deny)
	putProfile("bash (interpreter)", path(bash), none)
	putProfile("perl (interpreter)", path(perl), none)
	putProfile("rm", path(rm), allow)
	putProfile("a.py", tag("python-script", filepath.Join(scripts, "a.py")), allow)
	putProfile("b.py", tag("python-script", filepath.Join(scripts, "b.py")), deny)
	putProfile("x.py", tag("python-script", filepath.Join(scripts, "x.py")), allow)
	putProfile("s.sh", tag("shell-script", filepath.Join(scripts, "s.sh")), deny)
	putProfile("s.pl", tag("perl-script", filepath.Join(scripts, "s.pl")), allow)
	putProfile("parent.py", tag("python-script", filepath.Join(scripts, "parent.py")), deny)
	putProfile("pin.py", tag("python-script", pin), allow)
	putProfile("pout.py", tag("python-script", pout), allow)
	must(setMode("enforce"))
	// This process predates the generation; it is seeded from /proc.
	if !waitLabelled(uint32(os.Getpid()), 30*time.Second) {
		must(errors.New("the daemon did not seed this process's label"))
	}

	expect("python3 a.py (allow profile)", true, python, filepath.Join(scripts, "a.py"))
	expect("python3 b.py (deny profile)", false, python, filepath.Join(scripts, "b.py"))
	expect("./x.py #!/usr/bin/python3 (allow)", true, filepath.Join(scripts, "x.py"))
	expect("./s.pl #!/usr/bin/perl (allow)", true, filepath.Join(scripts, "s.pl"))
	expectCode("python3 -c (interpreter profile, deny)", false, python, "-c")
	childRm(python, filepath.Join(scripts, "parent.py"))
	// bash deletes through an rm child, so rm's own (allow) profile decides,
	// although the script's profile denies.
	expect("./s.sh #!/usr/bin/bash (deny profile; its rm child allows)", true, filepath.Join(scripts, "s.sh"))

	fmt.Println("-- profile rule edit through the API, no restart --")
	putProfile("b.py", tag("python-script", filepath.Join(scripts, "b.py")), allow)
	start := time.Now()
	changed := false
	for time.Since(start) < 15*time.Second {
		if run(python, filepath.Join(scripts, "b.py")) {
			changed = true
			break
		}
	}
	report(changed, fmt.Sprintf("b.py flipped deny -> allow after edit (%v)", time.Since(start).Round(time.Millisecond)))

	fmt.Println("-- PENDING window (first action unlinks; profile allows) --")
	latency(python, pout)
	window("script outside watched mounts", python, pout)
	window("script inside the watched scope", python, pin)
	nativeWindow(rm)

	fmt.Println("== phase 2: cmdline profiles (bare interpreter argv0) ==")
	putProfile("a2.py", cmdline(`/a2\.py `), allow)
	putProfile("b2.py", cmdline(`/b2\.py `), deny)
	putProfile("x2.py", cmdline(`/x2\.py `), allow)
	putProfile("fmmod", cmdline(`-m fmmod `), allow)
	expect("bare python3 a2.py (cmdline allow)", true, "python3", filepath.Join(scripts, "a2.py"))
	expect("bare python3 b2.py (cmdline deny)", false, "python3", filepath.Join(scripts, "b2.py"))
	expect("./x2.py #!/usr/bin/env python3 (allow)", true, filepath.Join(scripts, "x2.py"))
	expectEnv("python3 -m fmmod (module profile, allow)", true, []string{"PYTHONPATH=" + scripts}, "python3", "-m", "fmmod")
	expectCode("python3 -c (interpreter profile, deny)", false, "python3", "-c")

	if *debug {
		dumpProfiles()
	}
	if d, err := getDiagnostics(); err == nil {
		for _, u := range d.Structural.Undecided {
			fmt.Printf("  undecided %s %s=%d\n", u.Reason, u.Hook, u.Count)
		}
	}
	waitMatrix()
	finish()
}

func finish() {
	if failures > 0 {
		fmt.Printf("FAIL: %d check(s) failed\n", failures)
		cleanup()
		os.Exit(1)
	}
	fmt.Println("PASS")
}

// expect runs argv with a gate and a victim and checks the unlink verdict.
func expect(name string, allowed bool, argv ...string) {
	expectEnv(name, allowed, nil, argv...)
}

func expectEnv(name string, allowed bool, env []string, argv ...string) {
	before := pendingDenials()
	got := runEnv(env, argv...)
	detail := ""
	if !allowed && pendingDenials() != before {
		detail = " (denied as PENDING, not by its profile)"
		got = !allowed
	}
	report(got == allowed, fmt.Sprintf("%s: allowed=%v%s", name, got, detail))
}

// expectCode runs `python3 -c <gated unlink>`.
func expectCode(name string, allowed bool, python, flag string) {
	code := "import os,sys,time\nwhile not os.path.exists(sys.argv[1]): time.sleep(0.002)\ntry:\n    os.unlink(sys.argv[-1])\nexcept OSError:\n    pass\n"
	expect(name, allowed, python, flag, code)
}

func run(argv ...string) bool { return runEnv(nil, argv...) }

// runEnv appends a gate and a victim to argv, waits until the kernel labels
// the process, releases the gate and reports whether the victim was deleted.
func runEnv(env []string, argv ...string) bool {
	dir, err := os.MkdirTemp(*scope, "run")
	must(err)
	gate, victim := filepath.Join(dir, "gate"), filepath.Join(dir, "victim")
	write(victim, "", 0o644)
	cmd := exec.Command(argv[0], append(argv[1:], gate, victim)...)
	cmd.Env = append(os.Environ(), env...)
	must(cmd.Start())
	if !waitLabelled(uint32(cmd.Process.Pid), 10*time.Second) {
		fmt.Printf("    (%s was not labelled within 10s)\n", filepath.Base(argv[len(argv)-1]))
	}
	write(gate, "", 0o644)
	_ = cmd.Wait()
	_, err = os.Stat(victim)
	return errors.Is(err, os.ErrNotExist)
}

// dumpProfiles prints every local profile, for -debug.
func dumpProfiles() {
	messageID++
	id := strconv.Itoa(messageID)
	must(wsConn.WriteMessage(websocket.TextMessage, []byte(id+"|query|query core:profiles/local/")))
	_ = wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, reply, err := wsConn.ReadMessage()
		if err != nil || strings.HasPrefix(string(reply), id+"|done") {
			return
		}
		parts := strings.SplitN(string(reply), "|", 4)
		if len(parts) != 4 || parts[0] != id {
			continue
		}
		var p struct {
			ID           string
			Name         string
			Created      int64
			Fingerprints []map[string]string
		}
		if json.Unmarshal([]byte(strings.TrimPrefix(parts[3], "J")), &p) == nil {
			fmt.Printf("    profile %s %q created=%d %v\n", p.ID, p.Name, p.Created, p.Fingerprints)
		}
	}
}

// childRm runs a deny-profile parent that spawns rm (allow profile) and then
// unlinks its own victim. The first run lets the daemon learn rm.
func childRm(python, parent string) {
	var parentDeleted, childDeleted bool
	for i := 0; i < 2; i++ {
		dir, err := os.MkdirTemp(*scope, "child")
		must(err)
		gate := filepath.Join(dir, "gate")
		parentVictim, childVictim := filepath.Join(dir, "parent-victim"), filepath.Join(dir, "child-victim")
		write(parentVictim, "", 0o644)
		write(childVictim, "", 0o644)
		cmd := exec.Command(python, parent, gate, parentVictim, childVictim)
		must(cmd.Start())
		waitLabelled(uint32(cmd.Process.Pid), 10*time.Second)
		write(gate, "", 0o644)
		_ = cmd.Wait()
		_, perr := os.Stat(parentVictim)
		_, cerr := os.Stat(childVictim)
		parentDeleted, childDeleted = errors.Is(perr, os.ErrNotExist), errors.Is(cerr, os.ErrNotExist)
	}
	report(!parentDeleted && childDeleted,
		fmt.Sprintf("child rm of deny-profile parent: parent deleted=%v, rm deleted=%v", parentDeleted, childDeleted))
}

// latency measures spawn -> labelled for a gated process.
func latency(python, script string) {
	gatedScript := script + ".gated.py"
	write(gatedScript, "import os,sys,time\nwhile not os.path.exists(sys.argv[1]): time.sleep(0.002)\n", 0o644)
	var samples []time.Duration
	for i := 0; i < *runs; i++ {
		gate := filepath.Join(*outside, "gate"+strconv.Itoa(i))
		cmd := exec.Command(python, gatedScript, gate)
		start := time.Now()
		must(cmd.Start())
		if waitLabelled(uint32(cmd.Process.Pid), 5*time.Second) {
			samples = append(samples, time.Since(start))
		}
		write(gate, "", 0o644)
		_ = cmd.Wait()
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	if len(samples) == 0 {
		report(false, "spawn->label latency: no process was labelled")
		return
	}
	fmt.Printf("  spawn->label latency over %d: min %v, median %v, p90 %v, max %v\n", len(samples),
		samples[0].Round(time.Microsecond), samples[len(samples)/2].Round(time.Microsecond),
		samples[len(samples)*9/10].Round(time.Microsecond), samples[len(samples)-1].Round(time.Microsecond))
}

// window runs an ungated script whose first action is the unlink.
func window(name, python, script string) {
	before := pendingDenials()
	allowed := 0
	for i := 0; i < *runs; i++ {
		victim := filepath.Join(*scope, "pending-victim")
		write(victim, "", 0o644)
		_ = exec.Command(python, script, victim).Run()
		if _, err := os.Stat(victim); errors.Is(err, os.ErrNotExist) {
			allowed++
		}
	}
	fmt.Printf("  %s: %d/%d allowed, %d denied (label-pending denials +%d)\n",
		name, allowed, *runs, *runs-allowed, pendingDenials()-before)
}

// nativeWindow measures the worst case: the first exec of a never-seen native
// binary (a fresh copy of rm outside watched mounts, so no open hook and no
// learned label) that deletes at once.
func nativeWindow(rm string) {
	data, err := os.ReadFile(rm)
	must(err)
	before := pendingDenials()
	allowed := 0
	for i := 0; i < *runs; i++ {
		binary := filepath.Join(*outside, "rm-"+strconv.Itoa(i))
		write(binary, string(data), 0o755)
		victim := filepath.Join(*scope, "native-victim")
		write(victim, "", 0o644)
		_ = exec.Command(binary, "-f", victim).Run()
		if _, err := os.Stat(victim); errors.Is(err, os.ErrNotExist) {
			allowed++
		}
	}
	fmt.Printf("  first exec of a new native binary (rm copy, outside): %d/%d allowed, %d denied (label-pending denials +%d)\n",
		allowed, *runs, *runs-allowed, pendingDenials()-before)
}

// waitLabelled polls the active generation's pinned maps until pid has a
// label of its own image: a forked child carries this process's label until
// its exec replaces it, so that label does not count.
func waitLabelled(pid uint32, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if label, ok := effectiveLabel(pid); ok && (pid == uint32(os.Getpid()) || label != ownLabel()) {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func ownLabel() uint32 {
	label, ok := effectiveLabel(uint32(os.Getpid()))
	if !ok {
		return labelPending
	}
	return label
}

// effectiveLabel is the kernel's label for pid: its PROCS label, or the
// daemon's resolution of a pending record with the same start and sequence.
func effectiveLabel(pid uint32) (uint32, bool) {
	procs, resolved := openMaps()
	if procs == nil {
		return 0, false
	}
	defer closeMaps(procs, resolved)
	value := make([]byte, 24)
	if procs.Lookup(pid, value) != nil {
		return 0, false
	}
	if label := binary.LittleEndian.Uint32(value[20:]); label != labelPending {
		return label, true
	}
	r := make([]byte, 24)
	if resolved.Lookup(pid, r) == nil &&
		binary.LittleEndian.Uint64(r[0:]) == binary.LittleEndian.Uint64(value[0:]) &&
		binary.LittleEndian.Uint64(r[8:]) == binary.LittleEndian.Uint64(value[8:]) {
		return binary.LittleEndian.Uint32(r[16:]), true
	}
	return 0, false
}

func openMaps() (*ebpf.Map, *ebpf.Map) {
	entries, err := os.ReadDir(pinRoot)
	if err != nil || len(entries) == 0 {
		return nil, nil
	}
	dir := filepath.Join(pinRoot, entries[len(entries)-1].Name())
	procs, err := ebpf.LoadPinnedMap(filepath.Join(dir, "PROCS"), nil)
	if err != nil {
		return nil, nil
	}
	resolved, err := ebpf.LoadPinnedMap(filepath.Join(dir, "RESOLVED"), nil)
	if err != nil {
		procs.Close()
		return nil, nil
	}
	return procs, resolved
}

func closeMaps(maps ...*ebpf.Map) {
	for _, m := range maps {
		m.Close()
	}
}

type diagnostics struct {
	Structural struct {
		State     string
		Labelling struct {
			Enabled     bool
			ExeLearning string
			Wait        struct {
				State      string
				SelfTest   string
				MaxWaiters uint32
			}
		}
		Undecided []struct {
			Reason string
			Hook   string
			Count  uint64
		}
	}
	Warnings []struct {
		ID      string
		Message string
		Details string
	}
}

func getDiagnostics() (diagnostics, error) {
	var d diagnostics
	resp, err := http.Get(apiBase)
	if err != nil {
		return d, err
	}
	defer resp.Body.Close()
	return d, json.NewDecoder(resp.Body).Decode(&d)
}

func pendingDenials() uint64 {
	d, err := getDiagnostics()
	if err != nil {
		return 0
	}
	var total uint64
	for _, u := range d.Structural.Undecided {
		if u.Reason == "label-pending" {
			total += u.Count
		}
	}
	return total
}

func setup() error {
	if out, err := exec.Command("pgrep", "-x", "filemaster-core").Output(); err == nil && len(out) > 0 {
		return fmt.Errorf("a filemaster-core is already running (pids %s); stop it first", strings.Fields(string(out)))
	}
	_ = exec.Command(*corePath, "bpf-teardown").Run()
	for _, dir := range []string{*scope, *dataDir} {
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Join(*scope, "scripts"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(*outside, 0o755); err != nil {
		return err
	}
	_ = unix.Unmount(*outside, unix.MNT_DETACH)
	return unix.Mount("tmpfs", *outside, "tmpfs", 0, "mode=0755")
}

func startDaemon(mode string) error {
	must(os.MkdirAll(*dataDir, 0o755))
	config := fmt.Sprintf(`{"fileaccess":{"structuralEnforcement":%q,"watchPaths":["+ %s"]}}`, mode, *scope)
	write(filepath.Join(*dataDir, "config.json"), config, 0o644)
	log, err := os.Create(filepath.Join(os.TempDir(), "fm-live.log"))
	if err != nil {
		return err
	}
	daemon = exec.Command(*corePath, "--data-dir", *dataDir, "--log", "warning", "--devmode")
	daemon.Stdout, daemon.Stderr = log, log
	if err := daemon.Start(); err != nil {
		return err
	}
	for i := 0; i < 90; i++ {
		if _, err := getDiagnostics(); err == nil {
			conn, _, err := websocket.DefaultDialer.Dial("ws://127.0.0.1:818/api/database/v1", nil)
			if err != nil {
				return err
			}
			wsConn = conn
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.New("daemon did not come up")
}

func setMode(mode string) error {
	reply := dbRequest(fmt.Sprintf(`update|config:fileaccess/structuralEnforcement|J{"Value":%q}`, mode))
	if !strings.Contains(reply, "|success") {
		return fmt.Errorf("set mode: %s", reply)
	}
	for i := 0; i < 60; i++ {
		if d, err := getDiagnostics(); err == nil && d.Structural.State == "active" && d.Structural.Labelling.Enabled {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("structural enforcement did not become active with labelling")
}

// putProfile creates or updates a local profile through the database API,
// reading the current revision first as the UI does. The daemon renames a
// profile to the ID derived from its fingerprints, so that ID is used.
func putProfile(name string, fingerprints []map[string]string, config map[string]any) {
	var prints []profile.Fingerprint
	for _, fp := range fingerprints {
		prints = append(prints, profile.Fingerprint{Type: fp["Type"], Key: fp["Key"], Operation: fp["Operation"], Value: fp["Value"]})
	}
	id := profile.DeriveProfileID(prints)
	key := "core:profiles/local/" + id
	record := map[string]any{"ID": id, "Source": "local", "Name": name, "Fingerprints": fingerprints, "Config": config}
	op := "create"
	if reply := dbRequest("get|" + key); strings.Contains(reply, "|ok|") {
		parts := strings.SplitN(reply, "|", 4)
		var current map[string]any
		if len(parts) == 4 && json.Unmarshal([]byte(strings.TrimPrefix(parts[3], "J")), &current) == nil {
			record["Revision"] = current["Revision"]
			op = "update"
		}
	}
	data, err := json.Marshal(record)
	must(err)
	if reply := dbRequest(op + "|" + key + "|J" + string(data)); !strings.Contains(reply, "|success") {
		must(fmt.Errorf("put profile %s: %s", id, reply))
	}
	reply := dbRequest("get|" + key)
	parts := strings.SplitN(reply, "|", 4)
	var stored struct {
		ID           string
		Revision     int
		Config       map[string]any
		Fingerprints []map[string]string
	}
	if len(parts) != 4 || json.Unmarshal([]byte(strings.TrimPrefix(parts[3], "J")), &stored) != nil ||
		stored.ID != id || len(stored.Fingerprints) != len(fingerprints) {
		must(fmt.Errorf("profile %s did not persist as written: %.300s", id, reply))
	}
	if *debug {
		fmt.Printf("    put %s (%s) %s revision=%d config=%v\n", name, id, op, stored.Revision, stored.Config)
	}
}

func dbRequest(body string) string {
	messageID++
	id := strconv.Itoa(messageID)
	must(wsConn.WriteMessage(websocket.TextMessage, []byte(id+"|"+body)))
	_ = wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, reply, err := wsConn.ReadMessage()
		if err != nil {
			return "error: " + err.Error()
		}
		if strings.HasPrefix(string(reply), id+"|") {
			return string(reply)
		}
	}
}

func cleanup() {
	if wsConn != nil {
		wsConn.Close()
	}
	if daemon != nil && daemon.Process != nil {
		_ = daemon.Process.Signal(unix.SIGTERM)
		done := make(chan struct{})
		go func() { _ = daemon.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = daemon.Process.Kill()
		}
	}
	_ = exec.Command(*corePath, "bpf-teardown").Run()
	_ = unix.Unmount(*outside, unix.MNT_DETACH)
}

func report(ok bool, line string) {
	status := "ok  "
	if !ok {
		status = "FAIL"
		failures++
	}
	fmt.Printf("  %s %s\n", status, line)
}

func lookPath(name string) string {
	path, err := exec.LookPath(name)
	must(err)
	return path
}

func realPath(path string) string {
	real, err := filepath.EvalSymlinks(path)
	must(err)
	return real
}

func write(path, content string, mode os.FileMode) {
	must(os.WriteFile(path, []byte(content), mode))
}

func must(err error) {
	if err != nil {
		fmt.Println("fatal:", err)
		cleanup()
		os.Exit(2)
	}
}
