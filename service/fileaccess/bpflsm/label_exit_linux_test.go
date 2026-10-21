//go:build linux && !filemaster_test

package bpflsm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// profile is one label's test policy: whether its write rules allow in the
// scope, and whether the resolver should resolve a process to it at all (an
// unresolved key stays pending and so denies).
type labelProfile struct {
	label   uint32
	allow   bool
	resolve bool
}

// classifyArgs mirrors the interpreter/exe classification the daemon's
// process tags perform, reduced to what the exit test needs.
func classifyArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	base := filepath.Base(args[0])
	interp := base == "python3" || base == "python" || base == "bash" || base == "sh" || base == "node" || base == "perl"
	if !interp {
		return "exe:" + base
	}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-c":
			return "interp:" + base
		case arg == "-m":
			if i+1 < len(args) {
				return "mod:" + args[i+1]
			}
			return "interp:" + base
		case !strings.HasPrefix(arg, "-"):
			return "script:" + filepath.Base(arg)
		}
	}
	return "interp:" + base
}

func interpreterPath(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s is not installed in the VM", name)
	}
	return path
}

// TestLabellingExit is the M3 exit test: distinct interpreter scripts get
// distinct verdicts, a shebang script is labelled, -m resolves to the module
// and -c to the interpreter, a child inherits its own exec's label, a pending
// process denies, and a full label map denies and counts.
func TestLabellingExit(t *testing.T) {
	requireBPFLSM(t)
	python := interpreterPath(t, "python3")

	scope := t.TempDir()
	profiles := map[string]labelProfile{
		"script:a.py":      {label: 1, allow: true, resolve: true},
		"script:b.py":      {label: 2, allow: false, resolve: true},
		"script:x.py":      {label: 3, allow: true, resolve: true},
		"script:s.sh":      {label: 4, allow: true, resolve: true},
		"script:s.js":      {label: 5, allow: true, resolve: true},
		"script:s.pl":      {label: 6, allow: true, resolve: true},
		"mod:fmmod":        {label: 7, allow: true, resolve: true},
		"interp:python3":   {label: 8, allow: false, resolve: true},
		"exe:rm":           {label: 9, allow: true, resolve: true},
		"script:parent.py": {label: 10, allow: false, resolve: true},
		// script:pending.py is deliberately absent: the resolver leaves it pending.
	}

	var labels []LabelPolicy
	for _, profile := range profiles {
		policy := LabelPolicy{Label: profile.label}
		if profile.allow {
			policy.Rules = []RuleInput{{List: ListWrite, Pattern: scope + "/**", Allow: true}}
		}
		labels = append(labels, policy)
	}
	table, _, err := Compile(Policy{Scopes: []ScopeInput{{Path: scope}}, Labels: labels})
	if err != nil {
		t.Fatal(err)
	}

	var enf *Enforcer
	var learnMu sync.Mutex
	learned := make(map[string]bool)
	resolve := func(record Record) {
		key := classifyArgs(record.Args)
		profile, ok := profiles[key]
		if !ok || !profile.resolve {
			return
		}
		if err := enf.Resolve(record.TGID, record.Start, record.Seq, profile.label); err != nil {
			t.Logf("resolve %s: %v", key, err)
			return
		}
		// Learn the fast path only for a shebang script (keyed by its inode) or a
		// plain executable, never an interpreter exe-only, so distinct scripts run
		// by one interpreter do not collapse onto one label.
		if record.Script.Ino != 0 || strings.HasPrefix(key, "exe:") {
			_ = enf.LearnExec(record.Exe, record.Script, profile.label)
		}
		learnMu.Lock()
		learned[key] = true
		learnMu.Unlock()
	}

	pid := uint32(os.Getpid())
	root := "/sys/fs/bpf/filemaster-label-" + strconv.Itoa(os.Getpid())
	enf = NewEnforcerWithOptions(Options{
		PinRoot:     root,
		SelfTestDir: filepath.Join(t.TempDir(), "selftest"),
		DaemonPID:   &pid,
		Labelling:   true,
		OnRecord:    resolve,
	})
	t.Cleanup(func() { _ = enf.SetMode(ModeOff) })
	if err := enf.SetModeWithTable(ModeEnforce, table); err != nil {
		t.Fatalf("enforce: %v", err)
	}
	if status := enf.Status(); !status.Labelling.Enabled || len(status.Labelling.Programs) != len(labelPrograms) {
		t.Fatalf("labelling status = %+v", status.Labelling)
	}

	// runScript launches cmd, waits until the kernel labels its process (the
	// resolver answered the exec record), then releases the script, which
	// deletes victim. It returns whether the delete was allowed. gate makes
	// the window deterministic without the daemon's open hook.
	victimNum := 0
	runSynced := func(t *testing.T, resolveExpected bool, launch func(gate, victim string) *exec.Cmd) bool {
		t.Helper()
		victimNum++
		dir := filepath.Join(scope, "run"+strconv.Itoa(victimNum))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		gate := filepath.Join(dir, "gate")
		victim := filepath.Join(dir, "victim")
		if err := os.WriteFile(victim, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := launch(gate, victim)
		if err := cmd.Start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		child := uint32(cmd.Process.Pid)
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			proc, ok, err := enf.Proc(child)
			if err == nil && ok && proc.Label != LabelPending {
				break
			}
			if !resolveExpected && time.Now().After(deadline.Add(-6*time.Second)) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := os.WriteFile(gate, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		_ = cmd.Wait()
		_, err := os.Stat(victim)
		return os.IsNotExist(err)
	}

	// Direct interpreter cases use argv-named scripts; the name selects the
	// profile. a.py and b.py are the distinct-verdict pair.
	named := func(name, code string) func(gate, victim string) *exec.Cmd {
		return func(gate, victim string) *exec.Cmd {
			file := filepath.Join(filepath.Dir(victim), name)
			body := "import os,sys,time\n" +
				"while not os.path.exists(sys.argv[1]): time.sleep(0.005)\n" +
				code + "\n"
			if err := os.WriteFile(file, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			return exec.Command(python, file, gate, victim)
		}
	}
	unlinkCode := "try:\n os.unlink(sys.argv[2])\nexcept OSError: pass"

	if !runSynced(t, true, named("a.py", unlinkCode)) {
		t.Error("python a.py (allow profile): delete was denied")
	}
	if runSynced(t, true, named("b.py", unlinkCode)) {
		t.Error("python b.py (deny profile): delete was allowed")
	}

	// -m resolves to the module's profile (allow); -c to the interpreter (deny).
	modDir := filepath.Join(scope, "mod")
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "fmmod.py"),
		[]byte("import os,sys,time\nwhile not os.path.exists(sys.argv[1]): time.sleep(0.005)\n"+unlinkCode+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !runSynced(t, true, func(gate, victim string) *exec.Cmd {
		cmd := exec.Command(python, "-m", "fmmod", gate, victim)
		cmd.Env = append(os.Environ(), "PYTHONPATH="+modDir)
		return cmd
	}) {
		t.Error("python -m fmmod (allow module profile): delete was denied")
	}
	if runSynced(t, true, func(gate, victim string) *exec.Cmd {
		code := "import os,sys,time\nwhile not os.path.exists(sys.argv[1]): time.sleep(0.005)\n" + unlinkCode
		return exec.Command(python, "-c", code, gate, victim)
	}) {
		t.Error("python -c (deny interpreter profile): delete was allowed")
	}

	// A process the resolver never labels stays pending and so denies.
	if runSynced(t, false, named("pending.py", unlinkCode)) {
		t.Error("pending process: delete was allowed")
	}

	// env-shebang scripts for several interpreters.
	shebang := func(name, interp, body string) func(gate, victim string) *exec.Cmd {
		return func(gate, victim string) *exec.Cmd {
			file := filepath.Join(filepath.Dir(victim), name)
			if err := os.WriteFile(file, []byte("#!/usr/bin/env "+interp+"\n"+body+"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			return exec.Command(file, gate, victim)
		}
	}
	interpreterPath(t, "bash")
	if !runSynced(t, true, shebang("s.sh", "bash",
		`while [ ! -e "$1" ]; do sleep 0.01; done; rm -f "$2"`)) {
		t.Error("bash shebang script (allow): delete was denied")
	}
	if _, err := exec.LookPath("node"); err == nil {
		if !runSynced(t, true, shebang("s.js", "node",
			"const fs=require('fs');while(!fs.existsSync(process.argv[2])){}fs.unlinkSync(process.argv[3]);")) {
			t.Error("node shebang script (allow): delete was denied")
		}
	}
	if _, err := exec.LookPath("perl"); err == nil {
		if !runSynced(t, true, shebang("s.pl", "perl",
			`sleep 0.01 until -e $ARGV[0]; unlink $ARGV[1];`)) {
			t.Error("perl shebang script (allow): delete was denied")
		}
	}

	// A child rm spawned by a (deny) script gets rm's own (allow) label. The
	// parent runs twice: the first exec of rm is pending and denied while the
	// resolver learns it, the second is labelled at exec and allowed.
	rmRun := func() (parentDenied, childAllowed bool) {
		dir := filepath.Join(scope, "child"+strconv.Itoa(victimNum))
		victimNum++
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		gate := filepath.Join(dir, "gate")
		parentVictim := filepath.Join(dir, "parent-victim")
		childVictim := filepath.Join(dir, "child-victim")
		for _, v := range []string{parentVictim, childVictim} {
			if err := os.WriteFile(v, nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		script := "import os,sys,time,subprocess\n" +
			"while not os.path.exists(sys.argv[1]): time.sleep(0.005)\n" +
			"subprocess.call(['rm','-f',sys.argv[3]])\n" +
			"try:\n os.unlink(sys.argv[2])\nexcept OSError: pass\n"
		file := filepath.Join(dir, "parent.py")
		if err := os.WriteFile(file, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(python, file, gate, parentVictim, childVictim)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		child := uint32(cmd.Process.Pid)
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if proc, ok, err := enf.Proc(child); err == nil && ok && proc.Label != LabelPending {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		_ = os.WriteFile(gate, nil, 0o644)
		_ = cmd.Wait()
		_, perr := os.Stat(parentVictim)
		_, cerr := os.Stat(childVictim)
		return os.IsNotExist(perr) == false, os.IsNotExist(cerr)
	}
	rmRun() // first run learns rm's label
	parentDenied, childAllowed := rmRun()
	if !parentDenied {
		t.Error("child-rm parent (deny profile): parent delete was allowed")
	}
	if !childAllowed {
		t.Error("child rm (allow profile): child delete was denied")
	}
}

// TestLabelMapFullDenies fills the label map so a new process cannot be
// recorded; it must deny and count, never run unlabelled.
func TestLabelMapFullDenies(t *testing.T) {
	requireBPFLSM(t)
	python := interpreterPath(t, "python3")

	scope := t.TempDir()
	table, _, err := Compile(Policy{
		Scopes: []ScopeInput{{Path: scope}},
		Labels: []LabelPolicy{{Label: LabelUnidentified}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pid := uint32(os.Getpid())
	root := "/sys/fs/bpf/filemaster-mapfull-" + strconv.Itoa(os.Getpid())
	enf := NewEnforcerWithOptions(Options{
		PinRoot:     root,
		SelfTestDir: filepath.Join(t.TempDir(), "selftest"),
		DaemonPID:   &pid,
		Labelling:   true,
		MaxProcs:    8,
		OnRecord:    func(Record) {},
	})
	t.Cleanup(func() { _ = enf.SetMode(ModeOff) })
	if err := enf.SetModeWithTable(ModeEnforce, table); err != nil {
		t.Fatalf("enforce: %v", err)
	}

	victim := filepath.Join(scope, "victim")
	if err := os.WriteFile(victim, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// Fork a storm of short-lived processes to exhaust the tiny PROCS map.
	script := "import os,subprocess,sys,time\n" +
		"ps=[subprocess.Popen(['sleep','1']) for _ in range(64)]\n" +
		"time.sleep(0.3)\n" +
		"try:\n    os.unlink(sys.argv[1])\nexcept OSError:\n    pass\n"
	file := filepath.Join(scope, "storm.py")
	if err := os.WriteFile(file, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, file, victim)
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	if _, err := os.Stat(victim); os.IsNotExist(err) {
		t.Error("map-full process deleted the victim; it should have been denied")
	}
	status := enf.Status()
	if status.Labelling.MapFull == 0 {
		t.Errorf("label map-full counter did not increment: %+v", status.Labelling)
	}
}
