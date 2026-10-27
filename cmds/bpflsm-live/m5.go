package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/safing/portmaster/service/profile"
)

// The M5 hardening matrix against the real daemon: Open and Execute decisions
// under every structural mode, process labelling corner cases, common
// workflows in enforce, and a denied burst.

func m5Matrix() {
	fmt.Println("== M5: hardening matrix ==")
	must(startDaemon("off"))
	m5Coexistence()
	m5Labelling()
	m5Workflows()
	m5Pressure()
}

// m5Helper copies this binary to name outside every watched mount, so it is an
// app of its own.
func m5Helper(name string) string {
	self, err := os.Executable()
	must(err)
	target := filepath.Join(*outside, name)
	copyFile(self, target, 0o755)
	return target
}

func copyFile(from, to string, mode os.FileMode) {
	in, err := os.Open(from)
	must(err)
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	must(err)
	_, err = io.Copy(out, in)
	must(err)
	must(out.Close())
}

func pathFingerprint(path string) []map[string]string {
	return []map[string]string{{"Type": "path", "Operation": "equals", "Value": path}}
}

func tagFingerprint(key, value string) []map[string]string {
	return []map[string]string{{"Type": "tag", "Key": key, "Operation": "equals", "Value": value}}
}

func rules(defaultAction string, lists map[string][]string) map[string]any {
	fileaccess := make(map[string]any)
	for list, entries := range lists {
		fileaccess[list] = entries
	}
	config := map[string]any{"fileaccess": fileaccess}
	if defaultAction != "" {
		config["filter"] = map[string]any{"defaultAction": defaultAction}
	}
	return config
}

// setStructuralMode is setMode for any mode, including off.
func setStructuralMode(mode string) {
	if mode != "off" {
		must(setMode(mode))
		return
	}
	reply := dbRequest(`update|config:fileaccess/structuralEnforcement|J{"Value":"off"}`)
	if !strings.Contains(reply, "|success") {
		must(fmt.Errorf("set mode off: %s", reply))
	}
	for i := 0; i < 120; i++ {
		if d, err := getDiagnostics(); err == nil && d.Structural.Mode == "off" && d.Structural.State == "off" {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	must(errors.New("structural enforcement did not turn off"))
}

// attachedPrograms names the programs of every attached BPF link.
func attachedPrograms() []string {
	var names []string
	it := new(link.Iterator)
	defer it.Close()
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil {
			continue
		}
		program, err := ebpf.NewProgramFromID(info.Program)
		if err != nil {
			continue
		}
		if programInfo, err := program.Info(); err == nil {
			names = append(names, programInfo.Name)
		}
		_ = program.Close()
	}
	slices.Sort(names)
	return names
}

// promptRun runs helper op path and answers every Open/Execute prompt it
// raises for path with the action whose text is answer. It returns whether the
// operation succeeded and how many prompts were answered.
func promptRun(exe, op, path, answer string) (bool, int) {
	existing := make(map[string]bool)
	if notices, err := m4Notices(); err == nil {
		for _, notice := range notices {
			existing[notice.Key] = true
		}
	}
	cmd := exec.Command(exe, "--m4-helper", op, path)
	var output strings.Builder
	cmd.Stdout, cmd.Stderr = &output, &output
	must(cmd.Start())
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	answered := make(map[string]bool)
	deadline := time.After(60 * time.Second)
	for {
		select {
		case err := <-done:
			if err != nil && *debug {
				fmt.Printf("    prompt helper %s [%s %s]: %v %s\n", exe, op, path, err, output.String())
			}
			return err == nil, len(answered)
		case <-deadline:
			_ = cmd.Process.Kill()
			return false, len(answered)
		case <-time.After(100 * time.Millisecond):
		}
		notices, err := m4Notices()
		if err != nil {
			continue
		}
		for _, notice := range notices {
			if notice.Type != 2 || answered[notice.Key] || existing[notice.Key] || notice.SelectedActionID != "" ||
				!strings.Contains(notice.Message, path) || !strings.Contains(notice.Message, exe) {
				continue
			}
			for _, action := range notice.AvailableActions {
				if action.Text == answer {
					data, _ := json.Marshal(map[string]string{"SelectedActionID": action.ID})
					if strings.Contains(dbRequest("update|"+notice.Key+"|J"+string(data)), "|success") {
						answered[notice.Key] = true
					}
				}
			}
		}
	}
}

// m5Coexistence checks that fanotify's Open and Execute decisions, prompts
// included, are the same with structural enforcement off, in audit and in
// enforce, and that no BPF program ever attaches to file_open.
func m5Coexistence() {
	fmt.Println("-- coexistence (BPF-2): Open/Execute decisions and prompts under each structural mode --")
	base := filepath.Join(*scope, "coex")
	must(os.MkdirAll(base, 0o755))
	data := filepath.Join(base, "data")
	write(data, "coexistence\n", 0o644)
	tool := filepath.Join(base, "tool")
	copyFile(realPath(lookPath("true")), tool, 0o755)
	inScope := []string{"+ " + base + "/**"}
	outScope := []string{"- " + base + "/**"}
	ruleAllow, ruleDeny := m5Helper("coex-rule-allow"), m5Helper("coex-rule-deny")
	putProfile("coex rule allow", pathFingerprint(ruleAllow), rules("block", map[string][]string{"readRules": inScope, "execRules": inScope}))
	putProfile("coex rule deny", pathFingerprint(ruleDeny), rules("permit", map[string][]string{"readRules": outScope, "execRules": outScope}))

	outcomes := make(map[string]string)
	for _, mode := range []string{"off", "audit", "enforce"} {
		setStructuralMode(mode)
		programs := attachedPrograms()
		out, err := exec.Command("bpftool", "link", "show").CombinedOutput()
		report(err == nil && !strings.Contains(string(out), "file_open") && !slices.Contains(programs, "file_open"),
			fmt.Sprintf("%s: no file_open program attached (bpftool link: %d lines; LSM/tracing programs %v)", mode, strings.Count(string(out), "\n"), filemasterPrograms(programs)))
		report((mode == "off") == (len(filemasterPrograms(programs)) == 0), fmt.Sprintf("%s: structural programs attached=%v", mode, len(filemasterPrograms(programs)) > 0))

		askAllow, askBlock, askExec := m5Helper("coex-ask-allow-"+mode), m5Helper("coex-ask-block-"+mode), m5Helper("coex-ask-exec-"+mode)
		putProfile("coex ask allow "+mode, pathFingerprint(askAllow), rules("ask", nil))
		putProfile("coex ask block "+mode, pathFingerprint(askBlock), rules("ask", nil))
		putProfile("coex ask exec "+mode, pathFingerprint(askExec), rules("ask", nil))
		var outcome []string
		outcome = append(outcome, fmt.Sprintf("rule-allow open=%v exec=%v", m4Run(ruleAllow, "open", data), m4Run(ruleAllow, "exec", tool)))
		outcome = append(outcome, fmt.Sprintf("rule-deny open=%v exec=%v", m4Run(ruleDeny, "open", data), m4Run(ruleDeny, "exec", tool)))
		allowed, prompts := promptRun(askAllow, "open", data, "Allow")
		time.Sleep(2 * time.Second)
		if *debug {
			id := profile.DeriveProfileID([]profile.Fingerprint{{Type: "path", Operation: "equals", Value: askAllow}})
			fmt.Printf("    profile after Allow: %.1500s\n", dbRequest("get|core:profiles/local/"+id))
		}
		again, promptsAgain := promptRun(askAllow, "open", data, "Allow")
		outcome = append(outcome, fmt.Sprintf("ask+Allow open=%v prompts=%d, again open=%v prompts=%d", allowed, prompts, again, promptsAgain))
		allowed, prompts = promptRun(askBlock, "open", data, "Block")
		outcome = append(outcome, fmt.Sprintf("ask+Block open=%v prompts=%d", allowed, prompts))
		allowed, prompts = promptRun(askExec, "exec", tool, "Allow")
		time.Sleep(2 * time.Second)
		againExec, promptsAgainExec := promptRun(askExec, "exec", tool, "Allow")
		outcome = append(outcome, fmt.Sprintf("ask+Allow exec=%v prompts=%d, again exec=%v prompts=%d", allowed, prompts, againExec, promptsAgainExec))
		outcomes[mode] = strings.Join(outcome, "; ")
		fmt.Printf("  %s: %s\n", mode, outcomes[mode])
	}
	for _, mode := range []string{"off", "audit", "enforce"} {
		outcome := outcomes[mode]
		report(strings.HasPrefix(outcome, "rule-allow open=true exec=true; rule-deny open=false exec=false; ask+Allow open=true prompts=1, again open=true prompts=0;") &&
			strings.Contains(outcome, "; ask+Block open=false prompts=1;") && strings.Contains(outcome, "; ask+Allow exec=true prompts=") &&
			strings.HasSuffix(outcome, "again exec=true prompts=0") &&
			outcome == outcomes["off"],
			fmt.Sprintf("Open/Execute outcome under %s equals off and the expected decisions", mode))
	}
}

// filemasterPrograms keeps the structural and labelling programs.
func filemasterPrograms(programs []string) []string {
	var ours []string
	for _, name := range programs {
		if strings.HasPrefix(name, "inode_") || strings.HasPrefix(name, "bprm_") || strings.HasPrefix(name, "sched_process_") {
			ours = append(ours, name)
		}
	}
	return ours
}

// startGated starts argv with a gate and a victim appended, as runEnv does,
// without releasing the gate.
func startGated(argv ...string) (cmd *exec.Cmd, gate, victim string) {
	dir, err := os.MkdirTemp(*scope, "gated")
	must(err)
	gate, victim = filepath.Join(dir, "gate"), filepath.Join(dir, "victim")
	write(victim, "", 0o644)
	cmd = exec.Command(argv[0], append(argv[1:], gate, victim)...)
	must(cmd.Start())
	return cmd, gate, victim
}

// releaseGated opens the gate and reports whether the victim was deleted.
func releaseGated(cmd *exec.Cmd, gate, victim string) bool {
	write(gate, "", 0o644)
	_ = cmd.Wait()
	_, err := os.Stat(victim)
	return errors.Is(err, os.ErrNotExist)
}

func m5Labelling() {
	fmt.Println("-- labelling: interpreters, script forms, argv rewrite, fork/thread exec, restart, AppImage --")
	setStructuralMode("enforce")
	if !waitLabelled(uint32(os.Getpid()), 30*time.Second) {
		must(errors.New("the daemon did not seed this process's label"))
	}
	d, err := getDiagnostics()
	must(err)
	waitEnabled = d.Structural.Labelling.Wait.State == "on"
	fmt.Printf("  label wait: %s\n", d.Structural.Labelling.Wait.State)
	python, perl, node, rm := realPath(lookPath("python3")), realPath(lookPath("perl")), realPath(lookPath("node")), realPath(lookPath("rm"))
	scripts := filepath.Join(*scope, "m5-scripts")
	must(os.MkdirAll(scripts, 0o755))
	allow := rules("", map[string][]string{"writeRules": {"+ " + *scope + "/**"}})
	deny := rules("", map[string][]string{"writeRules": {"- " + *scope + "/**"}})
	putProfile("python3 (interpreter)", pathFingerprint(python), deny)
	putProfile("perl (interpreter)", pathFingerprint(perl), deny)
	putProfile("node (interpreter)", pathFingerprint(node), deny)
	putProfile("rm", pathFingerprint(rm), allow)

	gatedJS := "const fs = require('fs');\nconst [gate, victim] = process.argv.slice(-2);\n(function wait() { if (!fs.existsSync(gate)) return setTimeout(wait, 2); try { fs.unlinkSync(victim); } catch (e) {} })();\n"
	sJS, dJS := filepath.Join(scripts, "s.js"), filepath.Join(scripts, "d.js")
	write(sJS, "#!/usr/bin/node\n"+gatedJS, 0o755)
	write(dJS, "#!/usr/bin/node\n"+gatedJS, 0o755)
	putProfile("s.js", tagFingerprint("nodejs-script", sJS), allow)
	putProfile("d.js", tagFingerprint("nodejs-script", dJS), deny)
	expect("./s.js #!/usr/bin/node (script profile allows)", true, sJS)
	expect("node s.js (script profile allows)", true, node, sJS)
	expect("node d.js (script profile denies)", false, node, dJS)

	fmt.Println("  first action deletes (script open order; profiles allow):")
	firstPy, firstPl, firstJS := filepath.Join(scripts, "first.py"), filepath.Join(scripts, "first.pl"), filepath.Join(scripts, "first.js")
	write(firstPy, "import os,sys\ntry:\n    os.unlink(sys.argv[1])\nexcept OSError:\n    pass\n", 0o644)
	write(firstPl, "unlink $ARGV[0];\n", 0o644)
	write(firstJS, "try { require('fs').unlinkSync(process.argv[2]); } catch (e) {}\n", 0o644)
	putProfile("first.py", tagFingerprint("python-script", firstPy), allow)
	putProfile("first.pl", tagFingerprint("perl-script", firstPl), allow)
	putProfile("first.js", tagFingerprint("nodejs-script", firstJS), allow)
	for _, c := range []struct{ name, interpreter, script string }{
		{"python3 first.py", python, firstPy},
		{"perl first.pl", perl, firstPl},
		{"node first.js", node, firstJS},
	} {
		// Every run is allowed by its profile or denied because its label was
		// not resolved in time (fail closed); never denied otherwise.
		before := unresolvedDenials()
		allowed := 0
		for i := 0; i < *runs; i++ {
			victim := filepath.Join(*scope, "first-victim")
			write(victim, "", 0o644)
			_ = exec.Command(c.interpreter, c.script, victim).Run()
			if _, err := os.Stat(victim); errors.Is(err, os.ErrNotExist) {
				allowed++
			}
		}
		unresolved := unresolvedDenials() - before
		report(allowed+int(unresolved) == *runs && (allowed > 0 || !waitEnabled),
			fmt.Sprintf("%s: %d/%d allowed, %d denied unresolved (label-pending or label-wait-timeout)", c.name, allowed, *runs, unresolved))
	}
	// bash runs no unlink of its own: its rm child is labelled as rm, which
	// is learned first so the check does not measure rm's first exec.
	_ = exec.Command(rm, "-f", filepath.Join(*outside, "warm-up")).Run()
	time.Sleep(200 * time.Millisecond)
	firstSh := filepath.Join(scripts, "first.sh")
	write(firstSh, "rm -f \"$1\"\n", 0o644)
	putProfile("first.sh", tagFingerprint("shell-script", firstSh), deny)
	victim := filepath.Join(*scope, "sh-victim")
	write(victim, "", 0o644)
	_ = exec.Command(realPath(lookPath("bash")), firstSh, victim).Run()
	_, err = os.Stat(victim)
	report(errors.Is(err, os.ErrNotExist), "bash first.sh (deny profile): its rm child deletes under rm's allow profile")

	fmt.Println("  argv rewrite after start ($0 in perl):")
	rewriteAllowed, rewriteDenied := filepath.Join(scripts, "rewrite-allowed.pl"), filepath.Join(scripts, "rewrite-denied.pl")
	rewrite := func(to string) string {
		return fmt.Sprintf("$0 = %q;\nselect(undef,undef,undef,0.002) until -e $ARGV[0];\nunlink $ARGV[-1];\n", perl+" "+to)
	}
	write(rewriteAllowed, rewrite(rewriteDenied), 0o644)
	write(rewriteDenied, rewrite(rewriteAllowed), 0o644)
	putProfile("rewrite-allowed.pl", tagFingerprint("perl-script", rewriteAllowed), allow)
	putProfile("rewrite-denied.pl", tagFingerprint("perl-script", rewriteDenied), deny)
	for _, c := range []struct {
		script, other string
		allowed       bool
	}{{rewriteAllowed, rewriteDenied, true}, {rewriteDenied, rewriteAllowed, false}} {
		cmd, gate, victim := startGated(perl, c.script)
		waitLabelled(uint32(cmd.Process.Pid), 10*time.Second)
		var cmdline []byte
		for i := 0; i < 100 && !strings.Contains(string(cmdline), c.other); i++ {
			time.Sleep(10 * time.Millisecond)
			cmdline, _ = os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", cmd.Process.Pid))
		}
		rewritten := strings.Contains(string(cmdline), c.other)
		got := releaseGated(cmd, gate, victim)
		report(rewritten && got == c.allowed, fmt.Sprintf("%s rewrote its cmdline to %s (%v): allowed=%v, its own profile", filepath.Base(c.script), filepath.Base(c.other), rewritten, got))
	}

	fmt.Println("  fork and exec ordering:")
	forkPy := filepath.Join(scripts, "fork.py")
	write(forkPy, "import os,sys,time\nwhile not os.path.exists(sys.argv[1]): time.sleep(0.002)\npid = os.fork()\nif pid == 0:\n    try:\n        os.unlink(sys.argv[-1])\n    except OSError:\n        pass\n    os._exit(0)\nos.waitpid(pid, 0)\n", 0o644)
	putProfile("fork.py", tagFingerprint("python-script", forkPy), deny)
	expect("deny-profile python forks; the child (no exec) deletes", false, python, forkPy)
	threadPy, threadAllowPy := filepath.Join(scripts, "thread.py"), filepath.Join(scripts, "thread-allow.py")
	threadExec := "import os,sys,time,threading\nwhile not os.path.exists(sys.argv[-2]): time.sleep(0.002)\ndef run():\n    os.execv(sys.argv[1], sys.argv[1:-2] + [sys.argv[-1]])\nt = threading.Thread(target=run)\nt.start()\nt.join()\n"
	write(threadPy, threadExec, 0o644)
	write(threadAllowPy, threadExec, 0o644)
	putProfile("thread.py", tagFingerprint("python-script", threadPy), deny)
	putProfile("thread-allow.py", tagFingerprint("python-script", threadAllowPy), allow)
	denyHelper := m5Helper("m5-deny-helper")
	putProfile("m5 deny helper", pathFingerprint(denyHelper), deny)
	// Learned first, so it is denied by its profile, not as a pending first exec.
	report(m4Run(denyHelper, "noop"), "deny helper learned")
	expect("deny-profile python: a non-leader thread execs rm (allow)", true, python, threadPy, rm, "-f")
	expect("allow-profile python: a non-leader thread execs the deny helper", false, python, threadAllowPy, denyHelper, "--m4-helper", "delete")

	fmt.Println("  daemon restart with live processes (seeded from /proc):")
	aPy, bPy := filepath.Join(scripts, "live-a.py"), filepath.Join(scripts, "live-b.py")
	gated := "import os,sys,time\nwhile not os.path.exists(sys.argv[1]): time.sleep(0.002)\ntry:\n    os.unlink(sys.argv[-1])\nexcept OSError:\n    pass\n"
	write(aPy, gated, 0o644)
	write(bPy, gated, 0o644)
	putProfile("live-a.py", tagFingerprint("python-script", aPy), allow)
	putProfile("live-b.py", tagFingerprint("python-script", bPy), deny)
	aCmd, aGate, aVictim := startGated(python, aPy)
	bCmd, bGate, bVictim := startGated(python, bPy)
	waitLabelled(uint32(aCmd.Process.Pid), 10*time.Second)
	waitLabelled(uint32(bCmd.Process.Pid), 10*time.Second)
	stopDaemonKeepingGeneration()
	cCmd, cGate, cVictim := startGated(python, aPy)
	time.Sleep(200 * time.Millisecond)
	must(startDaemon("enforce"))
	must(setMode("enforce"))
	waitLabelled(uint32(cCmd.Process.Pid), 30*time.Second)
	report(releaseGated(aCmd, aGate, aVictim), "allow script started before the restart: allowed")
	report(!releaseGated(bCmd, bGate, bVictim), "deny script started before the restart: denied")
	report(releaseGated(cCmd, cGate, cVictim), "allow script started while the daemon was down: allowed")

	appImage, appImageDeny := "/opt/FmApp.AppImage", "/opt/FmAppDeny.AppImage"
	if _, err := os.Stat(appImage); err != nil {
		fmt.Printf("  info AppImage checks skipped: %v\n", err)
		return
	}
	fmt.Println("  AppImage (squashfuse mount under /tmp/.mount_*, tagged by APPIMAGE):")
	putProfile("FmApp AppImage", tagFingerprint("app-image-path", appImage), allow)
	putProfile("FmAppDeny AppImage", tagFingerprint("app-image-path", appImageDeny), deny)
	// The AppImage runtime forks AppRun, so the gate opens after a delay
	// rather than once a known pid is labelled.
	for _, c := range []struct {
		image   string
		allowed bool
	}{{appImage, true}, {appImageDeny, false}} {
		dir, err := os.MkdirTemp(*scope, "appimage")
		must(err)
		gate, victim := filepath.Join(dir, "gate"), filepath.Join(dir, "victim")
		write(victim, "", 0o644)
		cmd := exec.Command(c.image, "--m4-helper", "gated-delete", gate, victim)
		must(cmd.Start())
		time.Sleep(time.Second)
		write(gate, "", 0o644)
		err = cmd.Wait()
		report((err == nil) == c.allowed, fmt.Sprintf("%s deletes: allowed=%v", filepath.Base(c.image), err == nil))
	}
}

func unresolvedDenials() uint64 {
	d, err := getDiagnostics()
	if err != nil {
		return 0
	}
	var total uint64
	for _, u := range d.Structural.Undecided {
		if u.Reason == "label-pending" || u.Reason == "label-wait-timeout" {
			total += u.Count
		}
	}
	return total
}

// stopDaemonKeepingGeneration stops the daemon the way a service stop does,
// leaving the pinned generation enforcing.
func stopDaemonKeepingGeneration() {
	if wsConn != nil {
		wsConn.Close()
		wsConn = nil
	}
	_ = daemon.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = daemon.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = daemon.Process.Kill()
		<-done
	}
	daemon = nil
}

func m5Workflows() {
	fmt.Println("-- workflows in enforce: allowed folder vs denied folder --")
	setStructuralMode("audit")
	base := filepath.Join(*scope, "wf")
	allowDir, denyDir := filepath.Join(base, "allow"), filepath.Join(base, "deny")
	must(os.MkdirAll(allowDir, 0o755))
	must(os.MkdirAll(denyDir, 0o755))
	tools := map[string]string{}
	for _, name := range []string{"vim", "mv", "cp", "rm", "git", "tar"} {
		tools[name] = realPath(lookPath(name))
		putProfile(name, pathFingerprint(tools[name]), rules("permit", map[string][]string{
			"writeRules": {"+ " + allowDir + "/**", "- " + denyDir + "/**"},
		}))
	}
	run := func(dir string, argv ...string) (bool, string) {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		return err == nil, strings.TrimSpace(string(out))
	}
	setup := func(dir string, argv ...string) {
		if ok, out := run(dir, argv...); !ok {
			must(fmt.Errorf("%s: %s", strings.Join(argv, " "), out))
		}
	}
	// Each tool runs once in audit, so its executable label is learned, and
	// the git repositories are set up there, where nothing is denied.
	for _, name := range []string{"vim", "mv", "cp", "rm", "git", "tar"} {
		setup(base, name, "--version")
	}
	for _, dir := range []string{allowDir, denyDir} {
		repo := filepath.Join(dir, "repo")
		must(os.MkdirAll(repo, 0o755))
		setup(repo, "git", "init", "-q", "-b", "main")
		write(filepath.Join(repo, "a"), "a\n", 0o644)
		setup(repo, "git", "add", "a")
		setup(repo, "git", "-c", "user.name=m5", "-c", "user.email=m5@test", "commit", "-qm", "a")
		setup(repo, "git", "checkout", "-q", "-b", "other")
		setup(repo, "git", "rm", "-q", "a")
		write(filepath.Join(repo, "b"), "b\n", 0o644)
		must(os.MkdirAll(filepath.Join(repo, "sub"), 0o755))
		write(filepath.Join(repo, "sub", "c"), "c\n", 0o644)
		setup(repo, "git", "add", "b", "sub/c")
		setup(repo, "git", "-c", "user.name=m5", "-c", "user.email=m5@test", "commit", "-qm", "b")
		setup(repo, "git", "checkout", "-q", "main")
	}
	setStructuralMode("enforce")
	exists := func(path string) bool { _, err := os.Stat(path); return err == nil }
	read := func(path string) string { data, _ := os.ReadFile(path); return string(data) }

	for _, variant := range []struct {
		name    string
		dir     string
		allowed bool
	}{{"allowed", allowDir, true}, {"denied", denyDir, false}} {
		dir := variant.dir
		// vim's atomic save renames the original to a backup, writes a new
		// file and deletes the backup (backupcopy=no forces the rename).
		note := filepath.Join(dir, "note.txt")
		write(note, "old\n", 0o644)
		ok, out := run(dir, "vim", "-Es", "-u", "NONE", "-c", "set nocompatible backupcopy=no writebackup", "-c", "%d", "-c", "call setline(1, 'new')", "-c", "wq", note)
		saved := read(note) == "new\n"
		if variant.allowed {
			report(ok && saved && !exists(note+"~"), fmt.Sprintf("vim atomic save (%s): saved=%v, exit ok=%v", variant.name, saved, ok))
		} else {
			// The backup rename is denied; whatever vim does then, the file
			// is never lost.
			content := read(note)
			report(content == "old\n" || content == "new\n", fmt.Sprintf("vim atomic save (%s): content %q, exit ok=%v %.160q", variant.name, content, ok, out))
		}
		// vim's default save (backupcopy=auto) falls back to writing in place
		// when it may not rename; that open is not a structural operation.
		write(note, "old\n", 0o644)
		ok, _ = run(dir, "vim", "-Es", "-u", "NONE", "-c", "set nocompatible", "-c", "%d", "-c", "call setline(1, 'new')", "-c", "wq", note)
		report(read(note) == "new\n" && (ok || !variant.allowed), fmt.Sprintf("vim default save (%s): saved=%v, exit ok=%v", variant.name, read(note) == "new\n", ok))

		// File-manager style: move, copy a tree, delete a tree.
		write(filepath.Join(dir, "moveme"), "m\n", 0o644)
		ok, _ = run(dir, "mv", "moveme", "moved")
		report(ok == variant.allowed && exists(filepath.Join(dir, "moved")) == variant.allowed && exists(filepath.Join(dir, "moveme")) != variant.allowed,
			fmt.Sprintf("mv rename (%s): ok=%v", variant.name, ok))
		must(os.MkdirAll(filepath.Join(*outside, "tree", "sub"), 0o755))
		write(filepath.Join(*outside, "tree", "sub", "f"), "f\n", 0o644)
		ok, _ = run(dir, "cp", "-r", filepath.Join(*outside, "tree"), "tree")
		report(ok == variant.allowed && exists(filepath.Join(dir, "tree", "sub", "f")) == variant.allowed, fmt.Sprintf("cp -r into the folder (%s): ok=%v", variant.name, ok))
		ok, _ = run(dir, "mv", filepath.Join(dir, "tree"), filepath.Join(*outside, "moved-out"))
		if variant.allowed {
			report(ok && !exists(filepath.Join(dir, "tree")), fmt.Sprintf("mv a tree out (%s): ok=%v", variant.name, ok))
			must(os.MkdirAll(filepath.Join(dir, "tree", "sub"), 0o755))
			write(filepath.Join(dir, "tree", "sub", "f"), "f\n", 0o644)
		}
		// This test's own process has no rules and a permitting default.
		victimTree := filepath.Join(dir, "rmtree")
		must(os.MkdirAll(filepath.Join(victimTree, "sub"), 0o755))
		write(filepath.Join(victimTree, "sub", "f"), "f\n", 0o644)
		ok, _ = run(dir, "rm", "-r", victimTree)
		report(ok == variant.allowed && exists(filepath.Join(victimTree, "sub", "f")) != variant.allowed, fmt.Sprintf("rm -r a tree (%s): ok=%v", variant.name, ok))

		// git checkout of a branch that deletes a, adds b and sub/c.
		repo := filepath.Join(dir, "repo")
		ok, out = run(repo, "git", "checkout", "-q", "other")
		switched := exists(filepath.Join(repo, "b")) && exists(filepath.Join(repo, "sub", "c")) && !exists(filepath.Join(repo, "a"))
		if variant.allowed {
			report(ok && switched, fmt.Sprintf("git checkout (%s): ok=%v switched=%v", variant.name, ok, switched))
		} else {
			report(!ok && exists(filepath.Join(repo, "a")), fmt.Sprintf("git checkout (%s): ok=%v, a kept=%v %.160q", variant.name, ok, exists(filepath.Join(repo, "a")), out))
		}

		// tar -x of a tree, then again over the existing files.
		archive := filepath.Join(*outside, "m5.tar")
		if !exists(archive) {
			setup(*outside, "tar", "-cf", archive, "-C", *outside, "tree")
		}
		extract := filepath.Join(dir, "x")
		must(os.MkdirAll(extract, 0o755))
		ok, out = run(extract, "tar", "-xf", archive)
		report(ok == variant.allowed && exists(filepath.Join(extract, "tree", "sub", "f")) == variant.allowed, fmt.Sprintf("tar -x (%s): ok=%v %.100q", variant.name, ok, out))
	}

	fmt.Println("  package upgrade of a learned executable (tar, pacman -U):")
	oldPkg, newPkg := cachedPackage("tar-1.35-3-"), cachedPackage("tar-1.35-5-")
	if oldPkg == "" || newPkg == "" {
		fmt.Println("  info package upgrade skipped: tar packages are not in the pacman cache")
		return
	}
	archive := filepath.Join(*outside, "m5.tar")
	// Without the label wait, the first exec of the new inode is pending and
	// denies (fail closed) until the daemon learns it from that exec.
	learnedRun := func(name string, pendingDenies bool) {
		extract, err := os.MkdirTemp(allowDir, "upgrade")
		must(err)
		before, pending := waitCounters(), pendingDenials()
		ok, out := run(extract, "tar", "-xf", archive)
		after := waitCounters()
		denied := pendingDenials() - pending
		line := fmt.Sprintf("%s: tar -x allowed=%v, label waits +%d, label-pending denials +%d %.80q", name, ok, after[counterWait]-before[counterWait], denied, out)
		report(ok || pendingDenies && denied > 0, line)
	}
	learnedRun("before the upgrade", false)
	inode := func() uint64 {
		var st syscall.Stat_t
		must(syscall.Stat(tools["tar"], &st))
		return st.Ino
	}
	oldInode := inode()
	for _, pkg := range []string{oldPkg, newPkg} {
		if out, err := exec.Command("pacman", "-U", "--noconfirm", pkg).CombinedOutput(); err != nil {
			must(fmt.Errorf("pacman -U %s: %v: %s", pkg, err, out))
		}
	}
	report(inode() != oldInode, fmt.Sprintf("pacman replaced %s (inode %d -> %d)", tools["tar"], oldInode, inode()))
	learnedRun("first run after the upgrade", !waitEnabled)
	// Without the wait, the new inode stays pending until the daemon has
	// learned it from an exec record; it must then be allowed.
	for i := 0; !waitEnabled && i < 5; i++ {
		time.Sleep(300 * time.Millisecond)
		if ok, _ := run(allowDir, "tar", "--version"); ok {
			break
		}
	}
	time.Sleep(300 * time.Millisecond)
	learnedRun("run after the daemon learned the new inode", false)
	extract, err := os.MkdirTemp(denyDir, "upgrade")
	must(err)
	ok, _ := run(extract, "tar", "-xf", archive)
	report(!ok && !exists(filepath.Join(extract, "tree")), fmt.Sprintf("after the upgrade, tar -x into the denied folder: ok=%v", ok))
}

func cachedPackage(prefix string) string {
	matches, _ := filepath.Glob("/var/cache/pacman/pkg/" + prefix + "*.pkg.tar.zst")
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

// m5Pressure: a denied app's burst overflows the record budget; every delete
// stays denied and the drops are counted.
func m5Pressure() {
	fmt.Println("-- pressure: a denied 10,000-delete burst --")
	dir := filepath.Join(*scope, "deny-burst")
	must(os.MkdirAll(dir, 0o755))
	const count = 10000
	for i := 0; i < count; i++ {
		write(filepath.Join(dir, fmt.Sprintf("deny-%05d", i)), "", 0o644)
	}
	helper := m5Helper("m5-burst-deny-helper")
	putProfile("m5 burst deny helper", pathFingerprint(helper), rules("", map[string][]string{"writeRules": {"- " + dir + "/**"}}))
	before, err := getDiagnostics()
	must(err)
	report(m4Run(helper, "deny-burst", dir, fmt.Sprint(count)), "10,000 denied deletes: none succeeded")
	entries, err := os.ReadDir(dir)
	must(err)
	time.Sleep(time.Second)
	after, err := getDiagnostics()
	must(err)
	drops := after.Structural.DecisionDrops - before.Structural.DecisionDrops
	report(len(entries) == count && drops > 0 && after.Structural.State == "active",
		fmt.Sprintf("files kept %d/%d; %d records dropped and counted; daemon %s", len(entries), count, drops, after.Structural.State))
}
