//go:build linux && !filemaster_test

package bpflsm

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLabelExecUnderContention runs a labelled shell that repeatedly execs a
// never-seen binary which deletes in the scope, on one CPU crowded by other
// processes exec'ing with large argv/envp. Each exec must leave the child
// pending, so every delete is denied: a child that kept its parent's allow
// label would delete. Root-only; enabled with FM_BPF_CONTENTION=1.
func TestLabelExecUnderContention(t *testing.T) {
	if os.Getenv("FM_BPF_CONTENTION") != "1" {
		t.Skip("set FM_BPF_CONTENTION=1 to run the exec-labelling contention test")
	}
	requireBPFLSM(t)
	runs := 3000
	if value := os.Getenv("FM_BPF_CONTENTION_EXECS"); value != "" {
		var err error
		if runs, err = strconv.Atoi(value); err != nil {
			t.Fatal(err)
		}
	}
	bins := t.TempDir()
	copyBinary := func(name, as string) string {
		source, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("%s is not installed", name)
		}
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(bins, as)
		if err := os.WriteFile(path, data, 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	parentShell := copyBinary("bash", "pbash")
	stressShell := copyBinary("bash", "sbash")
	child := copyBinary("rm", "xrm")
	stressExe := copyBinary("true", "xtrue")
	for _, tool := range []string{"taskset", "chrt"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
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
	pid := uint32(os.Getpid())
	enf = NewEnforcerWithOptions(Options{
		PinRoot:     "/sys/fs/bpf/filemaster-execrace-" + strconv.Itoa(os.Getpid()),
		SelfTestDir: filepath.Join(t.TempDir(), "selftest"),
		DaemonPID:   &pid,
		Labelling:   true,
		OnRecord: func(record Record) {
			if record.Kind == RecordExec && filepath.Base(record.Path) == "pbash" {
				_ = enf.Resolve(record.TGID, record.Start, record.Seq, 1)
			}
		},
	})
	t.Cleanup(func() { _ = enf.SetMode(ModeOff) })
	if err := enf.SetModeWithTable(ModeEnforce, table); err != nil {
		t.Fatalf("enforce: %v", err)
	}
	enf.SetLabelWait(false)

	stressArgs := strings.Repeat("a", 200)
	stressEnv := "FM_STRESS=" + strings.Repeat("e", 15000)
	var stressors []*exec.Cmd
	stop := func() {
		for _, cmd := range stressors {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		stressors = nil
	}
	defer stop()
	for i := range 8 {
		loop := `while :; do "$X"` + strings.Repeat(" "+stressArgs, 30) + `; done`
		args := []string{"-c", "0", stressShell, "-c", loop}
		if i%4 == 3 {
			loop = `while :; do sleep 0.00$((RANDOM % 9 + 1)); "$X"` + strings.Repeat(" "+stressArgs, 30) + `; done`
			args = []string{"-c", "0", "chrt", "-f", strconv.Itoa(1 + i/4), stressShell, "-c", loop}
		}
		cmd := exec.Command("taskset", args...)
		cmd.Env = append(os.Environ(), "X="+stressExe, stressEnv)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		stressors = append(stressors, cmd)
	}

	victim := filepath.Join(scope, "victim")
	script := `sleep 0.5; for i in $(seq 1 ` + strconv.Itoa(runs) + `); do : > "$V"; "$C" -f "$V" 2>/dev/null; [ -e "$V" ] || echo deleted; done; echo done`
	cmd := exec.Command("taskset", "-c", "0", parentShell, "-c", script)
	cmd.Env = append(os.Environ(), "V="+victim, "C="+child, stressEnv)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	start := time.Now()
	if err := cmd.Run(); err != nil {
		t.Fatalf("parent shell: %v", err)
	}
	took := time.Since(start)
	stop()

	var misses uint64
	if program := enf.collection.Programs["sched_process_exec"]; program != nil {
		if stats, err := program.Stats(); err == nil {
			misses = stats.RecursionMisses
		}
	}
	deleted := strings.Count(output.String(), "deleted")
	t.Logf("exec contention: %d child execs in %v, %d deleted, sched_process_exec recursion misses %d",
		runs, took.Round(time.Millisecond), deleted, misses)
	if !strings.Contains(output.String(), "done") {
		t.Fatalf("parent shell did not finish: %q", output.String())
	}
	if deleted > 0 {
		t.Errorf("%d of %d deletes by a never-seen child of an allow-labelled shell were allowed", deleted, runs)
	}
}
