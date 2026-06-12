// Live phase-3 demonstration. Wires the full fanotify -> PromptHandler
// -> verdict path with a scripted prompter that denies anything whose
// path contains "blocked", so a real cat(1) of such a file fails with
// EACCES instead of just being logged.
//
// Run (as root, in host userns):
//
//	go run ./cmds/fileaccess-demo &
//	cat /tmp/filemaster-test/normal-file   # succeeds
//	cat /tmp/filemaster-test/blocked-file  # fails: Permission denied
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/safing/portmaster/service/fileaccess"
)

type scriptedPrompter struct{}

// Prompt: if the path mentions "blocked", deny; otherwise allow.
// Returns Always-variants so a second access of the same file skips
// straight to the persisted rule.
func (scriptedPrompter) Prompt(_ context.Context, e fileaccess.FileEvent, _ time.Duration) (string, bool) {
	if strings.Contains(e.Path, "blocked") {
		fmt.Printf("[prompter] DENY %s (pid %d, exe %s)\n", e.Path, e.PID, e.Exe)
		return fileaccess.ActionDenyAlways, true
	}
	fmt.Printf("[prompter] ALLOW %s (pid %d, exe %s)\n", e.Path, e.PID, e.Exe)
	return fileaccess.ActionAllowAlways, true
}

type stubInstance struct{}

func main() {
	fa, err := fileaccess.New(stubInstance{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "new:", err)
		os.Exit(1)
	}
	fa.SetHandler(fileaccess.NewPromptHandler(scriptedPrompter{}, nil, 5*time.Second))

	if err := fa.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		os.Exit(1)
	}
	fmt.Println("phase-3 demo up; sleeping 15s")
	fmt.Println("    try: cat /tmp/filemaster-test/normal")
	fmt.Println("    try: cat /tmp/filemaster-test/blocked-thing")
	time.Sleep(15 * time.Second)
	if err := fa.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, "stop:", err)
	}
	fmt.Println("done")
}
