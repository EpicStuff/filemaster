package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// m6Matrix checks special file (FIFO, socket) and symlink creation through
// the real daemon: a block default denies, a Write rule allows, each decision
// is recorded with its link target, a denial raises a notice whose Allow lets
// the retry through, and audit records a would-deny without a notice.
func m6Matrix() {
	fmt.Println("== M6: special file and symlink creation ==")
	base := filepath.Join(*scope, "m6")
	must(os.MkdirAll(base, 0o755))
	self, err := os.Executable()
	must(err)
	allowExe := filepath.Join(*outside, "m6-allow-helper")
	denyExe := filepath.Join(*outside, "m6-deny-helper")
	for _, target := range []string{allowExe, denyExe} {
		in, err := os.Open(self)
		must(err)
		out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		must(err)
		_, err = io.Copy(out, in)
		must(err)
		must(in.Close())
		must(out.Close())
	}
	must(startDaemon("off"))
	allowName, denyName := "M6 allowed app", "M6 denied app"
	putProfile(allowName, []map[string]string{{"Type": "path", "Operation": "equals", "Value": allowExe}}, map[string]any{
		"filter":     map[string]any{"defaultAction": "block"},
		"fileaccess": map[string]any{"writeRules": []string{"+ " + base + "/allowed-*"}},
	})
	putProfile(denyName, []map[string]string{{"Type": "path", "Operation": "equals", "Value": denyExe}}, map[string]any{
		"filter": map[string]any{"defaultAction": "block"},
	})
	must(setMode("enforce"))
	report(m4Run(allowExe, "noop"), "allow helper learned")
	report(m4Run(denyExe, "noop"), "deny helper learned")

	type m6Case struct {
		name, op, target string
		args             func(path string) []string
	}
	cases := []m6Case{
		{"fifo", "special", "", func(path string) []string { return []string{"fifo", path} }},
		{"socket", "special", "", func(path string) []string { return []string{"socket", path} }},
		{"symlink-relative", "symlink", "../dangling/target", func(path string) []string { return []string{"symlink", "../dangling/target", path} }},
		{"symlink-absolute", "symlink", "/etc/hostname", func(path string) []string { return []string{"symlink", "/etc/hostname", path} }},
	}
	for _, tc := range cases {
		for _, variant := range []struct {
			name, exe, app, verdict string
			allowed                 bool
		}{
			{"allowed", allowExe, allowName, "allow", true},
			{"denied", denyExe, denyName, "deny", false},
		} {
			path := filepath.Join(base, variant.name+"-"+tc.name)
			args := tc.args(path)
			got := m4Run(variant.exe, args...)
			report(got == variant.allowed, fmt.Sprintf("%s %s syscall: allowed=%v", variant.name, tc.name, got))
			_, statErr := os.Lstat(path)
			report((statErr == nil) == variant.allowed, fmt.Sprintf("%s %s exists=%v", variant.name, tc.name, statErr == nil))
			record, err := m4WaitRecord(tc.op, variant.verdict, path, "", variant.app)
			if err == nil && record.LinkTarget != tc.target {
				err = fmt.Errorf("link target %q, want %q", record.LinkTarget, tc.target)
			}
			report(err == nil, fmt.Sprintf("Monitor %s %s: op %s, path, link target %q and app: %v", variant.name, tc.name, tc.op, tc.target, err))
			if *debug && err == nil {
				fmt.Printf("    record %+v\n", record)
			}
			if variant.allowed || tc.name == "symlink-absolute" {
				continue
			}
			if tc.target != "" {
				noticed := false
				for i := 0; i < 40 && !noticed; i++ {
					notices, err := m4Notices()
					must(err)
					for _, notice := range notices {
						noticed = noticed || notice.Type == 0 && strings.Contains(notice.Message, path) && strings.Contains(notice.Message, tc.target)
					}
					if !noticed {
						time.Sleep(250 * time.Millisecond)
					}
				}
				report(noticed, "symlink deny notice names the link and its target")
			}
			m4AllowRetry(denyExe, denyName, record.Profile, path, args, tc.op, tc.target)
		}
	}

	must(setMode("audit"))
	for _, tc := range cases[:3] {
		path := filepath.Join(base, "audit-"+tc.name)
		report(m4Run(denyExe, tc.args(path)...), fmt.Sprintf("audit %s allowed", tc.name))
		record, err := m4WaitRecord(tc.op, "would-deny", path, "", denyName)
		if err == nil && record.LinkTarget != tc.target {
			err = fmt.Errorf("link target %q, want %q", record.LinkTarget, tc.target)
		}
		report(err == nil, fmt.Sprintf("Monitor audit %s would-deny: %v", tc.name, err))
	}
	time.Sleep(time.Second)
	notices, err := m4Notices()
	report(err == nil, fmt.Sprintf("query notices after audit: %v", err))
	for _, notice := range notices {
		if strings.Contains(notice.Message, filepath.Join(base, "audit-")) {
			report(false, "audit produced a deny notice: "+notice.Message)
		}
	}
	must(setMode("enforce"))
}
