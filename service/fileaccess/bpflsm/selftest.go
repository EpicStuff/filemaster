//go:build linux

package bpflsm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// selfTest proves each attached hook reads its arguments correctly. It runs a
// complete deny table, a deny table in audit mode, and a complete allow table
// on bank 1. Bank 0 remains empty and live when the test exits.
func selfTest(collection *ebpf.Collection, attached map[string]bool, dir string) (err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=1m,mode=0700"); err != nil {
		return fmt.Errorf("mount self-test tmpfs: %w", err)
	}
	defer func() {
		err = errors.Join(err, unix.Unmount(dir, unix.MNT_DETACH), os.Remove(dir))
	}()

	vault := filepath.Join(dir, "vault")
	open := filepath.Join(dir, "open")
	for _, folder := range []string{vault, open} {
		if err := os.MkdirAll(filepath.Join(folder, "sub"), 0o700); err != nil {
			return err
		}
		for _, name := range []string{"f", "g", "x", "y"} {
			if err := os.WriteFile(filepath.Join(folder, name), nil, 0o600); err != nil {
				return err
			}
		}
	}
	settings := collection.Maps["SETTINGS"]
	audit := collection.Maps["AUDIT"]
	defer func() {
		err = errors.Join(err,
			settings.Put(uint32(0), encodeSettings(publishedSettings{})),
			writeBank(collection.Maps, 1, Table{}),
			resetAudit(audit),
		)
	}()
	seed := func(allow bool) error {
		label := LabelPolicy{Label: LabelUnidentified, DefaultAllow: true}
		for _, list := range []RuleList{ListRead, ListWrite, ListExecute} {
			label.Rules = append(label.Rules, RuleInput{List: list, Pattern: vault + "/**", Allow: allow})
		}
		table, _, err := Compile(Policy{Scopes: []ScopeInput{{Path: vault}}, Labels: []LabelPolicy{label}})
		if err != nil {
			return err
		}
		return writeBank(collection.Maps, 1, table)
	}

	path := func(folder, name string) string { return filepath.Join(folder, name) }
	type testCase struct {
		hook string
		name string
		op   func() error
	}
	run := func(phase string, want error, cases []testCase) error {
		var failures []error
		for _, c := range cases {
			if !attached[c.hook] {
				continue
			}
			got := c.op()
			if (want == nil && got != nil) || (want != nil && !errors.Is(got, want)) {
				failures = append(failures, fmt.Errorf("%s %s (%s): want %v, got %v", phase, c.name, c.hook, want, got))
			}
		}
		return errors.Join(failures...)
	}

	// Deny everything in the vault while the default allows. This makes the in
	// and out link/rename cases reach both dentry arguments instead of short-
	// circuiting at an uncovered source.
	if err := seed(false); err != nil {
		return err
	}
	if err := settings.Put(uint32(0), encodeSettings(publishedSettings{bank: 1})); err != nil {
		return err
	}
	if err := run("deny", unix.EPERM, []testCase{
		{"inode_unlink", "unlink", func() error { return os.Remove(path(vault, "f")) }},
		{"inode_rmdir", "rmdir", func() error { return os.Remove(path(vault, "sub")) }},
		{"inode_mkdir", "mkdir", func() error { return os.Mkdir(path(vault, "new"), 0o700) }},
		{"inode_link", "link out (source argument)", func() error { return os.Link(path(vault, "g"), path(open, "g-link")) }},
		{"inode_link", "link in (destination argument)", func() error { return os.Link(path(open, "y"), path(vault, "y-link")) }},
		{"inode_rename", "rename out (source argument)", func() error { return os.Rename(path(vault, "g"), path(open, "g-moved")) }},
		{"inode_rename", "rename in (destination argument)", func() error { return os.Rename(path(open, "x"), path(vault, "x-moved")) }},
	}); err != nil {
		return err
	}

	if err := settings.Put(uint32(0), encodeSettings(publishedSettings{bank: 1, audit: true})); err != nil {
		return err
	}
	before, err := auditTotal(audit, OperationDelete)
	if err != nil {
		return err
	}
	if attached["inode_unlink"] {
		if err := os.Remove(path(vault, "f")); err != nil {
			return fmt.Errorf("audit unlink: %w", err)
		}
		after, err := auditTotal(audit, OperationDelete)
		if err != nil {
			return err
		}
		if after <= before {
			return fmt.Errorf("audit unlink did not increment delete would-deny counter: before=%d after=%d", before, after)
		}
		if err := os.WriteFile(path(vault, "f"), nil, 0o600); err != nil {
			return err
		}
	}

	// With both tables allow, including NOMATCH, all ordinary and formerly
	// Cordon-denied escapes must succeed.
	if err := seed(true); err != nil {
		return err
	}
	if err := settings.Put(uint32(0), encodeSettings(publishedSettings{bank: 1})); err != nil {
		return err
	}
	return run("allow", nil, []testCase{
		{"inode_unlink", "unlink", func() error { return os.Remove(path(vault, "f")) }},
		{"inode_rmdir", "rmdir", func() error { return os.Remove(path(vault, "sub")) }},
		{"inode_mkdir", "mkdir", func() error { return os.Mkdir(path(vault, "new"), 0o700) }},
		{"inode_link", "link out", func() error { return os.Link(path(vault, "g"), path(open, "g-link")) }},
		{"inode_link", "link in", func() error { return os.Link(path(open, "y"), path(vault, "y-link")) }},
		{"inode_rename", "rename out", func() error { return os.Rename(path(vault, "g"), path(open, "g-moved")) }},
		{"inode_rename", "rename in", func() error { return os.Rename(path(open, "x"), path(vault, "x-moved")) }},
	})
}

func auditTotal(audit *ebpf.Map, operation Operation) (uint64, error) {
	values, err := perCPUValues()
	if err != nil {
		return 0, err
	}
	if err := audit.Lookup(uint32(operation), &values); err != nil {
		return 0, err
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	return total, nil
}

func resetAudit(audit *ebpf.Map) error {
	if audit == nil {
		return nil
	}
	for _, operation := range allOperations {
		values, err := perCPUValues()
		if err != nil {
			return err
		}
		if err := audit.Put(uint32(operation), values); err != nil {
			return err
		}
	}
	return nil
}

// labelSelfTest proves the labelling programs read their kernel fields: an
// exec of an unlabelled shell must leave a pending record with its leader's
// /proc start time and a ring-buffer record with its argv and envp, and its
// exit must remove the record. It runs with an empty bank 0 and no bypass.
func labelSelfTest(collection *ebpf.Collection) (err error) {
	settings := collection.Maps["SETTINGS"]
	if err := settings.Put(uint32(0), encodeSettings(publishedSettings{labelling: true})); err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, settings.Put(uint32(0), encodeSettings(publishedSettings{})))
	}()
	reader, err := ringbuf.NewReader(collection.Maps["RECORDS"])
	if err != nil {
		return fmt.Errorf("open records: %w", err)
	}
	defer reader.Close()

	shell := exec.Command("/bin/sh", "-c", "read line")
	shell.Env = []string{"FILEMASTER_LABEL_SELFTEST=1"}
	stdin, err := shell.StdinPipe()
	if err != nil {
		return err
	}
	if err := shell.Start(); err != nil {
		return fmt.Errorf("start /bin/sh: %w", err)
	}
	pid := uint32(shell.Process.Pid)
	defer func() {
		_ = stdin.Close()
		_ = shell.Wait()
	}()

	reader.SetDeadline(time.Now().Add(5 * time.Second))
	var record Record
	for {
		raw, err := reader.Read()
		if err != nil {
			return fmt.Errorf("no exec record for /bin/sh (pid %d): %w", pid, err)
		}
		if record, err = decodeRecord(raw.RawSample); err == nil && record.TGID == pid && record.Kind == recordExec {
			break
		}
	}
	if !slices.Equal(record.Args, []string{"/bin/sh", "-c", "read line"}) || !slices.Contains(record.Env, "FILEMASTER_LABEL_SELFTEST=1") {
		return fmt.Errorf("exec record argv %q envp %q", record.Args, record.Env)
	}
	start, _, err := procStart(int(pid))
	if err != nil {
		return err
	}
	if record.Start < start || record.Start-start >= clockTick {
		return fmt.Errorf("exec record start %d is not within a tick of /proc's %d", record.Start, start)
	}
	exe, err := pathFileID("/proc/" + strconv.Itoa(int(pid)) + "/exe")
	if err != nil {
		return err
	}
	if record.Exe.Dev != exe.dev || record.Exe.Ino != exe.ino {
		return fmt.Errorf("exec record exe %+v, /proc says %+v", record.Exe, exe)
	}
	value := make([]byte, procValueSize)
	if err := collection.Maps["PROCS"].Lookup(pid, value); err != nil {
		return fmt.Errorf("no label record for /bin/sh: %w", err)
	}
	if proc := decodeProcValue(value); proc.Label != labelPending || proc.Start != record.Start || proc.Seq != record.Seq {
		return fmt.Errorf("label record %+v does not match exec record %+v", proc, record)
	}

	_ = stdin.Close()
	_ = shell.Wait()
	if err := collection.Maps["PROCS"].Lookup(pid, value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("label record for exited /bin/sh still present: %v", err)
	}
	return nil
}
