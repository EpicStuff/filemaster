//go:build linux

package bpflsm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
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
			settings.Put(uint32(0), encodeSettings(0, 0, fileID{}, false)),
			writeBank(collection.Maps, 1, Table{}),
			resetAudit(audit),
		)
	}()
	seed := func(allow bool) error {
		policy := Policy{Scopes: []ScopeInput{{Path: vault}}, DefaultAllow: true}
		for _, list := range []RuleList{ListRead, ListWrite, ListExecute} {
			policy.Rules = append(policy.Rules, RuleInput{List: list, Pattern: vault + "/**", Allow: allow})
		}
		table, _, err := Compile(policy)
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
	if err := settings.Put(uint32(0), encodeSettings(0, 1, fileID{}, false)); err != nil {
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

	if err := settings.Put(uint32(0), encodeSettings(0, 1, fileID{}, true)); err != nil {
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
	if err := settings.Put(uint32(0), encodeSettings(0, 1, fileID{}, false)); err != nil {
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
