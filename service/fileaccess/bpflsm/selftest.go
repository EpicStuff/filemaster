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

// selfTest proves each attached hook reads its arguments correctly: under a
// table with no rules every hook must deny, and under an allow table the same
// operations must succeed. A wrong argument index fails open silently in the
// kernel, so it would otherwise go unnoticed. It runs in a private tmpfs on
// bank 1 with no daemon bypass, and leaves bank 0 live and bank 1 empty.
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
	id, err := pathFileID(vault)
	if err != nil {
		return err
	}

	settings := collection.Maps["SETTINGS"]
	protected := collection.Maps["PROTECTED"]
	rules := collection.Maps["RULES"]
	ruleCount := collection.Maps["RULE_COUNT"]
	defer func() {
		err = errors.Join(err,
			settings.Put(uint32(0), encodeSettings(0, 0, fileID{})),
			protected.Delete(encodeBankedFile(1, id)),
			rules.Put(ruleSlot(1, 0, 0), make([]byte, compiledRuleSize)),
			ignoreMissing(ruleCount.Delete(encodeBankedObj(1, 0))),
		)
	}()

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

	// Deny table: the vault is a protected object with no rules.
	if err := protected.Put(encodeBankedFile(1, id), uint32(0)); err != nil {
		return err
	}
	if err := settings.Put(uint32(0), encodeSettings(0, 1, fileID{})); err != nil {
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

	// Allow table: one rule allowing write and create for every caller.
	if err := rules.Put(ruleSlot(1, 0, 0), encodeAnySubjectRule(actionWrite|actionCreate, policyAllow)); err != nil {
		return err
	}
	if err := ruleCount.Put(encodeBankedObj(1, 0), uint32(1)); err != nil {
		return err
	}
	return run("allow", nil, []testCase{
		{"inode_unlink", "unlink", func() error { return os.Remove(path(vault, "f")) }},
		{"inode_rmdir", "rmdir", func() error { return os.Remove(path(vault, "sub")) }},
		{"inode_mkdir", "mkdir", func() error { return os.Mkdir(path(vault, "new"), 0o700) }},
		{"inode_link", "link in", func() error { return os.Link(path(open, "y"), path(vault, "y-link")) }},
		{"inode_rename", "rename in", func() error { return os.Rename(path(open, "x"), path(vault, "x-moved")) }},
	})
}

func ignoreMissing(err error) error {
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}
