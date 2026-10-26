package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// subvolMatrix watches a whole btrfs filesystem whose subvolumes a and b and
// snapshot a-snap repeat inode numbers (every subvolume root is 256, a/d,
// b/x and a-snap/d are all 257), with b also mounted on its own. Two apps
// each have one Write rule on a/d; every other target only takes the app's
// default, so a kernel that keys objects by (s_dev, ino) alone applies a/d's
// rule to b/x and a-snap/d.
func subvolMatrix() {
	fmt.Println("== M5: btrfs subvolumes and snapshots repeat inode numbers ==")
	top, second := "/mnt/fm-subvol", "/mnt/fm-subvol-b"
	image := "/var/tmp/fm-subvol.img"
	for _, mountpoint := range []string{second, top} {
		_ = unix.Unmount(mountpoint, unix.MNT_DETACH)
	}
	_ = os.Remove(image)
	file, err := os.Create(image)
	must(err)
	must(file.Truncate(256 << 20))
	must(file.Close())
	defer func() {
		for _, mountpoint := range []string{second, top} {
			_ = unix.Unmount(mountpoint, unix.MNT_DETACH)
		}
		_ = os.Remove(image)
	}()
	a, b, snap := filepath.Join(top, "a"), filepath.Join(top, "b"), filepath.Join(top, "a-snap")
	run := func(argv ...string) string {
		out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
		if err != nil {
			must(fmt.Errorf("%s: %v: %s", strings.Join(argv, " "), err, out))
		}
		return strings.TrimSpace(string(out))
	}
	run("mkfs.btrfs", "-q", "-f", image)
	run("mkdir", "-p", top, second)
	run("mount", "-o", "loop", image, top)
	run("btrfs", "subvolume", "create", a)
	run("btrfs", "subvolume", "create", b)
	run("mkdir", filepath.Join(a, "d"), filepath.Join(b, "x"))
	run("btrfs", "subvolume", "snapshot", a, snap)
	run("mount", "-o", "subvol=b", run("findmnt", "-nro", "SOURCE", "--target", top), second)
	inode := func(path string) uint64 {
		var st unix.Stat_t
		must(unix.Stat(path, &st))
		return st.Ino
	}
	report(inode(a) == inode(b) && inode(a) == inode(snap) && inode(a) == inode(top) &&
		inode(filepath.Join(a, "d")) == inode(filepath.Join(b, "x")) && inode(filepath.Join(a, "d")) == inode(filepath.Join(snap, "d")),
		fmt.Sprintf("setup: subvolume roots are inode %d, a/d, b/x and a-snap/d are inode %d", inode(a), inode(filepath.Join(a, "d"))))

	self, err := os.Executable()
	must(err)
	allowExe := filepath.Join(*outside, "subvol-allow-helper")
	denyExe := filepath.Join(*outside, "subvol-deny-helper")
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

	*scope = top
	must(startDaemon("off"))
	allowName, denyName := "subvolume allow-rule app", "subvolume deny-rule app"
	putProfile(allowName, []map[string]string{{"Type": "path", "Operation": "equals", "Value": allowExe}}, map[string]any{
		"filter":     map[string]any{"defaultAction": "block"},
		"fileaccess": map[string]any{"writeRules": []string{"+ " + filepath.Join(a, "d") + "/**"}},
	})
	putProfile(denyName, []map[string]string{{"Type": "path", "Operation": "equals", "Value": denyExe}}, map[string]any{
		"filter":     map[string]any{"defaultAction": "permit"},
		"fileaccess": map[string]any{"writeRules": []string{"- " + filepath.Join(a, "d") + "/**"}},
	})
	must(setMode("enforce"))
	report(m4Run(allowExe, "noop"), "allow-rule helper learned")
	report(m4Run(denyExe, "noop"), "deny-rule helper learned")
	if d, err := getDiagnostics(); err == nil {
		for _, warning := range d.Warnings {
			if strings.Contains(warning.ID, "subvolume") {
				report(false, "unexpected warning "+warning.ID)
			}
		}
	}

	check := func(exe, app string, allowed, record bool, op string, args ...string) {
		if op == "delete" || op == "rename" {
			must(os.WriteFile(args[0], nil, 0o644))
		}
		got := m4Run(exe, append([]string{op}, args...)...)
		verdict := "deny"
		if allowed {
			verdict = "allow"
		}
		report(got == allowed, fmt.Sprintf("%s %s %s: %s", app, op, strings.Join(args, " -> "), verdict))
		if record {
			// A record names the target under its object's first context; b's
			// objects are also reachable through the second mount.
			alias := func(path string) string {
				if strings.HasPrefix(path, b+"/") {
					return second + strings.TrimPrefix(path, b)
				}
				return path
			}
			dest := ""
			if op == "rename" {
				dest = alias(args[1])
			}
			_, err := m4WaitRecord(op, verdict, alias(args[0]), dest, app)
			report(err == nil, fmt.Sprintf("  record %s %s with the exact path(s) (%v)", verdict, alias(args[0]), err))
		}
		if op == "create" && got {
			_ = os.Remove(args[0])
		}
	}
	check(allowExe, allowName, true, true, "delete", filepath.Join(a, "d", "victim"))
	check(allowExe, allowName, false, true, "delete", filepath.Join(b, "x", "victim"))
	check(allowExe, allowName, false, true, "delete", filepath.Join(snap, "d", "victim"))
	check(allowExe, allowName, false, false, "delete", filepath.Join(second, "x", "victim"))
	check(allowExe, allowName, false, true, "create", filepath.Join(snap, "d", "new"))
	check(allowExe, allowName, false, true, "rename", filepath.Join(b, "x", "r1"), filepath.Join(b, "x", "r2"))
	check(denyExe, denyName, false, true, "delete", filepath.Join(a, "d", "victim"))
	check(denyExe, denyName, true, true, "delete", filepath.Join(b, "x", "victim"))
	check(denyExe, denyName, true, true, "delete", filepath.Join(snap, "d", "victim"))
	check(denyExe, denyName, true, false, "delete", filepath.Join(second, "x", "victim"))
	check(denyExe, denyName, true, true, "create", filepath.Join(snap, "d", "new"))
	check(denyExe, denyName, true, true, "rename", filepath.Join(b, "x", "r1"), filepath.Join(b, "x", "r2"))
}
