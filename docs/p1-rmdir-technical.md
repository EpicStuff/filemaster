# P1 `rmdir` unwind-and-retry proof

## Scope and evidence convention

Every substantive statement below is explicitly labelled **verified by running
it** or **believed from reading source**.  “Verified” is limited to the
disposable VM experiment and does not claim the unrun P1 gates.

**Verified by running it.** This document covers only `rmdir`.  It does not
claim a proof for `unlink`, `rename`, `link`, daemon integration, or P1 gates
4–9.  The native LSM uses a securityfs Allow/Deny stub only.

**Verified by running it.** The reproducibility bundle is
`/root/vm/share/lsm-p1/` on the host and `/mnt/share/lsm-p1/` in the guest.
Its entry point is [REPRODUCE.md](/root/vm/share/lsm-p1/REPRODUCE.md).

## Verdict

**Verified by running it.** The native-C mechanism works for the exercised
`rmdir` cases on Linux `v7.1`: the first `security_path_rmdir()` pass returns
the private sentinel, VFS unwinds, the securityfs stub parks the task, and an
Allow response causes a re-resolved second pass that removes the directory.
The final native run booted `7.1.0-filemaster-p1-dirty` with
`capability,bpf,filemaster` in `/sys/kernel/security/lsm`.

**Verified by running it.** An Allow removed the target and recorded
`asks=1 answers=1 pass_two=1 allows=1`; a Deny left the target in place and
the traced syscall returned `EACCES`, with
`asks=1 answers=1 pass_two=1 denies=1`.  The artifacts are
`results/test-allow-deny/` and `results/run-tests-final-native.log`.

**Verified by running it.** A controlled replacement test parked `rmdir`,
renamed the original directory away, created a replacement at the same name,
then answered Allow.  The cached identity mismatch failed closed with
`EACCES` and recorded exactly one ask and one answer, with no second-pass
allow (`asks=1 answers=1 pass_two=0`).  This establishes one decision for
that exercised syscall/race, not a universal proof of P1 gate 6.

**Verified by running it.** An Allow of a nonempty directory re-ran normal VFS
work and returned `ENOTEMPTY`, rather than treating the first-pass decision as
the operation result.

**Verified by running it.** The optional BPF candidate also functioned in the
controlled Allow path: non-sleepable BPF `path_rmdir` returned the same
sentinel once, sleepable BPF `ask` called a `KF_SLEEPABLE` kfunc to park on the
securityfs prompt, and the second pass removed the directory.  This is not a
recommendation to ship the BPF candidate; its lifecycle caveat is recorded
below.

## P1 gate 1–3 evidence status

**Verified by running it.** Gate 1’s `rmdir` delivery evidence is positive:
the exact custom kernel booted, Filemaster was last in the active LSM list,
and its securityfs stub accepted the exercised Allow/Deny replies.

**Verified by running it.** Gate 2’s required concurrent-work evidence is
positive for the tested ext4 loop filesystem: both same-superblock
cross-directory rename and `fsfreeze` completed while a native prompt was
parked.

**Believed from reading source.** Gate 3’s implementation audit is positive
within `filename_rmdir()`: every return route introduced by the Ask sentinel
converts it to a normal errno before userspace.  The runtime trace exercises
two outcomes and saw no escape, but it is not an exhaustive proof of every
possible interruption or future call path.

## Exact source basis and the claimed wait point

**Verified by running it.** The source tag was `v7.1`, commit
`8cd9520d35a6c38db6567e97dd93b1f11f185dc6`, and the built release was
`7.1.0-filemaster-p1-dirty`.  The tag and commit are saved in
`results/kernel-tag.txt` and `results/kernel-commit.txt`.

**Believed from reading source.** In the unmodified `v7.1`
`filename_rmdir()`, the relevant order is:

```c
end_dirop(dentry);
mnt_drop_write(path.mnt);
path_put(&path);
if (is_delegated(&delegated_inode))
	error = break_deleg_wait(&delegated_inode);
```

**Believed from reading source.** `end_dirop()` in this tag calls
`inode_unlock(de->d_parent->d_inode)` and `dput(de)`.  Therefore the design
document’s ordering claim is correct for this exact kernel: the existing
conditional `break_deleg_wait()` is after the operation’s parent lock,
mount-write reference, and parent path have been released.  The generic Ask
wait was inserted *after* that existing conditional branch, so delegation
retains its original precedence.

**Believed from reading source.** The claim is narrower than “every possible
kernel lock is absent”: it describes the resources acquired by this
`filename_rmdir()` path.  The recorded baseline, patched function, and
`end_dirop()` definition are `results/filename-rmdir-v7.1-baseline.txt`,
`results/filename-rmdir-v7.1-patched.txt`, and
`results/end-dirop-v7.1.txt`.

## Measured final diffstat

**Verified by running it.** `scripts/verify-patches-apply.sh` constructed an
alternate Git index at the exact tag, applied all four patches with
`git apply --cached --check`, ran `git diff --cached --check`, and emitted the
following final diffstat.  It did not modify the dirty Filemaster repository.

| Area | Real diffstat | Notes |
| --- | ---: | --- |
| `fs/namei.c` | 16 insertions, 1 deletion | `rmdir` unwind, generic wait, retry, and terminal cleanup only. |
| Generic security hook plumbing | 38 insertions, 0 deletions | `errno.h`, LSM hook definition, `security.h`, and `security/security.c`. |
| Filemaster stub LSM | 593 insertions, 1 deletion | LSM registration, task verdict cache, securityfs stub, and the optional BPF kfunc bridge. |
| BPF sleepable-hook plumbing | 1 insertion, 0 deletions | Adds generated `bpf_lsm_ask` to the sleepable-hook set. |
| Total | 648 insertions, 2 deletions | 12 files. |

**Verified by running it.** The complete measured output is
`results/patch-apply-diffstat.txt` and `results/patch-area-diffstat.txt`; the
clean patch files are in `patches/`.

**Believed from reading source.** The VFS portion is small because it reuses
the existing failure/unwind labels instead of duplicating resolution or lock
handling.  The much larger stub number is experiment scaffolding, not a
measure of a production daemon protocol.

## Lock-freedom evidence

**Verified by running it.** The native patch instruments the sentinel path
with `lockdep_assert_not_held(&path.dentry->d_inode->i_rwsem)` immediately
after `end_dirop()`, and logs `security-ask-p1: filename_rmdir wait after VFS
unwind` only after `mnt_drop_write()` and `path_put()`.

**Verified by running it.** While a securityfs prompt was parked, the test
mounted a fresh 128 MiB ext4 loop filesystem at `/mnt/filemaster-p1-lock`,
then completed a cross-directory `mv` from `from/item` to `to/item`.  The
script checked that both directories had the same device number before the
rename.

**Verified by running it.** With the same `rmdir` still parked on that ext4
superblock, `timeout 15s fsfreeze -f /mnt/filemaster-p1-lock` completed, the
test confirmed the request remained pending, thawed the filesystem, answered
Allow, and observed the original `rmdir` complete.  The run logged
`cross-directory rename: completed` and `fsfreeze: completed while rmdir was
parked` in `results/test-lock-freedom/`.

**Believed from reading source.** The lockdep assertion checks the parent
inode semaphore specifically; it is not a formal proof about every lock or
reference in all filesystem implementations.  The ext4 rename/fsfreeze run is
the observed liveness evidence required for this P1 scope.

## Sentinel containment

**Believed from reading source.** The experiment reserves
`ESECURITYASK=520`, immediately after the nearby private errno values
`EOPENSTALE=518` and `ENOPARAM=519`.  The sentinel means “unwind and ask,” not
an errno intended for an application.

**Believed from reading source.** In `filename_rmdir()`, a sentinel after the
first path hook reaches `security_ask_wait()` only after the unwind; a
sentinel returned by the Ask hook itself is converted to `EIO`; and the final
return path converts any remaining sentinel to `EIO`.  The early
`filename_parentat()` return also converts it to `EIO` defensively.  This is a
source audit of this function, not a machine-checked proof of every kernel
control-flow path.

**Verified by running it.** The tracefs `sys_exit_rmdir` test saw only
`0xfffffffffffffff3` (`-EACCES`) for the denied request and
`0xffffffffffffffd9` (`-ENOTEMPTY`) for the allowed nonempty request; it
explicitly failed if the `-520` hexadecimal value appeared.  The matching
strace logs and trace are in `results/test-sentinel-containment/`.

**Verified by running it.** No observed native `rmdir` returned `-520` to
userspace.  The experiment did not exhaust signal interruption, daemon loss,
queue exhaustion, mount changes, or all VFS error paths, so those containment
paths remain unverified P1 work.

## Optional BPF candidate

**Believed from reading source.** Adding the generic `ask` LSM hook generates
`bpf_lsm_ask`; placing it in `sleepable_lsm_hooks` permits
`SEC("lsm.s/ask")`.  The BPF experiment added that one BTF-set line and
registered `filemaster_bpf_wait()` for `BPF_PROG_TYPE_LSM` with
`KF_SLEEPABLE`.

**Verified by running it.** The live kernel BTF contained
`filemaster_bpf_wait`, and the guest built and attached a non-sleepable
`SEC("lsm/path_rmdir")` pass-one program plus a sleepable
`SEC("lsm.s/ask")` post-unwind program.  The source and loader are saved in
`scripts/bpf/`; `scripts/build-bpf.sh` derives `vmlinux.h` from the live BTF.

**Believed from reading source.** The `v7.1` sleepable BPF trampoline calls
`rcu_read_lock_trace()` before invoking the program and
`rcu_read_unlock_trace()` afterward, so an untimed kfunc wait is inside a
tasks-trace RCU read-side critical section.  The saved excerpt is
`results/bpf-sleepable-trampoline-v7.1.txt`.

**Verified by running it.** With the BPF prompt parked, an actual separate
`vmctl ssh` session attached then detached an unrelated sleepable
`SEC("lsm.s/file_open")` program.  The cycle completed while the first
session’s prompt remained parked: attach took about 35 ms and link destruction
about 9 ms (`results/bpf-second-shell-cycle.log` and
`results/bpf-second-shell-pending-after-cycle.log`).

**Verified by running it.** With a BPF post-unwind program itself parked,
detaching its pinned link returned in about 7 ms before the Allow response.
The in-flight invocation later consumed Allow and the `rmdir` completed.  The
test output is `results/bpf-post-detach.log` and
`results/test-bpf-candidate.log`.

**Believed from reading source.** Prompt detach completion does not show that
tasks-trace RCU was absent: `bpf_link_free()` queues
`call_rcu_tasks_trace()` for sleepable links, so the observed command can
return before deferred program reclamation waits for the parked reader.  The
saved teardown excerpt is `results/bpf-link-teardown-v7.1.txt`.

**Verified by running it.** With pass one attached but the post-unwind BPF
program absent, `rmdir` failed closed with `EIO` without a second prompt.  The
strace is `results/bpf-no-post.strace`.

**Believed from reading source.** With no BPF `ask` program attached, the
generic Ask hook returns its default success; on retry the BPF map’s retained
WAITING state is deleted and converted to `EIO`, rather than emitting the
sentinel again.

**Believed from reading source.** This makes the BPF variant a functional
candidate but not a cleared architecture: the required direct detach commands
did not block, while the source still places an untimed wait inside
tasks-trace RCU and defers reclamation.  A later decision should treat that as
a lifecycle cost/risk until it is independently measured or eliminated.

## Surprises, blockers, and cost implications

**Verified by running it.** The design document’s critical placement claim was
not contradicted on `v7.1`; `break_deleg_wait()` really followed the ordinary
`rmdir` unwind.  Its exact line references had drifted, and the function is
conditional on a delegated inode, so the implementation deliberately keeps
the new Ask wait after that branch.

**Verified by running it.** The VM’s BIOS GRUB did not consume the initial
`grub-reboot` `next_entry`; the custom kernel booted only after the helper
used the VM-supported `GRUB_TOP_LEVEL=/boot/vmlinuz-linux-filemaster-p1` and
regenerated `grub.cfg`.  `scripts/prepare-boot.sh` records this workaround and
`scripts/restore-stock-boot.sh` restores the saved prior configuration.

**Verified by running it.** The default mkinitcpio configuration expected
modules intentionally omitted by the trimmed kernel, including `crypto_lz4`.
The final custom initramfs configuration and a `CRYPTO_LZ4=m` setting fixed
the build; both are saved under `config/`.

**Verified by running it.** The first BPF userspace build failed because
glibc `errno.h` for the BPF target sought a 32-bit glibc stub and because
bpftool-generated `vmlinux.h` tripped `-Wmissing-declarations` under
`-Werror`.  The final script uses local Linux errno constants and suppresses
only that generated-header warning.

**Verified by running it.** The BPF verifier rejected returning the kfunc’s
unconstrained `int` directly from an LSM program, whose return range is
restricted to Linux errno values.  The experimental BPF code now normalizes
every nonzero kfunc result to fail-closed `-EACCES`.

**Believed from reading source.** The positive cost change is that the native
VFS portion is 16 additions and one deletion, with ordinary second-pass VFS
validation preserved.  The negative cost change is the 38-line generic hook
surface plus a substantial LSM protocol implementation and, for BPF, BTF,
kfunc, loader, pinning, and deferred-lifecycle complexity.

**Verified by running it.** The host started with roughly 75 GiB free and had
about 70 GiB free after the experiment; the guest retained about 58 GiB free.
The trimmed configuration avoided a full distribution-kernel build.

## Configuration and reproduction

**Verified by running it.** The exact final `.config` is
`config/linux-v7.1-filemaster-p1.config`.  It began from upstream
`x86_64_defconfig`, enabled Filemaster/securityfs/path LSM, lockdep, tracing,
virtio, ext4, Btrfs, loopback, BPF LSM and BTF, and disabled major unused
hardware/network classes.  The recorded final count is 1,404 enabled symbols
and 4 modules; `results/final-config-summary.txt` lists the material symbols.

**Verified by running it.** The executable build, install, boot, test,
evidence, patch-export, and patch-apply scripts are all under `scripts/`.
`REPRODUCE.md` gives a cold-start sequence, including the optional BPF run and
how to restore the prior VM boot default.

**Verified by running it.** No change was made to existing Filemaster source
or documents for this experiment; this file is the sole new file in
`/root/filemaster/docs/`, and it was intentionally not staged or committed.
