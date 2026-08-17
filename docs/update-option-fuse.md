# FUSE backend exploration

> **Status: unreviewed research note.** This document collects investigation
> ideas for a possible backend. It does not select FUSE, describe supported
> Filemaster behaviour, or establish verified Linux-kernel facts.
>
> Shared and FUSE-specific evaluation checks are in
> [Backend Test Requirements](backend-test-requirements.md).
>
FUSE-based Linux file-access backend for Filemaster as an alternative
to fanotify.

Kernel behaviour described here was verified against Linux 7.1.8. Claims marked
*demonstrated* were reproduced experimentally; claims marked *unverified* were
reasoned from source and still need testing.

# Goal

Make Filemaster participate synchronously in filesystem operations so it can
reliably enforce app-specific access decisions for
open/read/write/create/delete/rename/move/truncate/link/etc., and support a
strong "freeze" mode, without relying on mutable pathname reconstruction after
the operation has started.

Keep Filemaster's existing policy/profile/rule model. Watch paths define
enforcement scope; do not invent separate policies per watched path. Reuse the
existing decision pipeline where sensible, but design the FUSE backend around the
semantics FUSE actually provides rather than forcing the Fanotify abstraction
onto it.

Implement this as a contained prototype/backend, not an irreversible rewrite.

# Threat model

**A virus the user downloads and deliberately runs.** It executes under the
user's own account, holds the user's privileges, can read Filemaster's policy and
code, can be written specifically to defeat it, and can use unprivileged user
namespaces (`unshare -rm`). It is *not* assumed to have root.

This is the hard case, and it rules out identifying applications by any
attacker-controllable string. See *Caller identity*.

# Settled decisions

## Enforcement happens at the open

Filemaster decides at Open. **Gating later read/write system calls is not
required.** A file that has been opened successfully is expected to be readable
or writable.

This is the most load-bearing decision here. It makes `FOPEN_PASSTHROUGH`
compatible with the design rather than a threat to it, and it removes any need to
sit in the read/write path.

## Revocation is desirable, not required

Making an already-open handle stop working when policy changes is a
**nice-to-have**. Do not compromise the open-scoped design or the performance
story to obtain it. See *Revocation* for how to add it afterwards.

## Start conservatively, with one exception

* no writeback cache initially
* **do** evaluate passthrough early — see *Passthrough* below
* be very careful with writable `MAP_SHARED` mmap; do not claim freeze or
  revocation is safe if existing mappings can bypass it
* deny or fail safely when caller identity cannot be reliably resolved

# Kernel-side facts

## Operation coverage

Every operation in the target feature list has a corresponding FUSE request.
There is no coverage gap to design around.

| Feature | FUSE op |
|---|---|
| Open, with requested access mode | `FUSE_OPEN` (flags carried in the request) |
| Directory listing | `FUSE_OPENDIR`, `FUSE_READDIR` |
| Delete | `FUSE_UNLINK`, `FUSE_RMDIR` |
| Create | `FUSE_CREATE`, `FUSE_MKNOD`, `FUSE_MKDIR` |
| Link | `FUSE_LINK`, `FUSE_SYMLINK` |
| Rename / move | `FUSE_RENAME`, `FUSE_RENAME2` |
| Truncate | `FUSE_SETATTR` |
| Metadata write | `FUSE_SETATTR`, `FUSE_SETXATTR`, `FUSE_REMOVEXATTR` |
| fallocate / hole punch | `FUSE_FALLOCATE` |
| Clone / copy | `FUSE_COPY_FILE_RANGE` |
| Metadata read | `FUSE_GETATTR`, `FUSE_ACCESS`, `FUSE_LISTXATTR` |

The kernel resolves the path before issuing the request, and the server then
*performs* the operation itself, so check and action are the same code path.
There is no TOCTOU gap between the decision and the act.

## Execve intent is visible

FUSE **can** distinguish an execve from an ordinary open, contrary to what is
commonly assumed. Do not build around a supposed absence of exec information, and
do not fake the distinction either — the real signal is there.

`__FMODE_EXEC` is bit `040` (`include/linux/fs.h:118`), unused in the `O_*`
space. It travels in `file->f_flags`, which is exactly how fanotify distinguishes
exec (`include/linux/fsnotify.h:443`). FUSE forwards `file->f_flags` verbatim to
the server (`fs/fuse/file.c:194`), masking off only `O_CREAT`, `O_EXCL`,
`O_NOCTTY` and conditionally `O_TRUNC` (`file.c:34-36`). The bit survives.

*Demonstrated* with a minimal libfuse filesystem:

	plain read : flags=0100000   __FMODE_EXEC(040)=clear
	execve     : flags=0100040   __FMODE_EXEC(040)=SET

Two caveats travel with it:

* It is **incidental, not a protocol guarantee.** libfuse defines no constant for
  `040` and nothing documents the behaviour. Re-verify on the target kernel; do
  not treat it as stable API.
* The scope is execve only, identical to `FAN_OPEN_EXEC_PERM`. Shared libraries
  loaded by `ld.so` are ordinary `O_RDONLY` opens, and `mmap(PROT_EXEC)` on an
  already-open descriptor produces no FUSE request at all.

The remaining limit is scope, not capability: only binaries **under the mount**
are visible. Executables in `/usr/bin` remain fanotify's job.

## Availability

* `CONFIG_FUSE_FS` is `tristate` — available as a module on stock kernels.
* `CONFIG_FUSE_PASSTHROUGH` is `default y` (`fs/fuse/passthrough.c`).
* `CONFIG_FUSE_IO_URING` is `default y` (`fs/fuse/dev_uring.c`).

Both optimisations are therefore likely present on target systems rather than
requiring a kernel change. Confirm per target rather than assuming.

## io_uring cannot bypass this

Because FUSE sits at the filesystem layer, operations issued through io_uring
reach it via the same VFS paths as ordinary syscalls. This is a real advantage
over syscall-level interception, where io_uring escapes entirely. Verify it, but
expect it to hold by construction.

# Passthrough

Under open-scoped enforcement, `FOPEN_PASSTHROUGH` preserves the guarantee
exactly: the server decides at `FUSE_OPEN`, then I/O runs at near-native speed
with no further round-trips.

**Evaluate it early rather than deferring it.** Measuring naive FUSE and
extrapolating will overstate the option's cost.

The one thing it forecloses is revocation: once passthrough is established for a
file, the server sees nothing further. Since revocation is a nice-to-have, a
reasonable shape is

* **passthrough on** for read-only opens, and
* **passthrough off** for writable opens, where the ability to start refusing
  matters and where the damage lives.

`FOPEN_PASSTHROUGH` is chosen per open, so making this decision per file costs
nothing structurally.

Before adopting writeback caching or aggressive attribute caching, prove the
optimisation does not weaken enforcement. That test does not apply to passthrough
under open-scoped enforcement, but it does apply to caching — see *Questions*.

# Requirements

## Freezing must handle `FUSE_INTERRUPT`, or it wedges processes

This is a requirement, not a test case. A FUSE backend that ignores it will hang
users' applications with no way out.

`request_wait_answer()` (`fs/fuse/dev.c:552`) waits in three stages:

1. `wait_event_interruptible` (`:560`) — any signal wakes it, and the kernel then
   sends the server a `FUSE_INTERRUPT` message naming the request.
2. `wait_event_killable` (`:576`) — only fatal signals. If the request is **still
   queued**, the kernel removes it and the process escapes cleanly (`:589-591`).
3. `wait_event` (`:598`) — **uninterruptible and unkillable.**

Stage 2's escape only works while the request is still on the queue. A freeze is
by definition a request the server has already *read* and is deliberately not
answering, so `SIGKILL` finds nothing to cancel and the task falls into stage 3.
The process is then unkillable, including by root, until the server replies.

The only in-band escape is to answer `FUSE_INTERRUPT` by completing the frozen
request with `EINTR`. That keeps processes killable but makes freezes fragile:
the message is sent for *any* deliverable signal, not only fatal ones. Signals a
process ignores never become pending and so never interrupt — but timer,
child-exit and terminal-resize handlers are common enough that this matters.

`struct fuse_interrupt_in` (`include/uapi/linux/fuse.h:952`) carries only the
request id — **no indication of which signal arrived.** Distinguishing a kill
from a benign signal would require reading pending-signal state from
`/proc/<pid>/status`, which is *unverified* and puts a `/proc` read in the escape
path.

Last resort is `/sys/fs/fuse/connections/<n>/abort` (`fs/fuse/control.c:35`),
which fails every pending request and tears down the mount.

**fanotify has no equivalent problem.** Its permission wait is
`TASK_KILLABLE|TASK_FREEZABLE` (`fs/notify/fanotify/fanotify.c:232-234`) with no
uninterruptible fallthrough, so a frozen process is always killable however long
the decision is held. Indefinite-and-killable comes free there and must be
engineered here.

## Caller identity

`fuse_in_header` (`include/uapi/linux/fuse.h:1034`) carries `uid`, `gid` and
`pid` and nothing else. There is no pidfd, no cgroup, no executable reference.
Under this threat model it is the weakest part of the option.

* The `pid` is set from `pid_nr_ns(task_pid(current), fc->pid_ns)`
  (`fs/fuse/dev.c:234`). `task_pid` is the **thread** id, so reaching the process
  needs `/proc/<tid>/status` → `Tgid`.
* `pid_nr_ns` returns **0** when the caller is not visible in the pid namespace
  captured at mount time (`fs/fuse/inode.c:1026`). Flatpak and bubblewrap put
  applications in their own pid namespace, so this is not a corner case — measure
  it before assuming fail-closed is acceptable.
* Identity must be re-resolved from `/proc` on every request. fanotify's
  `FAN_REPORT_PIDFD` gives a stable handle that can be recorded once at exec and
  compared later; nothing here does.
* Asynchronous requests carry no meaningful actor. Because `dev.c:234` uses
  `current`, writeback, readahead and deferred `FUSE_RELEASE` are attributed to
  kernel flusher threads, not to the application that caused them.

### Two attacks that defeat path-based identity

Both apply to **every** option under evaluation, including the existing fanotify
backend and Portmaster's network filtering. Neither is FUSE-specific, but do not
assume they are solved.

**Mount-namespace path spoofing.** An unprivileged process can build its own
mount view and overlay a trusted path onto its own binary:

	unshare -rm
	mount --bind /tmp/evil /usr/bin/firefox
	exec /usr/bin/firefox

A daemon in the init namespace reading `readlink("/proc/<pid>/exe")` gets the
string `/usr/bin/firefox`. *Demonstrated.* The mechanism: `proc_exe_link`
(`fs/proc/base.c:1760`) returns the target's `f_path` including its vfsmount;
`d_path` (`fs/d_path.c:265`) resolves against the *reader's* root but ignores
`prepend_path`'s return value, and `prepend_path` only resets the buffer on
error 3 (overflow), not error 1 (unreachable) — `d_path.c:189-190`.

**This one is cheaply fixable.** `proc_pid_get_link` calls `nd_jump_link()`
(`base.c:1810`), so *opening* `/proc/<pid>/exe` reaches the real file. Compare
`st_dev`/`st_ino` from an `fstat` on the opened link instead of trusting the
readlink string. *Demonstrated*: `stat -L` returned the attacker's inode while
`readlink` returned the spoofed path.

Filemaster inherits the vulnerable form today —
`service/process/process.go:296` calls gopsutil's `ExeWithContext`, which is
`os.Readlink("/proc/<pid>/exe")` (`gopsutil/process/process_linux.go:689`) — and
`service/profile/fingerprint.go:35-38` matches on `path`, `cmdline`, `env` and
`tag` with no binary-content hash. Fix this regardless of which backend wins.

**`LD_PRELOAD` into a trusted binary.** The malware does not imitate a trusted
application; it *launches* one:

	LD_PRELOAD=/tmp/evil.so /usr/bin/some-trusted-app

`/proc/<pid>/exe` is the genuine binary, with the correct inode and signature. No
path, hash or signature check detects this, and no interception mechanism helps,
because identity is resolved *correctly* and the answer is still wrong.

The only defence is **provenance recorded at launch**: at `FAN_OPEN_EXEC_PERM`
the parent is still the untrusted process, so the child can inherit distrust
without detecting the injection. That requires fanotify — FUSE sees execs only
under its own mount, and `/usr/bin` is not under it. It also does not cover
`ptrace` injection or a D-Bus/portal confused deputy, since neither involves an
execve.

**Decide explicitly** whether identity is established at launch and carried as a
token, or inferred per request from `/proc`. Per-request inference does not
survive this threat model on any backend.

## Backing-store containment

Preventing bypass of the FUSE view is the central security requirement. The
underlying backing filesystem must not be reachable by normal applications
through another pathname, bind mount, mount namespace, stale directory FD, or
anything else. Do not assume mounting FUSE over a directory automatically secures
processes that already had access to the underlying tree.

Ordinary DAC appears sufficient: run the daemon as root, place the backing store
under a `0700` root-owned directory outside the mount, and mount FUSE over
`/home/<user>`. The virus runs as the user and cannot traverse the parent, so it
can neither read the backing files nor `mount --bind` them (bind requires access
to the source path). `unshare -rm` does not rescue it: inside a user namespace a
process holds capabilities only over mapped uids, and root-owned host files are
unmapped.

**This is *unverified*.** It is the load-bearing assumption for the whole option
and should be the first thing tested: a non-root process under `unshare -rm`
attempting to read, traverse and bind-mount a `0700` root-owned backing
directory.

Independently: descriptors and working directories opened *before* the mount
existed refer to the backing store directly and bypass FUSE entirely, so the
mount must be established before any user process starts.

## Filesystem semantics

Preserve normal filesystem semantics as much as possible: ownership/modes, ACLs,
xattrs, links, locks, fsync, truncate, atomic rename/replacement, tmpfiles, mmap,
sparse files, nested mounts, and relevant ioctls/filesystem features. Identify
anything that cannot be transparently preserved rather than silently weakening
semantics.

## Failure behaviour

Filemaster must not casually wedge the whole managed filesystem. Keep the
synchronous filesystem path bounded and make overload and failure behaviour
explicit and safe. Handle daemon crash and restart, request cancellation,
timeouts and signals, queue exhaustion, and concurrent requests.

Note that the failure mode differs from fanotify's in kind, not degree: fanotify
degrades to the configured default if the listener dies, whereas a dead FUSE
daemon takes the filesystem with it.

Avoid recursion and deadlock when Filemaster itself performs filesystem
operations while servicing a request. A PID-based self-exemption is fragile here
for the reasons in *Caller identity*.

# What FUSE cannot do

Ranked by impact. Items 1–4 are structural and cannot be fixed by writing more
code.

1. **It sees only its own subtree.** Realistically `/home`. `/usr`, `/etc`,
   `/tmp` and `/var` are invisible, so exec control over system binaries and
   anything the malware does in `/tmp` is outside the mechanism entirely.
2. **Identity is weaker than the existing fanotify backend's** — see above.
3. **No true open-downgrade.** FUSE cannot rewrite the application's descriptor
   flags, so a denied write on an `O_RDWR` open fails at `write()` rather than
   producing a genuine read-only descriptor at `open()`. This is the one
   high-priority `Readme.md` item FUSE may be unable to meet.
4. **Memory-mapped writes cannot be intercepted or revoked.** Once a writable
   `MAP_SHARED` mapping exists, stores go to memory with no request generated.
   The only enforcement point is the open. True on every option.
5. **The daemon is a single point of failure for the whole tree** — see *Failure
   behaviour*.
6. **Freezing and killability conflict** — see *Requirements*.
7. **Caching is a correctness knob, not a performance knob.** `attr_timeout` and
   `entry_timeout` are the obvious answer to metadata-heavy `/home`, but a cached
   answer is a question that was never asked.
8. **Filesystem semantics are real work** — see above, plus daemon
   self-recursion.

# Revocation

Nothing on Linux can force-close another process's descriptor; there is no
`revoke()` syscall. The only way to take a file away from a running process is to
kill it. What is achievable is making the descriptor *stop working*.

**Within FUSE:** refuse subsequent `FUSE_READ`/`FUSE_WRITE` requests. Requires
passthrough to be off for that file — hence the read-only/writable split above.


## Hiding the file instead of refusing ("pretend it was deleted")

FUSE controls the entire filesystem view, so it can return `ENOENT` and make a
file appear not to exist rather than returning a permission error. This is a
genuine capability fanotify lacks: fanotify's custom deny errno is restricted to
`EIO`, `EPERM`, `EBUSY`, `ETXTBSY`, `EAGAIN`, `ENOSPC` and `EDQUOT`
(`fanotify_user.c:457-468`), and `ENOENT` is not on the list.

**Useful for denial at open.** It tells an adversary nothing about what exists or
what is protected, whereas `EPERM` confirms both.

**Useless as revocation.** Unix deliberately keeps open descriptors valid after
unlink, so a process that already holds the file is entirely unaffected — the
same reason a real `rm` does not stop a running program.

**It carries a real data-loss hazard.** Applications react to a file disappearing
by *propagating the deletion*. A sync client (Dropbox, Nextcloud, Syncthing) will
delete it on the server and every other device; a backup tool will drop it from
the backup set; a version-control client will stage a deletion. The lie is local,
the consequences are not.

If used at all, it must be an explicit per-application policy choice rather than
the default denial style, never presented to sync/backup/version-control clients,
and consistent between directory listing and `stat` — otherwise the illusion is
trivially detectable.

# Questions the evaluation must answer, not assume

1. **Downgrade semantics.** The target design requires that a denied write on an
   `O_RDWR` open yields a genuine read-only descriptor — the open succeeds and
   the descriptor reports read-only. FUSE cannot rewrite the application's fd
   flags, so the natural behaviour is that the open succeeds and the later
   `write()` fails instead. Determine precisely what is achievable, including
   what happens with a read-only backing file under `FOPEN_PASSTHROUGH`. This is
   item 3 in *What FUSE cannot do* and needs a definite answer, not an estimate.

2. **Freeze policy.** The mechanics are settled under *Requirements*; the policy
   is not. Decide whether `FUSE_INTERRUPT` is answered always (processes stay
   killable, freezes break on routine signals), never (freezes hold, processes
   wedge unkillably), or conditionally on a pending fatal signal — and if
   conditionally, verify that `/proc/<pid>/status` reflects a pending `SIGKILL`
   early enough to be useful.

3. **Caching versus correctness.** Quantify what enforcement is given up at each
   `attr_timeout`/`entry_timeout` setting, rather than treating caching as purely
   a performance knob.

# Scope and the fanotify boundary

Whole-system coverage is the ideal but is not mandatory. FUSE is inherently
mount-scoped, so it cannot deliver whole-system coverage the way a kernel-level
mechanism can. Address this directly rather than implicitly assuming a subtree:
state what is and is not covered, and what the backing-store arrangement must be
for the boundary to hold.


# Tests

Build adversarial tests for bypasses and races, not just happy paths.

* backing-path / bind-mount / mount-namespace bypasses
* `LD_PRELOAD` and mount-namespace identity spoofing
* caller identity under Flatpak/bubblewrap (expect `pid` 0)
* rename/move races
* create/delete/link/truncate
* freeze with already-open writable FDs
* freeze interrupted by fatal and non-fatal signals; confirm the process stays
  killable
* writable mmap behaviour
* daemon failure and timeout behaviour
* normal filesystem compatibility
* representative performance workloads, especially metadata-heavy `/home`, with
  and without passthrough

# Report on comparable axes

This option is being weighed against kernel-side alternatives. Report on the same
axes so the comparison is direct:

* Can it freeze indefinitely?
* Coverage scope
* Race-safety of the path presented to policy
* Per-kernel-version maintenance burden
* Code volume, in lines of userspace
* Deployment story

libfuse's `passthrough_hp` example is a reasonable starting point for estimating
volume.
