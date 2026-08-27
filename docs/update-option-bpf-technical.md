# BPF LSM update option — technical proof and implementation note

## Result

The focused proof in `/root/vm/share/fanotify/bpf-lsm-poc` passed on
2026-08-26 against the running Arch guest kernel `7.1.8-arch1-3` on x86-64.
Its active LSM list included `bpf`. It built with Clang 22.1.8, loaded with
libbpf, and used the running kernel's BTF from `/sys/kernel/btf/vmlinux`.

The test attaches exactly four upstream BPF LSM programs:

| Filemaster operation | LSM hook |
| --- | --- |
| Delete file | `inode_unlink` |
| Delete empty folder | `inode_rmdir` |
| Create hard link | `inode_link` |
| Rename | `inode_rename` |

Each hook's BPF program calls the same static policy lookup. For every listed
operation, the proof verified all of the following before observing the
filesystem result:

| Static map state | Result |
| --- | --- |
| Allow | The syscall and its filesystem side effect succeed. |
| Deny | `-EPERM`; no side effect. |
| Ask | `-EPERM`; no prompt and no side effect. |
| No map entry | `-EPERM`; no side effect. |
| Unrepresentable value | `-EPERM`; no side effect. |

These four `inode_*` hooks were picked without evaluating the `path_*`
alternatives; see [The `path_*` hook family](#the-path_-hook-family).

The test process is selected by TGID before it is resumed. That is only an
isolation mechanism for the proof; it is not the planned Filemaster process
identity or policy model.

## Lifecycle evidence

1. The object loaded and attached through a libbpf skeleton.
2. The policy hash-map value was updated for every test state.
3. After detaching the links, a selected process with a Deny map entry could
   delete a file. The proof therefore makes no claim of enforcement after
   detachment.
4. A fresh object and fresh map again denied an operation with no entry.
5. After the process exited, `bpftool prog show` and `bpftool link show` had
   no Filemaster proof program or link remaining.

The object-surface check accepts only the four `inode_*` sections above. It
contains no `file_open`, execute, or other program, so it cannot create a
second Open or File Execute decision path.

## Implementation consequences

1. Keep BPF structural enforcement separate from the current fanotify
   `Source` and decision pipeline. It has no synchronous prompt and no
   userspace wait; it should be a `FileAccess`-owned static structural
   enforcer with its own lifecycle and coverage status. It does emit an
   asynchronous denial event — see
   [Decided behaviour: deny with feedback](#decided-behaviour-deny-with-feedback).
2. Share the operation enum and static outcome semantics with the Go policy
   compiler, but do not make BPF-map layout part of the product rule format.
   The loader alone translates an already-resolved static snapshot into maps.
3. Use the loader's separate load and attach phases: create/load the object,
   populate and validate the complete policy snapshot, attach every required
   link, then publish the backend as enforced. Do the reverse on planned
   shutdown. Never attach a globally fail-closed program before its intended
   scope and policy are ready.
4. Individual map updates are atomic, but a multi-map policy update is not a
   complete snapshot. Before production, prove one generation-switch design
   (for example an inactive generation plus one active selector) and test that
   a failed or interrupted update cannot expose a partial Allow policy.
5. The TGID gate in the proof is test isolation only. Do not reuse it as
   Filemaster process identity: it does not express profiles and is vulnerable
   to normal PID lifetime/reuse issues. Compile an independently proven process
   identity into the static policy instead.
6. The proof's links disappear when its loader exits. Production must explicitly
   choose and test its daemon-crash behaviour: detach and report no protection,
   or persist a known fail-closed policy/link until the service repairs it. A
   successful object load is not enough to claim protection.

## Decided behaviour: deny with feedback

A BPF LSM program cannot prompt or wait for a userspace decision. The accepted
consequence is that a BPF-owned operation denies by default: Ask, no matching
static policy, an unsupported operation, or an unrepresentable policy case all
return `-EPERM`.

This is a deliberate trade, not a limitation to be worked around. Failing to
block is worse than blocking something the user would have allowed, so the
operation is denied first and the user grants afterwards.

To keep that usable, a denial must not be silent. The intended flow is:

1. The LSM program denies and emits the denial over a ring buffer.
2. Userspace surfaces what was blocked and offers to allow it.
3. On approval the static policy updates and the user retries the operation.

Two consequences for planning:

- The retry is the user's. Nothing replays the denied syscall, so the flow has
  to be legible enough that retrying is the obvious next step.
- The ring buffer, the notification surface, and the approve-and-retry flow are
  **not** covered by the six rows of the production estimate in
  [update-options-cost-technical.md](update-options-cost-technical.md#bpf-lsm).
  That estimate needs a row for them.

Deny-by-default applies only to BPF-owned structural operations. Open and File
Execute remain fanotify's, with their existing interactive prompt.

Weight this accordingly: if BPF LSM is the endpoint rather than an interim
backend, this flow *is* the product's answer for delete, rename and link — not a
stopgap affordance around a missing prompt. The denial notice and the
approve-and-retry path then carry the same design weight as the fanotify prompt
does today.

## Hook-context limits to resolve before implementation

The tested hook signatures expose the following kernel objects (plus the LSM
chain's prior return value):

| Hook | Inputs | Consequence |
| --- | --- | --- |
| `inode_unlink`, `inode_rmdir` | Parent inode and target dentry | No mount or complete path is supplied. |
| `inode_link` | Source dentry, destination directory inode, destination dentry | The policy must account for both source and destination. |
| `inode_rename` | Old directory/dentry and new directory/dentry | The policy must account for both ends; the tested hook has no rename-flags argument. |

The proof therefore establishes no map key for Filemaster path, mount,
original-path, profile, or hard-link semantics. Note the scope of that
statement: the proof never attempted path resolution at all.
`filemaster_lsm.bpf.c` contains four `SEC("lsm/inode_*")` programs and no path
handling of any kind, so this is an untested area, not a demonstrated limit.

### The `path_*` hook family

The `inode_*` hooks were chosen without comparing them against the parallel
`path_*` LSM hook family, which takes `struct path *` — dentry **and**
vfsmount — and so carries the mount context the `inode_*` hooks lack.

Verified on 2026-08-26 by scanning `/sys/kernel/btf/vmlinux` on the same Arch
guest that ran the proof (`7.1.8-arch1-3`, active LSM list
`capability,landlock,lockdown,yama,bpf`). All four proven operations have a
corresponding `path_*` stub, alongside several Filemaster would want later:

| Filemaster operation | `inode_*` hook (proven) | `path_*` stub (present, attach unverified) |
| --- | --- | --- |
| Delete file | `inode_unlink` | `bpf_lsm_path_unlink` |
| Delete empty folder | `inode_rmdir` | `bpf_lsm_path_rmdir` |
| Create hard link | `inode_link` | `bpf_lsm_path_link` |
| Rename | `inode_rename` | `bpf_lsm_path_rename` |
| — (future) | — | `path_mkdir`, `path_symlink`, `path_mknod`, `path_truncate`, `path_chmod`, `path_chown`, `path_chroot` |

The same stubs are present on the Debian 6.12 development host, so this is not
an Arch-specific kernel configuration.

### Status of `path_*`

Presence of a BTF stub proves the hook is compiled in. Kernel source answers the
question that mattered most; the remainder is still untested.

1. **`bpf_d_path()` is callable from these hooks — established by source read,
   not by running it.** `bpf_d_path_allowed()` returns
   `bpf_lsm_is_sleepable_hook(prog->aux->attach_btf_id)` for
   `BPF_PROG_TYPE_LSM`, and the `sleepable_lsm_hooks` set contains **every hook
   Filemaster wants, on both families**: `bpf_lsm_inode_unlink`,
   `bpf_lsm_inode_rmdir`, `bpf_lsm_inode_rename` (plus `inode_create`,
   `inode_mknod`, `inode_symlink`, `inode_setattr`), and inside
   `#ifdef CONFIG_SECURITY_PATH` the whole set `bpf_lsm_path_unlink`,
   `bpf_lsm_path_rmdir`, `bpf_lsm_path_link`, `bpf_lsm_path_rename`,
   `bpf_lsm_path_mkdir`, `bpf_lsm_path_symlink`, `bpf_lsm_path_truncate`,
   `bpf_lsm_path_chmod` and `bpf_lsm_path_chown`. The check is on the hook, not
   on whether the program itself is sleepable. Consequence: the `struct path`
   does not have to be walked by hand, and these are intended BPF LSM attach
   targets rather than merely compiled-in stubs.

   Note `bpf_lsm_inode_link` is **not** in the set, so `bpf_d_path()` is
   unavailable at `inode_link` — but `path_link` is in the set, so the `path_*`
   family closes that gap. This is a reason to prefer `path_*` for production,
   beyond the mount context it carries.
2. That a `SEC("lsm/path_rename")` program loads, attaches, and enforces in
   practice. Item 1 makes this expected rather than uncertain, so treat it as a
   confirmation step inside the first production hook work, not as a separate
   gating spike.
3. Behaviour under bind mounts, overlayfs, mount namespaces, and
   destination-overwrite rename. Untested, and now the substantive unknown in
   this area.
4. `path_*` hooks are gated on `CONFIG_SECURITY_PATH`. It is enabled on both
   kernels checked, including the Arch guest, which runs neither AppArmor nor
   TOMOYO. SELinux-only distributions (Fedora, RHEL) are the ones to confirm.
   The runtime probe is the BTF stub scan above.

Provenance: item 1 comes from reading `kernel/bpf/bpf_lsm.c` and the
`bpf_d_path` allowlist in `kernel/trace/bpf_trace.c`, not from the 7.1.8 guest.
Re-confirm the set membership against the target kernel when the first `path_*`
program is written, since the set is source-defined and not exported through
BTF.

Path-based policy is therefore source-supported and runtime-unconfirmed. The
`inode_*` results remain the only enforced-and-observed evidence.

### Required P1

Prove the exact identity available at every claimed hook, including bind
mounts, hard links, replacement, and destination-overwrite rename. Do not
promise a distinct `RENAME_EXCHANGE`, whiteout, or flag-specific policy from
`inode_rename` unless a separately proven context source makes the distinction
available; check whether `path_rename` closes that gap before assuming it
cannot be closed.

The first production VM matrix should add rename over an existing destination,
rename flag variants, cross-directory rename, hard-link creation followed by
later access, and the same operations through `*at()` callers. It must also
prove that Open and File Execute still follow fanotify alone while the BPF
links are active.

## Important non-results

1. This is operation-only policy. It does not prove pathname, inode, mount,
   original-path, profile, or application identity for Filemaster rules. That
   is because the proof never tested them, not because the hooks cannot supply
   them — see [The `path_*` hook family](#the-path_-hook-family).
2. `chmod` was intentionally run after reloading the proof and succeeded. It
   is outside the four-hook surface, so the result is a coverage limit rather
   than an Allow decision.
3. The proof does not test Filemaster's running fanotify service, interactive
   prompts, map pinning/replacement across a daemon restart, loader crash
   recovery, or an honest production coverage report.
4. It does not establish coverage for create, mkdir, symlink, metadata,
   truncate, allocation, clone/dedupe, or any other operation not listed in
   the table.

## Consequence

The target kernel can enforce the tested static structural subset using the
existing upstream BPF LSM hooks. That clears the minimal hook-feasibility gate
and supports the scoped four-hook estimate, but it does not justify extending
that estimate or claiming coverage for Filemaster's remaining requirements.
This static-only route can remain the final choice if its proven coverage meets
the chosen product scope; interactive decisioning is a separate later route —
see [Upgrade path](#upgrade-path).

Under the priority split in
[Backend Feature Requirements](backend-features.md#super-high-priority), that
scope question has a concrete answer for the four proven operations. Blocking
delete, rmdir, link and rename before they commit is the Super High requirement,
and static BPF enforcement satisfies it outright — including the rule that an
Ask which cannot be presented is a denial. What BPF lacks is the interactive
decision and its commit-time revalidation, which are High priority, and which no
amount of hook work inside BPF can supply.

So the gap between this option and an interactive backend is one priority tier,
not a hole in the top tier. Whether to close it is a product judgement about how
much the deny-and-retry flow costs in daily use — information that only running
this backend produces.

## Upgrade path

Closing that tier means adding an untimed interactive prompt before a
structural operation commits. **BPF bytecode cannot host that wait.** No BPF
primitive suspends a task until userspace answers; BPF can emit over a ring
buffer but cannot block for a reply, and the verifier rejects an unbounded wait
loop. A BPF program *can* return the internal sentinel the retry design uses —
`bpf_lsm_get_retval_range()` permits `[-MAX_ERRNO, 0]`, so a value above 511 is
legal — but the queue, correlation, wait, verdict cache, and reply transport
are native C in every route.

A custom kernel could expose that native wait to BPF through a `KF_SLEEPABLE`
kfunc rather than a native LSM, and the relevant `path_*` hooks are in
`sleepable_lsm_hooks`. That does not make this an option on a **stock** kernel:
the kfunc and the new post-unwind hook both have to be compiled in, and a wait
at the stock hooks is unsafe regardless of who sleeps, because the parent
`i_rwsem` and the mount-write reference are held there. See
[BPF cannot own the wait, and a kfunc does not change that](update-option-bpf-dkms-technical.md#where-bpf-can-and-cannot-sit).

The upgrade is therefore a **replacement, not an extension**: the interactive
stage is the
[LSM + DKMS backend](update-option-lsm-dkms-technical.md), built fresh, with
the BPF backend detached at cutover and no split ownership left behind. That
route is described in
[BPF then DKMS](update-option-bpf-dkms-technical.md). It is an upgrade to
consider later, not a committed plan.

Two things this phase can produce that the upgrade depends on, and which are
worth doing here rather than deferring:

1. The `path_*` hook evidence above — bind mounts, overlayfs, mount namespaces,
   and destination-overwrite rename. Stage two uses the `path_*` family.
2. The operation matrix, fail-closed matrix, and VM corpus.

About **45% of production and 50% of tests** carry across; see
[Cost of going via BPF](update-option-bpf-dkms-technical.md#cost-of-going-via-bpf).
Do not read the low figure as a mark against this route — it is low precisely
because this phase ships a working backend rather than groundwork.
