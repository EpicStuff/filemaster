# LSM + DKMS update option — native-LSM permission bridge

## Status and terminology

This is the native-LSM-first route. It is **architecturally viable for a
specific operation only after that operation passes the unwind and
re-resolution proof below**. It is not a claim that every Filemaster backend
feature is already safe to implement this way.

`+ DKMS` is shorthand for the later targeted-kernel change, not a claim that a
native LSM can be loaded as an ordinary DKMS module. The Filemaster LSM is
built into the target kernel and selected in its LSM configuration. The
targeted change may be delivered by a directly built custom kernel or, only
where separately proved suitable, by a livepatch/`klp-build` workflow.

The short overview is in the [+ DKMS overview](update-option-+dkms.md). This
document replaces two earlier designs: the one in which VFS sent structural
decisions directly to Filemaster and the LSM was retired, and the one in which
a new pre-lock hook received a copied, data-only candidate context. Both are
recorded in [Rejected mechanisms](#rejected-mechanisms).

This backend is also the second stage of the
["BPF then DKMS"](update-option-bpf-dkms-technical.md) upgrade path — an
option to consider later, not a committed plan. BPF bytecode cannot host an
untimed wait, so the wait is native C in every variant. There *is* a distinct
BPF-flavoured candidate in which that native wait lives in a `KF_SLEEPABLE`
kfunc called from BPF rather than in a registered LSM — see
[BPF LSM + native wait](update-option-bpf-dkms-technical.md#bpf-lsm--native-wait)
— but sizing puts it **larger** than pure native
(2,985–4,835 vs 2,655–4,275 production lines), so it is not a cheaper route to
this endpoint. Reaching it from BPF rather
than from [LSM only](update-option-lsm-only.md) means the native-LSM
groundwork in [Reuse from LSM only](#reuse-from-lsm-only) has to be built here
instead of already existing.

This route covers structural operations that need semantics current fanotify
permission events cannot supply. Fanotify remains the owner of the existing
interactive Open and File Execute path; the native-LSM permission bridge does
not replace or duplicate those decisions.

Kernel line references in this document were read against mainline at the time
of writing. `start_dirop()`/`end_dirop()` are a recent `fs/namei.c` refactor;
older kernels open-code the same thing as `inode_lock_nested()` plus
`lookup_one_qstr_excl()`. Pin the exact target kernel before P1 and re-read.

## Selected decision path

The LSM stays in the decision path and owns the wait. VFS gains only the
ability to unwind and retry:

```text
requesting task
    -> VFS resolves and locks as it does today
    -> existing security_path_* hook
    -> Filemaster LSM
         -> no answer yet: return the internal Ask sentinel
    -> VFS unwinds normally: locks, mount-write ref, and path refs released
    -> new generic security hook, called with nothing held
    -> Filemaster LSM
         -> publish a permission request, wait killably and untimed
         -> Filemaster userspace rule/prompt pipeline
         -> final Allow or Deny, cached against this task
    -> VFS restarts the operation from the pathname
    -> existing security_path_* hook
    -> Filemaster LSM
         -> cached answer matches the re-resolved objects: allow or deny
    -> normal later LSM checks and the operation commit
```

Two properties make this work, and both come from structure that
`fs/namei.c` already has:

1. **The unwind point already exists.** `filename_unlinkat()` and
   `filename_renameat2()` each end with a full-unwind retry point used today by
   `retry_estale`. Everything the operation acquired has been released there,
   and the caller's `struct filename` is still valid.
2. **The second pass is a real pass.** Re-resolution, locking, and every later
   security check happen normally. There is no bespoke revalidation step, so
   VFS never has to understand what Filemaster approved.

`Ask` is an internal Filemaster-LSM state, not an outcome returned to
userspace. The LSM ultimately returns only success or an error. This is
deliberately the same shape as a fanotify permission event: the kernel raises a
request, userspace answers Allow or Deny, and the original task resumes.

## The LSM is an event source, not a second rule engine

The daemon is the only place Filemaster rules are evaluated. The LSM does not
hold a compiled policy snapshot, does not resolve Allow/Deny in the kernel, and
does not implement a second matcher. It raises a permission event, waits, and
enforces the answer — exactly the role fanotify's permission group plays for
Open today.

This is a deliberate reversal of an earlier draft of this document, which gave
the LSM a kernel-side policy snapshot with a three-way Allow/Deny/Ask
classification. That reintroduced, one level down, the duplicated rule logic
the fanotify-shaped model exists to avoid.

| Concern | Where it is handled |
| --- | --- |
| Rule matching, profiles, prompt policy | Daemon only |
| Raising the event, correlation, wait, enforcement | Filemaster LSM |
| Unwind and restart | VFS, generically |
| Which subtrees produce events at all | Kernel-side scope marks (below) |

**Scope, not rules.** Forwarding every structural operation to userspace is the
fanotify model, and it has fanotify's cost: a round trip per event. The
mitigation is fanotify's mitigation — scope. The daemon tells the kernel which
mounts or subtrees are watched; anything outside them is allowed without an
event. That is a filter on *where events come from*, not a policy evaluator,
and it keeps `rm -rf` inside an unwatched build directory free. Anything
beyond that is a verdict cache, not a rule engine, and it is explicitly
deferred until measurement shows it is needed.

**Fail closed.** No listener, receiver disconnect, queue exhaustion, malformed
response, or kernel allocation failure is ever treated as Allow. "No prompt
timeout" governs a live request with an authorized receiver attached; it does
not require an unbounded wait when no receiver exists.

## Why the stock hooks cannot host the wait

Native LSM code can own a userspace query and wait. TOMOYO is the in-tree
existence proof. That does **not** make the existing hooks safe for an untimed
Filemaster prompt, and TOMOYO itself shows why.

`tomoyo_supervisor()` waits at the stock `path_*` hooks — under the operation
locks — but caps the wait: it loops `wait_event_interruptible_timeout(...,
HZ)` while `entry.timer < 10`, so **ten seconds maximum**, then falls through
to a rejection. That cap is not a design preference; it is the mitigation for
holding those locks. Filemaster's untimed-prompt requirement deletes the
mitigation, so it cannot adopt TOMOYO's placement.

What is held at each stock hook:

| Hook | Held across a wait there |
| --- | --- |
| `security_path_unlink()` | Parent `i_rwsem` exclusive (via `start_dirop()`), plus the `mnt_want_write()` reference |
| `security_path_rename()`, same directory | Parent `i_rwsem` exclusive, plus the mount-write reference |
| `security_path_rename()`, cross directory | Both parents' `i_rwsem`, **plus the per-superblock `s_vfs_rename_mutex`** taken by `lock_rename()` |

The cross-directory rename case is the decisive one. An untimed wait there is an
untimed filesystem-wide rename barrier, not merely a two-directory stall.

Note also that TOMOYO's `TOMOYO_RETRY_REQUEST` is **not** a precedent for
restarting the VFS operation. It retries only TOMOYO's own permission check,
inside a `do { } while (error == TOMOYO_RETRY_REQUEST)` loop in its own code.

## The unwind-and-retry mechanism

### Pass one

The existing hook runs unchanged, with a fully resolved `dentry`. The LSM
therefore has real target context — inode, type, ownership — to put in the
prompt and to hand the daemon. It raises no wait here. If the operation is in
scope and has no cached answer, it returns an internal sentinel.

The sentinel must live in the kernel's private, never-returned-to-userspace
errno range above 511, alongside `ERESTARTSYS` (512), `EOPENSTALE` (518), and
`ENOPARAM` (519). `EOPENSTALE` is precedent for a VFS-internal sentinel already
consumed inside `fs/namei.c`. The value must be translated by the retry helper
on every path; a test must assert it can never reach userspace.

The existing error paths then unwind the operation with no new code:
`end_dirop()` releases the parent lock, `mnt_drop_write()` releases the
mount-write reference, and `path_put()` releases the parent path and mount refs.

### The wait point

One new generic security hook is called at the point everything has been
released, immediately alongside the existing `retry_estale` check. Illustrative
only; the target-kernel ABI is part of P1:

```c
	path_put(&path);
	if (security_ask_pending(error)) {
		error = security_ask_wait();   /* dispatches into security/filemaster/ */
		if (!error)
			goto retry;
	}
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
```

All four candidate operations have this shape. `filename_renameat2()` takes it
at its `should_retry` block, after `mnt_drop_write()` and both `path_put()`
calls.

**`filename_rmdir()` already contains the exact structure this design needs.**
Its `break_deleg_wait()` sits after `end_dirop()`, `mnt_drop_write()`, and
`path_put(&path)` — every lock, the mount-write reference, and all path
references released — and is followed by `goto retry`. Mainline already waits
there on an outside party and then re-runs the operation. For `rmdir` this
design is not analogous to an existing kernel pattern; it *is* the existing
pattern, with a second reason to take the branch.

That makes `rmdir` the cheapest and least speculative first proof, and P1
should lead with it rather than with `unlink`.

**P1 ran this and it worked.** On Linux `v7.1` in the dev VM: Allow completed
the `rmdir`, Deny returned `EACCES`, a parked prompt did not block a
same-superblock cross-directory `rename` or an `fsfreeze`, and an Allow on a
nonempty directory returned `ENOTEMPTY` — second-pass semantics are ordinary
VFS, as designed. The measured change is **16 insertions and one deletion** in
`fs/namei.c` plus 38 lines of one-time generic hook plumbing. One correction:
the line references below had drifted, and `break_deleg_wait()` is conditional
on a delegated inode, so the new wait is placed after that branch rather than
reusing it. Full report: [P1 `rmdir` unwind-and-retry proof](p1-rmdir-technical.md).

Re-verified 2026-08-27 against a mainline `fs/namei.c` snapshot new enough to
have `start_dirop()`/`end_dirop()`. In `filename_rmdir()`, `security_path_rmdir()`
is called with the parent's `i_rwsem` held for write — `__start_dirop()` does
`inode_lock_nested(dir, I_MUTEX_PARENT)` — and with the `mnt_want_write()`
reference held; the `break_deleg_wait()`/`goto retry` block sits below `exit4:`,
`exit3:` and `exit2:`, after all three are released. Both halves of the design's
premise hold on that snapshot. P1 must confirm it on the exact kernel it builds,
since `start_dirop()` is recent and this area moves.

Per-operation differences to expect:

| Operation | Distance from the existing wait point |
|---|---|
| `filename_rmdir()` | None. `break_deleg_wait()` is already at the fully released point. |
| `filename_unlinkat()` | The delegation wait sits at the inner `retry_deleg:` label, after `mnt_want_write()`. The Filemaster wait must go one level further out. |
| `filename_renameat2()` | Same as unlink: move out to the `should_retry` block. |
| `filename_linkat()` | The source `old_path` is still held at the delegation wait. It must be released before the Filemaster wait, so this one needs a small restructure rather than an insertion. |

Unwinding this far out — rather than to the inner `retry_deleg:` label — is
deliberate. `retry_deleg:` sits *after* `mnt_want_write()`, so waiting there
would hold the mount-write reference and block `remount,ro` and `fsfreeze` on
that filesystem for the life of the prompt. The outer retry point has no such
residual.

The request, the correlation record, the queue, the untimed killable wait, the
verdict, and the final errno all live in `security/filemaster/`. VFS calls a
generic security hook and knows nothing of Filemaster's protocol, queue, or
prompt UI. This is what keeps the route "kernel -> LSM -> filemaster" rather
than a VFS path that goes around the LSM.

### Pass two

`goto retry` re-runs the operation from the caller's `struct filename`, which
survived the wait. Resolution, locking, and all later security checks happen
normally.

The LSM caches the verdict in its per-task LSM blob (`lsm_blob_sizes.lbs_task`),
keyed on operation, parent identity, final name, target identity, and the
daemon's answer generation. On pass two the hook finds the cached answer and
enforces it only if every key still matches the re-resolved objects. Any
mismatch — the name now refers to a different object, the mount changed, the
daemon restarted — fails closed. **Exactly one ask-retry is permitted per
syscall**; a second Ask without a matching cached answer returns the denial
error rather than looping.

The cached verdict is **single-use**. Clear it on every exit from the retry
helper, on the failure paths as well as the success path, so that a verdict
left behind by a killed or errored syscall can never be consumed by a later
unrelated one. Keep the ask-retry counter independent of the existing
`retry_estale` counter; the two must not share a budget, and their combination
must remain bounded.

Because pass two is an ordinary pass, TOCTOU is handled by re-resolution plus
the key match, not by hand-written revalidation inside VFS. Re-running a
resolution after dropping everything is established behaviour in these
functions already, via `retry_estale` and `break_deleg_wait`.

## LSM stacking and hook ordering

`call_int_hook()` short-circuits on the first non-default return
(`__CALL_STATIC_INT` in `security/security.c` jumps out as soon as
`R != LSM_RET_DEFAULT(HOOK)`). The sentinel therefore has stacking
consequences that must be proved, not assumed:

1. On pass one, LSMs ordered **after** Filemaster do not run. They run normally
   on pass two.
2. LSMs ordered **before** Filemaster run twice. Expect duplicate audit and
   SELinux AVC records for the same syscall.
3. Filemaster should therefore be ordered **last**. This bounds the duplication
   and gives a useful property: Filemaster only ever prompts for operations
   every other active LSM already permitted.
4. No successful pass-one check may become a bypass of any later check.

This must be exercised against a real stacked configuration, not only against a
kernel where Filemaster is the sole LSM.

## Who actually asked

The prompt must name the process the user recognises, and the wait must not
block infrastructure shared with unrelated work. Three cases break the naive
assumption that `current` is the asking process:

**io_uring.** `IORING_OP_UNLINKAT` and `IORING_OP_RENAMEAT` do not execute in
the submitting task; they run in an io_uring worker. Two consequences, and both
need proving rather than assuming:

1. `current` is a worker, so a prompt built from it names the wrong process.
   Resolve the submitting task's identity for the prompt instead.
2. An untimed wait occupies a worker from a shared pool. Confirm the ask path
   is reached only on the blocking-worker route, and that it does not surface a
   spurious error during io_uring's initial non-blocking attempt.

**Kernel threads.** Exclude `PF_KTHREAD`. There is no user to prompt.

**Stacked filesystems.** Overlayfs performs operations on its underlying layers
under overridden credentials, so one user-visible delete can reach the hook
more than once. Decide explicitly whether Filemaster acts on the overlay-level
operation, the underlying one, or both, and record the choice. Unhandled, this
produces duplicate prompts for a single user action — the most visible possible
failure of a prompting product.

These are the same three classifications the
[LSM-only phase](update-option-lsm-only-technical.md#kernel-internal-operations-are-not-user-operations)
must make. Settle them there, where the consequence is a duplicate silent
decision, rather than here, where it is a duplicate prompt.

## Permission-request lifecycle

For a claimed Ask-capable operation, all of these are mandatory:

1. The wait happens only at the new generic hook, with all locks, mount-write
   references, and path/dentry/inode references from the first pass released.
   This is verified against the unwind path, and re-verified whenever the
   target kernel's `fs/namei.c` changes.
2. The Filemaster LSM allocates and owns the request and correlation record and
   publishes it to an authenticated Filemaster receiver.
3. The triggering task waits killably. There is no answer timeout; a live
   request with an attached receiver may wait indefinitely. Fatal signal
   interruption removes the request safely and returns the documented
   interrupted-operation result.
4. Every failure mode in [fail closed](#the-lsm-is-an-event-source-not-a-second-rule-engine)
   denies.
5. Pass two re-resolves, re-locks, matches the cached verdict against the
   re-resolved objects, and runs all ordinary later checks before commit.
6. Exactly one Filemaster decision is enforced per syscall, and at most one
   ask-retry occurs.
7. The transport prevents self-recursion and does not let Filemaster's own
   userspace file access deadlock the request it must answer.

The Go side should be a new `fileaccess.Source` adapter. It turns an LSM
request into the existing `PendingEvent`/rule/prompt/`Respond(Verdict)` flow;
the kernel response carries the correlation ID and final verdict only. The
adapter needs richer namespace-operation fields than today's open event, but it
reuses the service's lifecycle, policy, prompt, and response machinery.

## Hook family across phases

The phases do not all use the same hook family, and this route depends on the
switch being made explicitly:

| Phase | Family | Note |
| --- | --- | --- |
| BPF LSM | `inode_*` proven and enforced; `path_*` source-supported, runtime-unconfirmed | See [BPF LSM technical](update-option-bpf-technical.md) |
| LSM only | `inode_*`, mirroring the BPF-proven set | Static only |
| LSM + DKMS | `path_*` | Needs the mount and path identity `inode_*` does not supply |

`path_*` hooks are gated on `CONFIG_SECURITY_PATH`
(`include/linux/lsm_hook_defs.h`); `inode_*` hooks are unconditional. The gate
is not a constraint for this route, which builds its own kernel, but it is one
for the BPF phase on distributions that ship neither AppArmor nor TOMOYO.

## Reuse from LSM only

| LSM-only work | Later LSM + targeted-kernel status |
| --- | --- |
| Native-LSM build, registration, ordering, health reporting, and boot checks | Retained. |
| Filemaster operation model, profiles, rule semantics, VM corpus, and fanotify coexistence tests | Retained; these are userspace and unaffected. |
| Privileged kernel/daemon channel: writer authorization, securityfs or generic netlink plumbing | Largely retained, repurposed from policy publication to event transport and scope marks. |
| Hook adapters | Retained and extended. Both passes go through the same hook; nothing is gated off. |
| Object identity derivation at the hook | Retained. Phase two needs the same stable identity as the verdict-cache key. |
| Published answer table | **Superseded.** Phase two answers from the daemon instead. Fully used during the LSM-only phase; not carried forward. |
| Table publication machinery: RCU-style lifetime, generation handling | Retained, repurposed to publish scope marks. |
| Event transport, correlation, killable wait, verdict cache, unwind/retry hook | New targeted-kernel work. |

Because the LSM-only kernel side is a lookup table rather than a matcher (see
[LSM-only technical](update-option-lsm-only-technical.md)), rule evaluation
never has to move between phases. The daemon decides in both; it precomputes in
phase one and answers live in phase two. What is discarded at the handover is
the table, not the thinking.

### How much of LSM only survives

Applied to the LSM-only production line items in
[the cost note](update-options-cost-technical.md#lsm-only), at midpoint:

| LSM-only line item | Mid LoC | Carried forward | Why |
|---|---:|---:|---|
| LSM registration, Kconfig, hook implementation | 350 | ~95% | Same hooks, same registration; both passes use the same adapter. |
| Marked-directory store, snapshot lifetime, control interface | 675 | ~70% | The mark set, its inode-walk lookup, and its publication path are exactly what phase two needs for scope. Only the decided-outcome payload attached to each mark is dropped. |
| Identity derivation, lookup, coverage status | 425 | ~60% | Identity and status survive as the verdict key; outcome lookup does not. |
| Daemon writer, lifecycle, diagnostics | 400 | ~75% | Same plumbing, different payload — replies instead of outcomes. |
| Custom Arch kernel build, packaging, VM support | 350 | 100% | Phase two needs the identical build and boot loop. |
| FileAccess/config integration | 275 | ~90% | Phase two adds a `Source` adapter beside the existing wiring. |
| **Production** | **2,475** | **~80%** | |

Tests carry less. The static outcome matrix, VM corpus, and fanotify
coexistence coverage survive; answer-publication tests largely do not, and
phase two adds sentinel containment, the one-ask-retry bound, LSM stacking, and
doubled-resolution performance. Call tests **~55%**.

Combined across the 4,500–7,950 production-plus-test band, **roughly 65–75% of
LSM-only work carries into LSM + DKMS**, with production nearer the top of that
range and tests nearer the bottom.

Keying the LSM-only table on marked directories rather than path strings is
what lifts this. Under a path-keyed table the store was largely discarded at
the handover; under inode-identified marks it *is* phase two's scope mechanism,
so the same code and the same publication path serve both phases.

Treat this as a soft figure. It is a percentage of an estimate whose own
confidence the cost note calls low until the four-hook native proof and the
control-plane P1 pass, and the per-item splits are judgement rather than
measurement. The number to revisit after P1 is the 70% on the mark-store row;
it carries the most uncertainty and the most weight.

Also treat it as a weak argument. A high reuse score partly reflects how much
of the LSM-only stage is groundwork for this one rather than shipped
capability; the BPF first stage scores lower precisely because it ships a
standalone backend. See
[Reuse is the wrong metric](update-option-bpf-dkms-technical.md#reuse-is-the-wrong-metric),
which also gives the better measure — total route cost against building this
backend directly.

## Rejected mechanisms

Recorded so they are not re-proposed a third time.

| Mechanism | Why rejected |
| --- | --- |
| Wait at the stock `security_path_*` hook, TOMOYO-style | Holds the parent `i_rwsem`, the mount-write reference, and for cross-directory rename the per-superblock `s_vfs_rename_mutex`. TOMOYO survives this only via a 10-second cap, which the untimed-prompt requirement removes. |
| VFS sends structural decisions directly to Filemaster; the LSM is retired | Defeats both stated reasons for choosing this route: it discards the phase-one LSM work and it puts Filemaster's prompt machinery directly into custom VFS code, so the hard lock-free wait and revalidation work remains custom VFS work anyway. |
| New pre-lock, data-only hook receiving a copied candidate context | The final component cannot be resolved without the parent lock, so a hook placed before that lock cannot see the target at all — no inode, no type, no owner. The prompt could not say what was being deleted, and the promised proof that a "fresh lookup confirms the same parent/name/object relationship" is unachievable for an object identity never captured. It also required a new hook family and pushed Filemaster revalidation semantics into VFS. |
| Unwind to the inner `retry_deleg:` label and wait there | That label sits after `mnt_want_write()`. The mount-write reference would be held for the life of the prompt, blocking `remount,ro` and `fsfreeze`. The outer retry point avoids this at no cost. |
| Sentinel plus `task_work_add()` and `-ERESTARTNOINTR`, restarting at the syscall boundary | Needs no VFS change at all, but depends on entry-code ordering between `arch_do_signal_or_restart()` and `resume_user_mode_work()`, is architecture-specific, and re-reads the pathname from userspace, creating a fresh TOCTOU the in-function retry avoids. |
| LSM holds a compiled policy snapshot and resolves Allow/Deny in-kernel | Duplicates the rule engine one level down. Superseded by the fanotify-shaped model; scope marks, and later a verdict cache, cover the performance concern without a second matcher. |

## Comparison with a DKMS-only direct backend

Compared with a direct Filemaster patch in VFS, this design places every
Filemaster-specific concern — request, wait, verdict cache, response — in
`security/filemaster/`. The VFS change is a sentinel check, a generic security
call, and a `goto retry`, in the idiom the same functions already use for
`retry_estale`.

That is a materially smaller and more reviewable kernel surface than either the
DKMS-only design or the rejected pre-lock-hook design, which is the point of
the route: fewer custom kernel lines is directly fewer lines in which a
mistake can corrupt a filesystem.

It does not eliminate the shared risk entirely. Restarting an operation after
releasing everything must not change observable semantics, the verdict key must
be strong enough that a stale approval cannot authorize a different object, and
the stacking interaction above is unproven. But the residual is bounded by the
fact that pass two is an ordinary VFS pass rather than a hand-written
reconstruction of one.

With livepatch delivery this design also fits better than its predecessors:
livepatch redirects whole functions at entry, and here the unit of change *is*
a small number of self-contained functions.

## P1 gates and delivery boundary

The first implementation is not a broad feature claim. It must prove one
operation at a time in a disposable VM, beginning with `unlink`/`rmdir` and
then `rename`:

1. Build and boot the exact kernel with the Filemaster LSM configured, ordered
   last, and visible in `/sys/kernel/security/lsm`. **Lead with `rmdir`**: its
   existing delegation wait already sits at the target wait point, so it is the
   smallest and least speculative first change. Take `unlink`, `rename`, and
   `link` after it, in that order of increasing restructure.
2. Add the sentinel and the retry hook for one operation. Show by inspection
   and by instrumentation that nothing acquired by pass one is held at the wait,
   and that concurrent unrelated filesystem work — including `fsfreeze` and
   cross-directory renames on the same superblock — proceeds during a prompt.
3. Prove the sentinel can never be returned to userspace on any path.
4. Exercise Allow, Deny, task kill, daemon loss, queue exhaustion,
   stale/replaced name, mount change, daemon restart mid-wait, scope-mark
   changes mid-wait, and Filemaster self-access.
5. Prove the one-ask-retry bound holds and cannot livelock.
6. Prove exactly one Filemaster decision per syscall, that ordinary later LSM
   checks still run on pass two, and measure the audit/AVC duplication from
   stacking against a real SELinux or AppArmor configuration.
7. Measure the cost of the doubled resolution under `rm -rf` and a large `git
   checkout`, with and without scope marks.
8. Prove the caller-identity cases: an `io_uring` `UNLINKAT`/`RENAMEAT` names
   the submitting process and not a worker, kernel threads raise no prompt, and
   a single delete on an overlayfs mount produces exactly one prompt.
9. Only advertise that operation after stress and adversarial VM tests pass;
   repeat the proof independently for every additional operation family.

Direct custom-kernel compilation is the reference delivery for P1. A livepatch
path is a separate compatibility proof, not a shortcut around the source-level
VFS audit. This narrows, for P1 only, the delivery question the
[overview](update-option-+dkms.md) leaves open.

## Source basis

Read against mainline `fs/namei.c`, `security/security.c`,
`security/tomoyo/`, and `include/linux/lsm_hook_defs.h` at the time of writing:

1. [Linux Security Module usage](https://docs.kernel.org/admin-guide/LSM/index.html)
   documents that LSMs are build/boot-selected kernel extensions rather than
   ordinary loadable modules.
2. `filename_unlinkat()` and `filename_renameat2()` in `fs/namei.c` each take
   the mount-write reference and the operation locks before their
   `security_path_*` hook, and each already contain a full-unwind retry point
   used by `retry_estale`. `lock_rename()` takes `s_vfs_rename_mutex` whenever
   the two parents differ.
3. `tomoyo_supervisor()` in `security/tomoyo/common.c` demonstrates an
   LSM-owned userspace query and wait, bounded at ten one-second iterations.
   `TOMOYO_RETRY_REQUEST` retries only TOMOYO's own check.
4. `__CALL_STATIC_INT` in `security/security.c` short-circuits the LSM chain on
   the first non-default return.
5. `path_*` hooks are gated on `CONFIG_SECURITY_PATH` in
   `include/linux/lsm_hook_defs.h`; `inode_*` hooks are not.
6. [fanotify permission-event documentation](https://man7.org/linux/man-pages/man7/fanotify.7.html)
   describes the request/response and marking model this design follows.
7. [Kernel livepatch documentation](https://docs.kernel.org/livepatch/livepatch.html)
   explains its function-entry redirection model and why livepatch suitability
   must be checked per target function.
