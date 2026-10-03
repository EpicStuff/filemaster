# Fanotify extension in a custom kernel — technical note

> **Status: Gate 1 completed — negative as a small fanotify-reuse proposition.**
> **Verified from source** against Linux v7.1: fanotify has an untimed,
> killable wait primitive, but its existing teardown semantics are fail-open and
> a blocking permission group cannot request the identity/context carried by
> FID notification events. Per the P0 feasibility boundary, this note stops
> before costing.

> **This is not a recommendation or a full impossibility proof.** **Judged:**
> a substantially larger custom fanotify design could change these behaviours.
> It would no longer be justified as merely reusing the existing permission
> transport, queue, and event format. No production-line, test-line, session,
> or token estimates are made in this revision.

## Evidence convention and audited source

- **Verified from source** means read in the stated kernel tree.
- **Verified by running it** means observed in P1's custom-kernel VM experiment.
- **Believed** marks a direct inference rather than an observed lifecycle.
- **Judged** is an engineering assessment, not a measurement.

**Verified from source.** The audit used the Linux v7.1 tag
(commit b3f94b2b3f3e51ab880a51fc6510e1dafba654ed) in the P1 source tree. The
P1 worktree head was 8cd9520d35a6c38db6567e97dd93b1f11f185dc6; its diff from
v7.1 does not change the fanotify or fsnotify files cited below. Line numbers
therefore describe the kernel that P1 built, with the same fanotify source as
the v7.1 tag.

## Candidate boundary

**Verified by running it — P1.** This candidate does not remove the VFS
unwind-and-retry mechanism. For rmdir, P1 observed the same fs/namei.c
post-unwind retry shape at +16/-1 lines; the stipulated four-operation
extrapolation remains outside this feasibility note. Only the service called at
the fully released point would change.

**Verified from source.** The candidate assessed here is a custom-kernel
extension that makes unlink, rmdir, rename, and link prompt through fanotify
permission events. It is not the DKMS-only runtime-hook proposal on an
unmodified distro kernel.

## Gate 1.1 — wait and receiver lifecycle

### Does fanotify_get_response() provide an untimed, killable wait?

**Verified from source — yes, as a primitive.**
fs/notify/fanotify/fanotify.c:217–290 waits with
"wait_event_state(..., TASK_KILLABLE | TASK_FREEZABLE)" for an event to become
answered. That call has no timeout. Its signal-interruption path returns
-ERESTARTSYS. The fanotify permission watchdog has a default of zero and only
warns when configured; it does not choose an answer or end the wait
(fanotify_user.c:50–52 and 111–164).

### What happens to a pending permission event on daemon death, fd close, or group destruction?

**Verified from source — final fanotify-FD close is fail-open.**
fanotify_release() stops queueing, drains both pending permission-event lists,
answers each with "finish_permission_event(..., FAN_ALLOW, NULL)", wakes the
access wait queue, and only then destroys the fsnotify group
(fs/notify/fanotify/fanotify_user.c:1098–1151). Thus the final close releases
parked access tasks by allowing the original operation, rather than failing it.

**Believed (direct control-flow inference from source).** Daemon death has that
same result only when it closes the final file-descriptor reference. An
inherited or duplicated descriptor keeps the group alive; the existing
untimed wait then remains pending until it is answered, interrupted, or its
group is released.

**Verified from source — direct group destruction is not an independent
verdict path.** fsnotify_destroy_group() stops queueing and waits for active
user waits to drain; it does not itself answer and wake a parked permission
event (fs/notify/group.c:50–93). The normal fanotify release path supplies the
FAN_ALLOW answers before it invokes group destruction.

**Verified from source — there is a second fail-open path.**
fanotify_handle_event() returns success when fsnotify_prepare_user_wait() loses
a race with mark deletion; its source comment says to let the operation pass
(fs/notify/fanotify/fanotify.c:969–1010).

**Gate answer.** **Judged:** the existing wait is useful reuse, but current
lifecycle semantics do not satisfy the required fail-closed receiver-loss
behaviour. A structural extension would need a distinct fail-closed teardown
and mark-removal policy while leaving the established Open/Execute fanotify
behaviour unchanged.

## Gate 1.2 — decision context and permission-event shape

### Can a blocking permission event carry the needed structural context?

**Verified from source — no, not as-is.** The current permission event is a
single held path plus optional pre-content position/count, response state, and
returned event fd. It has no parent/name records, file handles, second path,
mount identifier, or two-sided rename payload
(fs/notify/fanotify/fanotify.h:438–452 and
fs/notify/fanotify/fanotify.c:584–611).

| Decision information | Current blocking permission event | Existing fanotify precedent | Required change |
|---|---|---|---|
| Parent/name and object identity for unlink or rmdir | **Verified from source:** no FID or DFID_NAME payload. | **Verified from source:** FID notification events can emit DFID_NAME. | **Judged:** add a structural-permission event type and serialization. |
| Old and new rename endpoints | **Verified from source:** no second parent/name/path. | **Verified from source:** FAN_RENAME notification emits OLD_DFID_NAME and NEW_DFID_NAME records. | **Judged:** retain both endpoints in a blocking event and define mark matching. |
| Target identity | **Verified from source:** no target FID. | **Verified from source:** FAN_REPORT_DFID_NAME_TARGET describes the moved/source child, not an overwritten destination inode. | **Judged:** add an explicit destination-target identity record when policy needs it. |
| Mount context | **Verified from source:** a permission event exposes no mount-id record. | **Verified from source:** FAN_REPORT_MNT is notification-only. | **Judged:** define one or two mount-id records and their lifetime. |
| Byte ranges | **Verified from source:** position/count is emitted only for FAN_PRE_ACCESS pre-content events. | **Verified from source:** FAN_EVENT_INFO_TYPE_RANGE exists. | **Judged:** structural operations should explicitly declare ranges absent/not applicable; no current structural permission range exists. |
| Response correlation | **Verified from source:** response lookup is only by the returned event fd. | **Verified from source:** existing permission reads create and save that fd. | **Judged:** define a valid response handle or correlation ID for each structural event. |

### Why FAN_RENAME does not solve the blocking case

**Verified from source.** FAN_RENAME is a notification encoding, not a
permission event. In FID mode, fanotify_alloc_event() creates the old/new
records and copy_info_records_to_user() serializes them as OLD_DFID_NAME and
NEW_DFID_NAME (fs/notify/fanotify/fanotify.c:745–879;
fs/notify/fanotify/fanotify_user.c:690–739; and
include/uapi/linux/fanotify.h:155–159).

**Verified from source — hard interface conflict.** fanotify_init() rejects
any FID-reporting mode unless the group is FAN_CLASS_NOTIF
(fanotify_user.c:1659–1660). FAN_REPORT_MNT is also restricted to that
notification class and cannot be combined with the FID report bits
(fanotify_user.c:1639–1644). Permission masks are conversely rejected for a
notification group (fanotify_user.c:1985–1990). The current UAPI therefore
does not permit a group that is both blocking and DFID_NAME/TARGET/MNT-rich.
(Line references corrected 2026-08-30 against `v7.1` at
`/root/vm/share/lsm-p1/source/linux-v7.1`; the earlier citations were 1–2 lines
adrift. Every underlying claim was confirmed.)

**Verified from source.** The current permission-mask family covers
Open/Access/Exec and pre-access events, not unlink, rmdir, rename, or link
(include/linux/fanotify.h:82–103). Existing fsnotify move input reaches
fanotify with both directory sides, but the permission allocator discards that
shape in favour of its one-path permission event. This is not a flag addition
to the existing event format.

### Cross-pass verdict state remains separate

**Verified by running it — P1.** The VFS retry must consume exactly one stored
Allow/Deny decision after the full unwind. **Verified from source:** a normal
fanotify response only wakes and completes the current permission event; it
does not supply per-task retry state. A structural fanotify design still needs
the stipulated cross-pass verdict carry and its lifecycle.

## Prior art — a substantive prototype exists, with a security-model mismatch

> **Correction (2026-08-27).** An earlier revision of this section said the prior
> art "stops before the hard part" and that there was "no fork to adopt". The
> first claim was **wrong** and the second was misleadingly framed. The branch
> was subsequently fetched and read. Findings below are **verified from source**
> in that branch unless marked otherwise.

### What is merged (unchanged)

**Verified from source (v7.1 tree P1 built).** No structural permission event is
merged. `FAN_DELETE_PERM`, `FAN_RENAME_PERM` and `fsnotify_pre_modify` appear
nowhere in `include/` or `fs/`. `FAN_PRE_ACCESS 0x00100000` is present; there is
no `FAN_PRE_MODIFY`. The UAPI carries
`/* #define FAN_DIR_MODIFY 0x00080000 */ /* Deprecated (reserved) */`
(`include/uapi/linux/fanotify.h:28`). Gates 1.1 and 1.2 above describe merged
v7.1 accurately and are not retracted.

### The unmerged prototype

**Verified from source.** `github.com/amir73il/linux`, branch
`fan_pre_modify-wip` (tip `4a8b6401`), 24 patches on a v6.5-rc1 base, authored
2023. Load-bearing commits:

| Commit | Subject |
|---|---|
| `18f55ff` | `fanotify: introduce class FAN_CLASS_VFS_FILTER` |
| `a1c9f39` | `fanotify: allow permission events with FAN_CLASS_VFS_FILTER` |
| `b31ab27` | `vfs: implement 'vfs write barriers'` |
| `29c60e4` | `fanotify: introduce directory entry pre-modify permission events` |
| `4a8b640` | `nfsd: generate pre-modify path permission events` |

**Verified from source — it removes the Gate 1.2 class conflict by design.**
`FAN_CLASS_VFS_FILTER` exists specifically to deliver permission events
"without any vfs locks", and `a1c9f39` adds a `FAN_PRE_VFS` mark flag that tells
the listener an event arrived without `sb_start_write()` held. This is a
prototype of exactly the new class Gate 1.2 concluded would have to be designed.

**Verified from source — the ask is genuinely pre-lock, on every path.**
`29c60e4` adds `mnt_want_write_parent{,s}()` wrappers. Post-patch `fs/namei.c`
ordering, at the stated line numbers:

| Operation | Ask | Lock | Target lookup |
|---|---|---|---|
| create | 3946 | 3953 | 3954 |
| rmdir | 4332 | 4336 | 4337 |
| unlink | 4465 | 4469 | 4470 |
| rename | 5035 (both parents) | — | 5043 / 5052 |

Diffstat for `29c60e4`: `fs/namei.c` +78/−24-ish within 200 insertions total
across 8 files, including `fs/namespace.c` +81.

### Why it does not satisfy Filemaster as written

**Verified from source — the decision has no target identity.** The hook is
`fsnotify_name_perm(path, name, mask)`, passing `d_inode(path->dentry)` — the
**parent** — plus a `qstr` name. The event fires before `lookup_one_qstr_excl()`,
so the target inode is not a decision input. The name is bound to an inode after
the answer, under the lock.

**Verified from source — the SRCU mechanism is not a TOCTOU defence.** `b31ab27`
states `sb_write_barrier()` calls `synchronize_srcu()` to wait for opted-in
writers, and "never blocks new writers from starting write". It is a quiescence
barrier for the listener, not exclusion. It cannot prevent a concurrent rename
re-pointing the name between the answer and the lookup.

**Judged — concrete failure.** A second thread renames a valuable file onto the
approved name after Allow and before the lock; the operation consumes the
authorization against a different inode. P1 closes this by construction and
**measured** a raced replacement failing closed. That property is given up here.

**Verified from source — two further deliberate holes.** `29c60e4` states events
are not generated for operations relative to an `O_PATH` dfd received inside a
lookup permission event (a recursion escape that doubles as a bypass primitive);
that overlayfs upper-layer modifications generate no events; and that the hooks
"do not cover all the possible ways that users can make directory entry
modifications".

**Verified from source — rename is two decisions.** `fsnotify_rename_perm()`
raises `FS_PRE_MOVE_FROM` then, only if that returns 0, `FS_PRE_MOVE_TO`, joined
by a `fsnotify_get_cookie()`. Two blocking round-trips per move, requiring
daemon-side correlation, not one two-sided decision.

**Judged.** None of this is defective. The stated consumers are HSM and "a
persistent change tracking service" — cooperative, not adversarial. The design is
correct for that and mismatched to an enforcement boundary.

### The separable idea

**Judged.** Pre-lock placement is **not** fanotify-specific.
`mnt_want_write_parent()` is a VFS restructuring; what it calls is arbitrary.
Filemaster could place its own ask hook there and keep the native LSM. So this
is an axis orthogonal to the endpoint choice:

| | post-unwind ask (P1) | pre-lock ask (`fan_pre_modify-wip`) |
|---|---|---|
| Kernel diff | 16 lines/op in `namei.c` (**measured**) | ~160 lines `namei.c` + `namespace.c`, plus SRCU infra |
| Module machinery | sentinel, cross-pass verdict, retry plumbing | none of it |
| TOCTOU | closed by construction, **measured** | open by construction |
| Rename | one decision | two events + cookie |
| Status | proven on 7.1 by P1 | prototype, v6.5-rc1, 2023, unmaintained |

**Judged, untested.** A third design follows: ask pre-lock, then verify target
identity under the lock and fail closed on mismatch. It would take the cheap
path in the common case with a safe fallback. Both halves now have code behind
them. This has not been designed or costed.

### Effect on the cost case — REOPENED (2026-08-27, second revision)

> **Correction.** The previous revision closed this option with: "the daemon
> protocol and the module wait/queue are unchanged either way." That holds for
> adopting pre-lock placement **into the LSM design**. It is **false for the
> fanotify endpoint**, where fanotify supplies the transport. The wrong
> proposition was evaluated. The option is reopened as a costed candidate.

**Derived** from the row breakdown of the 1,760–2,830 line native module in
[LSM module sizing](lsm-module-sizing-technical.md):

| Module row | Lines | Supplied by a fanotify endpoint? |
|---|---|---|
| Per-task verdict cache, `lbs_task` lifecycle | 170–270 | No |
| Daemon transport, queue, correlation, authenticated receiver, reply validation, killable wait | 380–600 | **Yes** |
| Identity payload and pass-two revalidation | 220–340 | No — and the prototype specifically lacks it |
| Scope marks and publication lifetime | 420–680 | **Largely** — sizing calls these "an event-origin filter, never a kernel policy matcher", which is what fanotify marks are |
| Fail-closed, cancellation, recursion, classification, diagnostics | 230–380 | Partly, and inverted — fanotify is fail-open |

**Judged.** Transport plus most of marks is ~600–1,050 of 1,760–2,830, i.e.
**34–37% mid-range**. An independently offered 25–40% band is consistent with
this breakdown and is not dismissed.

**Verified — what does not come free.** Fail-closed teardown
(`fanotify_release()` drains with `FAN_ALLOW`); revalidation against the
raced-replacement attack (decision on *(parent, name)* before
`lookup_one_qstr_excl()`; the SRCU barrier is quiescence, not exclusion);
rename as two cookie-joined events rather than one decision; overlayfs
upper-layer uncovered; the 500–850 daemon lines unchanged.

**Judged — additional costs specific to this endpoint.** Regression risk to the
shipping Open/Execute fanotify path, and a 24-patch rebase from v6.5-rc1 to
`v7.1` plus ongoing per-release rebase of a larger surface than the LSM route's
measured ~16 lines per operation.

**Scope warning.** The `+DKMS` rows at ~3,800–6,300 production lines cover more
than the four structural operations. They cannot be compared directly against
the four-operation LSM sizing without mixing scopes.

**A number is now entered (2026-08-30), by owner decision.** This section's
refusal was overruled on the grounds that every figure in the cost model is an
estimate. The full row-by-row derivation is
[Fanotify extension — estimate entered](update-options-cost-technical.md#fanotify-extension-in-a-custom-kernel--estimate-entered-2026-08-30):
**~2,100–3,700 production lines, ~225–380M tokens, 15–26 sessions**.

**Derived — the headline correction.** The 34–37% saving above is on the module
body only, and the module is ~2,830 of candidate A's 4,275 high-end production
lines. Re-costing all four components puts the whole-option line saving at
**~15%**, and a 20–25% difficulty premium — patch rebase across five releases,
regression re-verification of the shipping Open path, and an unsolved
revalidation design — brings the token band to **225–380M against candidate A's
234–350M**. On cost the two routes are a tie; the discriminators are P0 Gate 3's
dimensions, not these numbers.

A port of the delete/rename patch to `v7.1` and a recount — the P1 method —
still supersedes the estimate.

> **Port base corrected (2026-08-30).** This document costed against
> `fan_pre_modify-wip` (2023, v6.4). A branch survey found **`fan_pre_dir_access`
> (2025-07-08, v6.16-rc5)**, which contains a variable-length permission event
> carrying fid + name and lifts the class restriction — i.e. the Gate 1 item 1
> blocker, already implemented, ~127 lines, two years newer. Gate 1's verified
> facts about mainline `v7.1` are unaffected; its inference that the event type
> "would have to be designed" is not. See
> [cost technical — port base](update-options-cost-technical.md#port-base--there-is-a-much-newer-branch-and-it-is-not-the-one-we-read-2026-08-30).

## Response correlation, one-decision rename, and fail-closed — read from source (2026-08-30)

All citations at `6ccca12ea`, the tip of `fan_pre_dir_access` (base
`d7b8f8e2 Linux 6.16-rc5`). **Mainline `v7.1` is a different tree and its line
numbers differ** — where a claim needs to hold for `v7.1`, that is said.

### Q1 — how a fid+name permission event is answered. **Not a blocker.**

**Verified from source.** The branch did not replace the response key. It kept
the fd, because a pre-dir-content event always has a parent-directory path to
open.

- `905163ce4` moved the shared `struct fanotify_event fae` to the **end** of
  `struct fanotify_perm_event` so a variable-length `fanotify_name_event` can be
  suffixed onto it in one allocation. `struct path path` and
  `int fd` survive unchanged (`fanotify.h:441-458`), and `FANOTIFY_PERM()` is
  still a plain `container_of` (`fanotify.h:460-464`).
- `fanotify_alloc_event()` routes a perm event with name info through
  `fanotify_alloc_name_event(..., perm=true)` and then
  `fanotify_init_perm_event()` (`fanotify.c:873-879`), which does
  `pevent->path = *path; path_get(path)` (`fanotify.c:585-600`).
- Because the path is non-NULL, `copy_event_to_user()` runs `create_fd()`
  (`fanotify_user.c:774-776`) and records the key:
  `FANOTIFY_PERM(event)->fd = fd` (`:861-862`).
- `process_access_response()` reads `response_struct->fd` off the wire (`:333`),
  rejects `fd < 0` (`:394`), linear-scans `access_list` for `event->fd == fd`
  (`:397-401`), then `finish_permission_event()` and wakes
  `access_waitq` (`:403-405`), releasing `fanotify_get_response()`'s
  `wait_event_state(..., TASK_KILLABLE|TASK_FREEZABLE)` (`fanotify.c:232-234`).

There is **no cookie, event id or sequence number** in the response path.
Uniqueness holds because each event takes a fresh `get_unused_fd_flags()`.

**Judged — this transfers.** `create`, `unlink`, `rmdir` and `rename` all have a
parent-directory path available at the decision point, so the fd key works for
Filemaster's operations too. **No new correlation mechanism has to be designed.**

**Verified — an unexpected positive.** The no-fd case is already *fail-closed*:
`fanotify_read()` denies a perm event outright if `copy_event_to_user()` fails or
no fd could be created (`fanotify_user.c:947-951`).

### Q2 — rename as one decision. **The wound.**

**Verified — the container can hold two name records.**
`fanotify_alloc_name_event()` takes `moved` and `perm` as independent parameters
(`fanotify.c:644-650`); with `moved` set it derives `dir2`/`name2` and sizes the
allocation for both (`:656-670, 702-719`), and the `perm` prefix is added on top
of that same allocation (`:673-677`). Serialization is generic over event type —
`copy_info_records_to_user()` emits the second record whenever
`fanotify_event_has_dir2_fh(event)` and does **not** check the type
(`fanotify_user.c:634-647`). So one permission event carrying `OLD_DFID_NAME` +
`NEW_DFID_NAME`, answered by one fd-keyed response, is structurally
representable.

**Verified — nothing constructs one.** `moved` is only ever set under
`mask & FAN_RENAME` (`fanotify.c:833-856`); `FAN_RENAME` is not in
`FANOTIFY_PERM_EVENTS` (`include/linux/fanotify.h:93-106`); and a
`FAN_CLASS_PRE_CONTENT_FID` group rejects any mask outside
`FANOTIFY_PRE_CONTENT_EVENTS` (`fanotify_user.c:1952-1955`). The `OLD_DFID_NAME`
label is hard-gated on `event->mask & FAN_RENAME` (`:616-618`).

**Verified — the prior art deliberately chose two events.** On
`fan_pre_modify-wip`, commit `29c60e4db` adds `fsnotify_rename_perm()` in
`include/linux/fsnotify.h`, called from `mnt_want_write_parents()`:

```c
u32 cookie = fsnotify_get_cookie();
ret = fsnotify_name(FS_PRE_MOVE_FROM | FS_PRE_VFS, old_path, ..., old_name, cookie);
if (ret)
        return ret;
return fsnotify_name(FS_PRE_MOVE_TO | FS_PRE_VFS, new_path, ..., new_name, cookie);
```

Two sequential blocking permission events joined only by a cookie; the
destination is asked only if the source was allowed.

**Judged.** One-decision rename needs a new `FAN_PRE_RENAME`-class bit in
`FANOTIFY_PERM_EVENTS`, a new VFS hook passing both `(dir, name)` pairs into one
`fsnotify()` call, relabelling in `copy_info_records_to_user()`, and a decision
about which of the two directories the single held `path`/fd refers to. The
container supports it; **the upstream author's own design does not use it that
way**, so Filemaster would be designing against prior art rather than porting it.

**Open product question.** Whether Filemaster *requires* one decision for a
rename, or can accept two cookie-joined prompts, is a
[backend features](backend-features.md) question, not a kernel one. It belongs
to the Gate 1 item 3 sweep.

### Q3 — fail-closed. Cheaper than assumed, and there is a **third** fail-open site.

**Verified — the branch changes neither known site.** `-S` pickaxe over
`d7b8f8e20..6ccca12ea` for `finish_permission_event(group, event, FAN_ALLOW, NULL)`
and for `fsnotify_prepare_user_wait` both return empty. Both fail-open paths are
therefore as recorded for mainline.

**Verified at `6ccca12ea` — a third fail-open path not previously recorded.** On
notification-queue overflow, `fsnotify_insert_event()` returns 2
(`fs/notify/notification.c:100-108`) and `fanotify_handle_event()` does
`WARN_ON(...); fsnotify_destroy_event(...); ret = 0;` (`fanotify.c:1031-1037`) —
a **silently allowed permission event**. Bounded by
`group->max_events = fanotify_max_queued_events`, or `UINT_MAX` when
`FAN_UNLIMITED_QUEUE` (CAP_SYS_ADMIN) is set (`fanotify_user.c:1664-1669`).

> **Unconfirmed for `v7.1`.** This was read at v6.16-rc5. The overflow logic is
> old and the branch does not touch it, but the `v7.1` line numbers and exact
> text have **not** been checked. Confirm before relying on it.

**Verified — already fail-closed:** `-ENOMEM` on event allocation propagates as
an error rather than an allow (`fanotify.c:1017-1026`); a perm event that cannot
be copied or given an fd is denied (`fanotify_user.c:947-951`); signal-interrupted
waits return `-ERESTARTSYS` (`fanotify.c:236-258`).

**Judged — the variable-length event type is neutral.** All three fail-open
sites key on `fanotify_is_perm_event(event->mask)` / `FANOTIFY_PERM()`, which
work identically for `FID_NAME_PERM` because `fae` is shared and
`FANOTIFY_PERM()` is a plain `container_of`. Flipping `FAN_ALLOW`→`FAN_DENY` in
`fanotify_release()` and `return 0`→`return -EPERM` in the mark-deletion race is
the same small change regardless of event type; variable-length allocation adds
no new silent-drop path.

### The `FAN_PRE_DIR_ACCESS` hook is not usable as a gate

**Verified.** `fsnotify_lookup_perm()` produces no event when the superblock
lacks `SB_I_ALLOW_HSM`, when `dentry->d_flags & DCACHE_HSM_ONCE`, or — decisively
— because it is only reached from `walk_component()` on a **dcache miss**:
`if (unlikely(!dentry)) dentry = lookup_slow_notify(nd);` (commit `53bdc3667`,
`fs/namei.c`). A cached dentry produces nothing. This is a cache-population hook
and **cannot be made fail-closed**, because on the fast path it never fires.

This confirms rather than contradicts the split recorded above: take the
**event plumbing** from this branch, never the **hook placement**.

### Latent defect to fix on port

**Verified.** `fanotify_should_merge()` has no `case
FANOTIFY_EVENT_TYPE_FID_NAME_PERM` and would fall through to
`default: WARN_ON_ONCE(1)` (`fanotify.c:156-176`). Harmless at the tip only
because `fanotify_merge()` returns 0 for perm events first (`:198-199`).

### Effect on the estimate

**Judged — the band stands; the risk profile improves.** Q1 removes an
unpriced design risk. Q3 makes fail-closed smaller than the
"Fail-closed, cancellation, recursion, classification, diagnostics" row assumed,
but adds a third site to cover. Q2 confirms a cost the estimate already carried
(rename as two cookie-joined events). Net: **~2,100–3,700 lines / ~225–380M
stands, and should be read toward its low end** — but only if Filemaster can
accept two-event rename. If it requires one decision, that row grows and the
work diverges from prior art.

## Gate conclusion and stop point

> **Superseded in part.** This records the Gate 1 source findings, which stand.
> Its cost judgement — that the option could not be costed — was made before the
> `fan_pre_modify-wip` prototype was read and before the module row breakdown was
> checked. See [Effect on the cost case — REOPENED](#effect-on-the-cost-case--reopened-2026-08-27-second-revision).


**Gate 1 result: negative for the claimed reuse.**

1. **Verified from source:** fanotify_get_response() supplies an untimed,
   killable/freezable wait, but final descriptor close and a mark-deletion race
   currently allow the operation. It is not a ready fail-closed receiver-loss
   mechanism.
2. **Verified from source:** blocking permission events cannot carry the
   required DFID_NAME, two-sided rename, target, or mount context. Existing
   FAN_RENAME proves that some notification serialization exists, but the UAPI
   expressly prevents combining it with a permission group.

**Judged:** the remaining genuine reuse is the wait primitive and portions of
the queue/response machinery. The candidate would first need new structural
permission masks, a combined event model, response correlation, mark rules,
fail-closed teardown, and retry-state integration. That is enough unverified
shared-subsystem work that the purported kernel-side saving cannot responsibly
be costed as a small fanotify extension. This does not choose an architecture;
it records why the feasibility gate did not pass. Per instruction, no costing
or later P0 gates were attempted.
