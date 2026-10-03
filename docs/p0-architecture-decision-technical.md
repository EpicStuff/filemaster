# P0 — feasibility and cost inputs: direct fanotify vs LSM

> **Status: scope definition, not findings.** This defines the evaluation that
> feeds the backend architecture choice. It does not make that choice — the
> project owner does, using these figures.

## Purpose

Establish **feasibility and cost inputs** for two custom-kernel architectures
for interactive structural decisions. **The architecture choice is the project
owner's and is made outside this evaluation.** Report evidence and figures; do
not recommend a route.

The two architectures:

- **Direct fanotify** — extend fanotify so structural operations raise
  permission events. See
  [Fanotify extension in a custom kernel](update-option-fanotify-extension-technical.md).
- **LSM** — a Filemaster LSM at a new post-unwind hook. See
  [LSM + DKMS](update-option-lsm-dkms-technical.md).

Report on **crash/corruption/silent-failure risk, implementation and debugging
difficulty, testing burden, and future rebase cost**. At the feasibility stage
these matter more than lines of code, so lead with them — but the owner needs
cost to decide, so give line and token figures for both architectures once
feasibility is settled, using the methodology in
[cost technical](update-options-cost-technical.md).

## Working rules

- **Do not trust the technical docs in this folder.** They are AI-generated and
  unreviewed, and P1 already found drifted line references. Verify against the
  exact kernel source that will be built, and name the version.
- Label every claim **verified from source**, **verified by running it**, or
  **believed**.
- A clear negative is a successful result.

## Already established by P1 — do not redo

[P1 `rmdir` unwind-and-retry proof](p1-rmdir-technical.md) built and booted a
custom `v7.1` and demonstrated, for `rmdir`:

- Sentinel → full VFS unwind → wait with nothing held → `goto retry` → ordinary
  second pass. Allow completed the operation; Deny returned `EACCES`.
- Lock freedom is real: a same-superblock cross-directory `rename` and an
  `fsfreeze` both completed while a prompt was parked.
- A raced replacement (target renamed away, replacement created at the same
  name, then Allow) **failed closed**, with exactly one decision raised.
- Second-pass semantics are ordinary VFS: Allow on a nonempty directory returned
  `ENOTEMPTY`.
- Measured: `fs/namei.c` +16/−1, generic hook plumbing +38.

Treat unwind-and-retry as **proven for `rmdir`** and use it as the assumed
mechanism for both architectures. What remains open is whether it generalises to
the richer operations, and what each architecture would cost to own it.

## Already established by the Gate 1 fanotify check — do not redo

[Fanotify extension in a custom kernel](update-option-fanotify-extension-technical.md)
answered Gate 1 items 1 and 2 against Linux `v7.1` and stopped there, as
instructed. The result was **negative for the fanotify architecture as a small
reuse proposition**: the wait primitive is reusable, the teardown semantics and
the event format are not. Nothing here rules out a substantially larger custom
fanotify fork; it rules out the cost argument the option was proposed on.

> **Updated 2026-08-30.** The direct-fanotify architecture *is* carried as a
> costed alternative after all. Reading `amir73il/linux:fan_pre_modify-wip`
> reopened it, and an estimate is now entered:
> **~2,100–3,700 production lines, ~225–380M tokens** — a tie with the LSM
> architecture's 2,655–4,275 / 234–350M. Working in
> [cost technical](update-options-cost-technical.md#fanotify-extension-in-a-custom-kernel--estimate-entered-2026-08-30).
> **Consequence for this document: Gate 3 is no longer optional.** Cost was
> expected to separate the two architectures and does not, so the comparison
> must be made on Gate 3's dimensions — blast radius, new kernel state, rebase
> burden, and regression risk to the shipping Open/Execute path.

## Gate 1 — kill criteria, do these first

Report on these before proceeding. Any one of them may settle feasibility on its own.

1. ~~**Can a blocking fanotify permission event carry what a decision needs?**~~
   **Answered 2026-08-27 — no.** Verified from source against `v7.1`: a blocking
   permission event carries one held path plus optional pre-content
   position/count, and `fanotify_init()` refuses FID/name reporting and
   `FAN_REPORT_MNT` outside `FAN_CLASS_NOTIF` while refusing permission masks
   inside it. `FAN_RENAME`'s `OLD_DFID_NAME`/`NEW_DFID_NAME` records exist but
   cannot be combined with a permission group. A new structural permission event
   type and serialization is required.
2. ~~**Does `fanotify_get_response()` provide an untimed, killable wait?**~~
   **Answered 2026-08-27 — yes as a primitive, no as a lifecycle.** Verified
   from source: `wait_event_state(..., TASK_KILLABLE | TASK_FREEZABLE)` with no
   timeout. But `fanotify_release()` drains both pending permission lists with
   `finish_permission_event(..., FAN_ALLOW, NULL)`, and
   `fanotify_handle_event()` returns success when
   `fsnotify_prepare_user_wait()` loses a mark-deletion race. Both are fail-open.
3. ~~**Is there any feature in [backend-features.md](backend-features.md) that one
   architecture fundamentally cannot satisfy?**~~ **Answered 2026-08-30 — no.**
   Neither architecture has a **Cannot** cell. The sweep found **twelve Expensive
   cells for B (fanotify)** and **three for A (LSM)**, and could not eliminate
   either route. Full table in
   [Gate 1 item 3 — the feature sweep](#gate-1-item-3--the-feature-sweep-2026-08-30)
   below.
4. **`O_RDWR` → read-only downgrade.** Analyse `f_mode`, `FMODE_WRITER`,
   write-access accounting, read accounting, and `O_TRUNC`. Determine whether an
   indefinite wait can occur under a parent lock on **every** open and create
   path. This is a potential kill criterion for both architectures and has not
   been analysed at all.

## Gate 1 item 3 — the feature sweep (2026-08-30)

**Verified against Linux `v7.1`** in the P1 source tree at
`/root/vm/share/lsm-p1/source/linux-v7.1` (git head `8cd9520d3`, tagged
`Linux 7.1`; `Makefile` VERSION 7 PATCHLEVEL 1 SUBLEVEL 0). Every `file:line`
below was read in that tree. Claims are labelled **verified from source**,
**verified by running it** (P1's booted custom kernel), or **judged**.

Verdict vocabulary, as commissioned: **Cannot** = architecturally impossible, or
possible only by abandoning that endpoint. **Expensive** = possible, materially
costlier than the other architecture. **Equal** = no meaningful difference.

One standing fact frames several rows: **filemaster's shipping scope mechanism
is `FAN_MARK_MOUNT`, one mark per protected mount**
(`service/fileaccess/mount_linux.go:532`), with subtree scoping done in the
daemon. Recursive-subtree watching is therefore not an open requirement for
either endpoint at *event-raising* time; it resurfaces only as a *suppression*
requirement (row 33).

### The table

| Feature | A (LSM) | B (fanotify) | Evidence |
|---|---|---|---|
| **Rule model** — ordered Read/Write/Execute lists, first applicable match, profile default | Equal | Equal | **Judged.** Entirely daemon-side; neither endpoint sees rules. |
| Delete evaluates target + containing folder; Create evaluates destination + parent | Equal | Equal | **Judged.** Daemon-side, given the context rows below. |
| **Rename/move as one decision** — source Delete *and* destination Create-or-Write, answered together | Equal | **Expensive** — fanotify's only two-sided shape is notification-only, and its structural prototype raises two cookie-joined events | **Verified from source.** `security_path_rename(old_dir, old_dentry, new_dir, new_dentry, flags)` is a *single* call carrying both parents as `struct path` (`include/linux/security.h:2110-2112`; call site `fs/namei.c:6192`). fanotify's `fsnotify_move()` issues three separate `fsnotify_name()` calls (`include/linux/fsnotify.h`), and `FAN_RENAME` requires `FAN_REPORT_NAME` (`fs/notify/fanotify/fanotify_user.c:2024-2025`), which requires `FAN_CLASS_NOTIF` (`:1659-1660`), while permission masks are refused in that class (`:1985-1990`). The `fan_pre_modify-wip` prototype raises `FS_PRE_MOVE_FROM` then `FS_PRE_MOVE_TO` joined by a cookie — *secondhand, not verified here* (no local clone; see "Could not verify"). |
| Unsupported operation fails closed | Equal | Equal | **Judged.** Daemon-side default. The endpoint half is row 29. |
| Hard-link / symlink policy | Equal | Equal | **Verified from source.** Both have a site: `security_path_link` / `security_path_symlink` (`include/linux/security.h:2108-2109`; `fs/namei.c:5691,5864`), and fanotify raises `FAN_CREATE` on the same operations. Both need a new blocking event regardless. |
| **Event records** — protected mount's stable ID and display path at decision time; deepest mount wins; explicit unknown | Equal | **Expensive** — fanotify's dirent events carry a directory *inode*, not a `struct path`, so mount marks are refused for exactly the events B needs | **Verified from source.** `fanotify_user.c:2013-2016` refuses any event outside `FANOTIFY_FD_EVENTS|FANOTIFY_MOUNT_EVENTS` on a `FAN_MARK_MOUNT` mark, with the in-tree comment *"they do not carry enough information (i.e. path) to be filtered by mount point"*. `fsnotify_move()` passes `FSNOTIFY_EVENT_INODE`/`FSNOTIFY_EVENT_DENTRY`, never a path. This collides directly with filemaster's shipping mount-mark scope (`mount_linux.go:532`). The `security_path_*` family takes `const struct path *dir` (`include/linux/security.h:2099-2112`), so the mount is present by construction under A. |
| **Freeze semantics** — untimed | Equal | Equal | **Verified from source.** `fanotify_get_response()` waits with `wait_event_state(..., TASK_KILLABLE|TASK_FREEZABLE)`, no timeout (`fs/notify/fanotify/fanotify.c:232-234`). v7.1's new permission watchdog only `pr_warn`s, never answers, and is off by default (`fanotify_user.c:53` — `static int perm_group_timeout` uninitialised; `:117-164`; early return at `:177-179`). **Verified by running it** for A (P1 parks on its own securityfs wait). |
| Freezes are killable | Equal | Equal | Same source lines: `TASK_KILLABLE`. |
| No locks held during a freeze | Equal | Equal | **Verified by running it** for A (P1: same-superblock cross-directory rename and `fsfreeze` both completed while a prompt was parked). **Judged** for B: the wait point is a `fs/namei.c` placement decision, not an endpoint property. |
| Re-validation; raced replacement fails closed | Equal | Equal | **Verified by running it** for A (P1: target renamed away, replacement created, Allow → failed closed, exactly one decision). **Judged** for B: unwind-and-retry is available to either endpoint. *Caveat:* the fanotify prototype the cost estimate was built on decides **pre-lock** on `(parent, name)` and is open to this race — but pre-lock vs post-unwind is a placement axis orthogonal to the endpoint choice. |
| **Event context** — operation, process, object, mount, path, second object | Equal | **Expensive** | See the rename and mount rows, plus Gate 1 item 1 above: today's blocking permission event carries one held path and optional pre-content position/count, with no name, fid, second object, or mount record. |
| Path is context, not identity | Equal | Equal | **Judged.** Both render the path in-kernel at hook time. |
| No separate event types for create-vs-replace | Equal | Equal | **Judged.** A userspace derivation in both. |
| **Existing Open/Execute behaviour preserved** | Equal | **Expensive** — B modifies the queue, class validation, mark validation and teardown that the shipping path runs on | **Judged**, from verified shared call sites: `fanotify_handle_event()` (`fanotify.c:930-1013`) and `fanotify_release()` (`fanotify_user.c:1098-1153`) serve `FAN_OPEN_PERM` and any new structural event alike. A adds a separate hook and transport and does not link into that code at all. |
| **Pre-delete**, files and directories | Equal | Equal | **Verified by running it** for A (`rmdir`, P1: sentinel → unwind → untimed killable wait → `goto retry` → ordinary second pass; Allow completed, Deny returned `EACCES`). For B the wait primitive is reusable; the event shape is not (rows above). |
| **Pre-link**, hard links and symlink creation | Equal | Equal | As the hard-link/symlink row. |
| **Pre-create** — parent + name, before the object exists | Equal | **Expensive** — a permission event with no fd is refused by construction today | **Verified from source.** An event that cannot report `event->fd` requires fid mode (`fanotify_user.c:2013-2016`); fid mode requires `FAN_CLASS_NOTIF` (`:1659-1660`); permission masks are refused in `FAN_CLASS_NOTIF` (`:1985-1990`). A serializes parent path + name with no equivalent rule. |
| **Pre-rename/move** with destination identity in the same event | Equal | **Expensive** | As the rename row. |
| Ask-that-cannot-be-prompted defaults to deny, with a user notification | Equal | Equal | **Judged.** Daemon-side. |
| Interactive prompts for structural operations, blocking no unrelated process | Equal | Equal | As the freeze rows. |
| **Open reports the application's requested access mode** | **Expensive** — A's endpoint does not cover Open, so A must extend fanotify anyway (surrendering its "does not touch the shipping path" property) or migrate Open onto the LSM | Equal | **Verified from source.** It is not reported today: `create_fd()` opens the event fd with `group->fanotify_data.f_flags` — the *group's* `event_f_flags` — not the application's, via `dentry_open_nonotify()` (`fs/notify/fanotify/fanotify_user.c`, `create_fd()`). Neither route gets this free; only B is already editing that file. |
| **Three-valued Open response** (Allow / Deny / Allow-read-only) | **Expensive** — same reason as the row above | Equal | **Verified from source.** The response word has free bits: `FAN_ALLOW 0x01`, `FAN_DENY 0x02`, `FAN_AUDIT 0x10`, `FAN_INFO 0x20`, errno in the top `FAN_ERRNO_BITS` (`include/uapi/linux/fanotify.h:246-256`), so `0x04`/`0x08` are available inside `FANOTIFY_RESPONSE_ACCESS` (validated at `fanotify_user.c:440-443`). |
| Allow-read-only cancels `O_TRUNC`; write-only downgrade is a deny; mmap covered by denying write at open | Equal | Equal | **Judged.** The hard half — `f_mode` / `FMODE_WRITER` / write-access accounting / `O_TRUNC` in `do_dentry_open()` — is identical for both and is **unanalysed**; it is Gate 1 item 4. |
| **Directory listing** — distinct from open, and **one decision per enumeration**, not per buffer-fill | Equal | **Expensive** — fanotify has no per-open-file-description state to hang the decision on | **Verified from source.** Both endpoints already have a per-`getdents` site: `security_file_permission(file, MAY_READ)` at `fs/readdir.c:95` and `fsnotify_file_perm(file, MAY_READ)` at `:99`. Collapsing that to one decision per description needs per-description state. An LSM has `file->f_security` (`include/linux/fs.h:1284`) sized by `lbs_file` (`include/linux/lsm_hooks.h:106`). fanotify's only per-description state is the two `FMODE_NONOTIFY*` bits (`include/linux/fs.h:175,181`), latched at open time by `fsnotify_open_perm_and_set_mode()` (`fs/notify/fsnotify.c:615-673`) — and an inode/mount ignore mask is per-object, so two applications listing the same directory would share one decision. |
| **Pre-truncate** (truncate and ftruncate) | Equal | Equal | **Verified from source**, small difference only: A can hang off existing blocking sites (`security_path_truncate`, `fs/open.c:116`; `security_file_truncate`, `fs/namei.c:4305`, `fs/open.c:185`); B must add call sites. **Judged** not material. |
| **Metadata-write events** — mode, owner, timestamps, xattrs | Equal | **Expensive** — four-plus new fsnotify call sites and a new event family; fanotify has only the `FAN_ATTRIB` notification | **Verified from source.** A's sites already exist and already block: `security_path_chmod` (`fs/open.c:632`), `security_path_chown` (`fs/open.c:771`), `security_inode_setattr` (`include/linux/security.h:428`), `security_inode_setxattr` (`fs/xattr.c:304`). |
| **fallocate / hole punch** with byte range and mode | **Expensive** — A must define its own range record | Equal | **Verified from source.** `FAN_EVENT_INFO_TYPE_RANGE` already exists for B (`include/uapi/linux/fanotify.h:153`). Neither endpoint has a fallocate hook today, so the hook cost is shared. **Judged** small. |
| **Clone / reflink** (`FICLONE`, `FICLONERANGE`) | Equal | Equal | **Judged.** Both objects are already-open descriptors, so no path resolution, mark placement, or revalidation question arises for either endpoint. |
| **Fail-open vs fail-closed selectable**; defined behaviour on daemon death and on queue-full | Equal | **Expensive** — three verified fail-open paths, all in code the shipping Open path also runs | **Verified from source — and one path more than the docs record.** (i) `fanotify_release()` drains both pending permission lists with `finish_permission_event(..., FAN_ALLOW, NULL)` (`fanotify_user.c:1098-1153`). (ii) `fanotify_handle_event()` returns 0 when `fsnotify_prepare_user_wait()` loses a mark-deletion race (`fanotify.c:970-977`). (iii) **Queue-full and group-shutdown, previously unrecorded:** `fsnotify_insert_event()` returns 2 when `group->q_len >= group->max_events` or `group->shutdown` (`fs/notify/notification.c:94-104`), and `fanotify_handle_event()` converts that to `ret = 0`, i.e. **allow** (`fanotify.c:996-1004`) — the `BUG_ON` at `:1000` guards *merge* only, not overflow. This matters more for filemaster than for a typical listener because mount marks make every operation on a protected mount an event. The one fail-closed path is allocation failure (`fanotify.c:984-993`). A writes its own teardown and can choose fail-closed. |
| Defined interrupted-wait, cancellation, and malformed-response behaviour | Equal | Equal | **Verified from source**, minor edge to B: `process_access_response()` validation exists (`fanotify_user.c:440-443`), and the wait's `-ERESTARTSYS` path is written (`fanotify.c:236-268`). A writes equivalents. **Judged** comparable. |
| Capability discovery | Equal | Equal | **Judged.** B probes `fanotify_init`/`fanotify_mark` for `EINVAL`; A versions its own protocol. Neither has a first-class discovery API. |
| **Metadata-read events** (stat family; optionally xattr read, readlink, access) with **no fd delivered** | Equal | **Expensive** — the same no-fd class conflict as Pre-create, plus a new hook site | **Verified from source.** `security_inode_getattr(path)` already exists at `fs/stat.c:259`; there is no fsnotify hook anywhere on that path. The no-fd conflict is `fanotify_user.c:2013-2016` + `:1659-1660` + `:1985-1990`. |
| **Suppression that scales to a subtree** | Equal | **Expensive** — fanotify has no subtree scope and cannot acquire one without leaving marks behind as the scope mechanism | **Verified from source.** Mark types are inode / mount / filesystem / mount-namespace only (`include/uapi/linux/fanotify.h:97-100`). `__fsnotify_parent()` consults exactly **one** level — `parent = dget_parent(dentry)` (`fs/notify/fsnotify.c:207`) — gated on `fsnotify_inode_watches_children()` (`include/linux/fsnotify_backend.h:673-683`). A subtree ignore is therefore one mark per directory, racing every `mkdir`. A holds its own path-prefix policy: new code, but not fighting an existing model. **This is the closest thing in the whole sweep to a Cannot for B.** |
| **Write permission events** (promote the modify notification) | Equal | Equal | **Judged.** B has `FAN_MODIFY` and the `FAN_PRE_ACCESS` precedent; A must invent the placement. Neither is cheap, and filemaster does not intend to use it — it decides Read and Write at Open. |
| **Dedupe** (`FIDEDUPERANGE`) | Equal | Equal | **Judged.** One source and an array of destinations with per-destination status fits neither endpoint's two-object shape. |
| **Directory traversal permission events** | Equal | **Expensive** — no fsnotify hook exists on the lookup path at all, and lookup runs in a non-blocking mode | **Verified from source.** A's site exists and already carries the signal: `mask = nd->flags & LOOKUP_RCU ? MAY_NOT_BLOCK : 0` fed to `inode_permission()` → `security_inode_permission()` (`fs/namei.c:1956`; `MAY_NOT_BLOCK` at `include/linux/fs.h:100`; the honouring branch at `fs/namei.c:375`). Both still need the forced retry out of the RCU walk. |
| **Listener self-exemption in the kernel** | Equal | Equal | **Verified from source**, minor edge to B: `FMODE_FSNOTIFY_NONE` already exempts fanotify's own event fds (`fs/notify/fsnotify.c:622-623`; the fds are made with `dentry_open_nonotify()` in `create_fd()`), though that is per-file, not per-group. A compares `current`'s tgid. **Judged** comparable. |
| **io_uring parity** | Equal | Equal | **Verified from source.** `create_io_thread()` clones with `CLONE_THREAD` (`kernel/fork.c:2649`), so an io-wq worker shares the issuing process's tgid; fanotify records `task_tgid(current)` and reports `pid_vnr(event->pid)` (`fanotify.c:874`; `fanotify_user.c:852`), and an LSM reads `current` directly. io_uring's structural opcodes re-enter the same `fs/namei.c` paths, so hooks in either endpoint fire. |

### Conclusion — Cannot cells

**There are none.** Neither architecture has a feature it fundamentally cannot
satisfy. **This gate does not eliminate an architecture.**

That is a real result rather than a hedge, and the reason is structural: both
candidates are custom-kernel forks with unbounded edit rights over the code they
own. B is not "fanotify as shipped"; it is "fanotify as filemaster forks it", and
every restriction found above is a line B is entitled to change. The **Cannot**
bar — *architecturally impossible, or possible only by abandoning that endpoint*
— was therefore only ever reachable for B, and only for something that would
require discarding marks, the single queue, or fd-based delivery. Nothing in
[backend-features.md](backend-features.md) quite requires that.

The two rows that came closest, and would be the ones to re-examine if the owner
wants to press this further:

1. **Subtree suppression** (metadata-read, medium priority). fanotify's scope
   mechanism *is* marks, marks are per inode/mount/filesystem, and
   `__fsnotify_parent()` is one level deep. Giving fanotify a subtree scope means
   adding a scope mechanism that is not a mark — which is arguably abandoning
   what the endpoint supplies. Called **Expensive** rather than **Cannot** only
   because an in-kernel path-prefix filter bolted into `fanotify_handle_event()`
   is describable.
2. **Mount attribution for structural events.** fanotify refuses dirent-family
   events on mount marks by design, because those events carry a directory inode
   and no `struct path` — and mount marks are exactly filemaster's shipping scope
   model. Called **Expensive** because B can plumb a `struct path` into the new
   structural event; but that plumbing is at every structural hook site, and it
   is not reuse.

Counting the cells, since cost came back a tie and this is the one input that
distinguishes on capability rather than money:

| | Cannot | Expensive | Equal |
|---|---|---|---|
| **A (LSM)** | 0 | 3 | 35 |
| **B (fanotify)** | 0 | 12 | 26 |

A's three Expensive cells cluster in one place — **Open**. A's endpoint does not
cover Open at all, so the three-valued response, requested-access-mode
reporting, and (marginally) fallocate range records all force A to either extend
fanotify anyway or migrate Open off it. That is worth noting precisely because
"the LSM route never touches the shipping fanotify path" is one of A's stated
advantages, and for the Open feature set it is **not true**.

B's twelve cluster in three places: the event *shape* (no fd, no name, no second
object, no mount), *lifecycle* (three fail-open paths, all shared with the
shipping Open path), and *scope* (marks cannot express a subtree or attribute a
dirent event to a mount).

### Could not verify

- **The `amir73il/linux` prototype branches.** ~~There is no local clone and no
  network fetch was attempted, so every statement about `fan_pre_modify-wip` and
  `fan_pre_dir_access` in this sweep is secondhand.~~ **Partly resolved
  2026-08-30 by a parallel source read** of a clone at
  `<scratchpad>/amirlinux`, recorded in
  [the fanotify extension note](update-option-fanotify-extension-technical.md#response-correlation-one-decision-rename-and-fail-closed--read-from-source-2026-08-30).
  Now **verified**: rename raised as two cookie-joined events (`29c60e4db`,
  `fsnotify_rename_perm()` — `FS_PRE_MOVE_FROM` then `FS_PRE_MOVE_TO`), and
  `fan_pre_dir_access` carrying fid + name in a variable-length permission event
  (`905163ce4` 68+/20−, `43ffbf710` 59+/15−). The rename row's verdict above
  therefore stands on verified evidence, not secondhand. **Still secondhand:**
  the SRCU barrier being quiescence rather than exclusion, the `O_PATH`
  recursion escape, and "overlayfs upper-layer modifications generate no
  events". A recount against those branches would still supersede B's cost
  estimate.
- **Overlayfs, product-level.** What is **verified from source** is narrower and
  sharper than the docs' claim, and points the other way — see below.

### Overlayfs — a verified constraint the docs do not record

**Verified from source.** A default overlayfs mount (`nfs_export=off`) sets
`sb->s_export_op = &ovl_export_fid_operations` (`fs/overlayfs/super.c:1506-1510`),
which provides `.encode_fh` only and no `.fh_to_dentry`
(`fs/overlayfs/export.c:866-869`). `exportfs_can_decode_fh()` requires
`nop->fh_to_dentry` (`include/linux/exportfs.h:336-339`), and
`fanotify_test_fid()` requires decodability for **any non-inode mark**
(`fs/notify/fanotify/fanotify_user.c:1790-1812`). Therefore: **on a default
overlayfs mount, fanotify refuses a filesystem or mount mark for any
fid-carrying event, with `-EOPNOTSUPP`.** Since B's structural events are
fid-shaped by construction (Pre-create row), B on overlayfs falls back to
per-inode marks — one per directory — which is the subtree problem in its worst
form. `fanotify_test_fsid()` (`:1748-1787`) additionally rejects zero-fsid
filesystems such as fuse for non-inode marks. A's `security_path_*` hooks have no
fid, fsid, or export-operation requirement whatsoever.

**Judged.** For the *user's* operation this does not separate the routes: an
unlink through an overlay mount enters `do_unlinkat()` in `fs/namei.c` with the
overlay path, so a post-unwind hook (A) and an fsnotify hook (B) both see it.
The asymmetry is entirely in whether the endpoint can be *scoped* to that mount.
Marked **Expensive**, folded into the mount-attribution row, not given a row of
its own.

### Where the `-technical.md` docs were wrong

Line references were spot-checked, not exhaustively audited.

1. **Fanotify is fail-open in three places, not two.**
   [backend-features-technical.md:106-115](backend-features-technical.md) and
   [update-option-fanotify-extension-technical.md:57-79](update-option-fanotify-extension-technical.md)
   both name only `fanotify_release()` and the `fsnotify_prepare_user_wait()`
   race. **Queue overflow and group shutdown are a third**: `fsnotify_insert_event()`
   returns 2 (`fs/notify/notification.c:94-104`) and `fanotify_handle_event()`
   turns that into allow (`fs/notify/fanotify/fanotify.c:996-1004`). Both
   documents should be corrected. This is the most load-bearing omission found,
   because filemaster's mount marks make queue pressure a realistic operating
   condition rather than an edge case.
2. **Line-reference drift, ~1-2 lines**, in
   [update-option-fanotify-extension-technical.md:116-122](update-option-fanotify-extension-technical.md):
   the fid/class rejection is cited as `fanotify_user.c:1658-1659`, actually
   **1659-1660**; `FAN_REPORT_MNT` as `1638-1643`, actually **1639-1644**;
   permission masks rejected for a notification group as `1983-1992`, actually
   **1985-1990**. Every underlying claim is correct.
3. **[backend-features-technical.md:128-131](backend-features-technical.md)**
   leaves the fid-with-permission-class question open ("needs verifying against
   the target kernel"). It is now settled: still restricted in `v7.1`
   (`fanotify_user.c:1659-1660`). The document should state the answer.
4. **[backend-features-technical.md:39-47](backend-features-technical.md)**
   ("Reuse of existing machinery") lists marks as reused rather than duplicated.
   For structural events on `v7.1` that is **not** available as written: dirent
   events are refused on mount marks (`fanotify_user.c:2013-2016`), which is the
   only mark type filemaster currently uses.

No conclusion in the docs was found to be *reversed* by this sweep; the
corrections are one omission and some drift.

## Gate 2 — the operation sweep

For every operation in [backend-features.md](backend-features.md):

- Its actual common kernel path.
- The existing LSM hook, if any.
- The existing fsnotify/fanotify hook, if any.
- **Exactly what is held at each candidate wait point**: locks, mount-write and
  freeze references, and object/path references.

Prefer full unwind and ordinary retry in both candidates. Do not design a
bespoke revalidation mechanism; P1 showed the ordinary second pass is sufficient
for `rmdir` and the same shape should be tested for the rest.

## Gate 3 — minimum designs and comparison

Design the **minimum** direct-fanotify implementation and the **minimum** LSM
implementation. Do not write production code.

Compare on these dimensions rather than lines of code:

| Dimension | Why it matters |
|---|---|
| Core kernel functions and files modified | Rebase burden and blast radius |
| New persistent kernel state | Lifecycle bugs, use-after-free risk |
| New kernel/userspace lifecycle machinery | The dominant remaining cost |
| Unique test dimensions | Ongoing verification burden |
| Regression risk to the existing Open/Execute path | Fanotify touches working code; an LSM does not |

## Optional runtime extension

If a further runtime proof is wanted, the highest-value one is **not** a full
backend. It is the P1 experiment repeated for one *rich* namespace operation —
`unlink` or `rename` — showing it can capture trustworthy context, fully unwind,
wait without locks, retry, and reject a raced replacement. `rename` is the
harder and more informative of the two because of `s_vfs_rename_mutex` and
two-sided identity.

Reuse the P1 bundle at `/root/vm/share/lsm-p1/` rather than starting over.

## Sequencing and size

These gates are **not** one job and should not be run as one.

| Part | Size | Needs a VM |
|---|---|---|
| ~~Gate 1 items 1–2 (fanotify source questions)~~ | **Done 2026-08-27 — negative** | No |
| ~~Gate 1 item 3 (feature sweep)~~ | **Done 2026-08-30 — no Cannot cell for either architecture** | No |
| Gate 1 item 4 (`O_RDWR` analysis) | Medium to large, never attempted | No |
| Gate 2 (full operation sweep) | **Large** | No |
| Gate 3 (minimum designs, dimension counts) | **Large** | No |
| Optional runtime extension | Large | Yes |

Gate 1 items 1–2 were run first and stopped there, as intended. They settled the
*cheap-reuse* claim for direct fanotify, but not the architecture — see the
update above. Item 3 is now **done** and did not eliminate either architecture.
**Item 4 (`O_RDWR` downgrade) is the last unrun Gate 1 item**, has still never
been attempted, and is the largest unexamined risk left in either route. With
cost a tie and the feature sweep a tie, **Gate 3 is now the deciding input**.

## What is actually outstanding before the owner picks a path (2026-08-30)

Cost is **done**: every option in
[Backend option cost estimates](update-options-cost.md) now carries a figure.
Three things are not, and two of them can change the answer.

| Open item | Can it change the path? |
|---|---|
| ~~**Gate 1 item 3 — feature sweep.**~~ **Done 2026-08-30 — no.** No **Cannot** cell for either architecture. Twelve **Expensive** cells for B (event shape, three fail-open paths, mark-based scope), three for A (all in Open, which A's endpoint does not cover). [Table](#gate-1-item-3--the-feature-sweep-2026-08-30). | **No — it did not separate them.** The one cheap input that could have eliminated a route did not. The decision now rests on Gate 3. |
| **Gate 1 item 4 — `O_RDWR` downgrade.** Can an indefinite wait occur under a parent lock on every open and create path? | **Yes, but not as a tiebreak.** It applies equally to both custom-kernel routes, so it cannot separate them — it can invalidate the whole custom-kernel family, which would push the decision toward BPF LSM or the second fanotify group. Never attempted. |
| **Gate 3 — minimum designs and dimension comparison.** | **It is now the deciding input**, because cost came back a tie. Large. |
| Outstanding [prior-art](prior-art-technical.md) leads (AppArmor prompting, Landlock Supervise status). | No. They may lower a figure; they do not reorder anything. |

**Judged.** "Cost is the last thing before deciding" is nearly true and
materially wrong in one place: the feature sweep is cheap, needs no VM, and is
the only cheap thing left that can remove an option outright. It should be run
before the decision, not after.

## Output

Findings and figures written to this file. State plainly where the evidence is
insufficient. Do not recommend an architecture — present what each would cost
and what each risks, and leave the choice to the owner.
