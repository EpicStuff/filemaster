# Codex task prompts — outstanding

Two jobs are ready to hand to a fresh Codex session. **Job A needs no VM and can
eliminate an option; Job B needs a VM and only sharpens a number.** Cost came
back a tie between the LSM and fanotify architectures, so Job A is the higher
value of the two right now.

Both carry the same standing rules, reproduced in each prompt:

- Report **feasibility and cost only**. Do not choose an architecture — the
  project owner does that.
- Do not trust the `-technical.md` docs in `docs/`. They are AI-generated and
  unreviewed, and P1 already found drifted line references. Verify against the
  exact kernel source that will be built, and name the version.
- Label every claim **verified from source**, **verified by running it**, or
  **believed/judged**.
- A clear negative is a successful result. Stop and report it.

---

## Job A — Gate 1 item 3: the feature sweep (no VM)

> You are working in the Filemaster repository. Read `docs/backend-features.md`
> and `docs/backend-features-technical.md` first.
>
> **Task.** For every feature listed in `docs/backend-features.md`, determine
> whether each of the two candidate custom-kernel architectures can satisfy it:
>
> - **A. LSM endpoint** — a Filemaster registered LSM at a new post-unwind hook,
>   with its own daemon transport. See `docs/update-option-lsm-dkms-technical.md`
>   and the proven mechanism in `docs/p1-rmdir-technical.md`.
> - **B. fanotify endpoint** — the same product, but fanotify supplies the event,
>   the queue, the wait, the reply and the marks. See
>   `docs/update-option-fanotify-extension-technical.md`.
>
> Produce one row per feature with three columns: satisfiable under A,
> satisfiable under B, and the evidence. Distinguish clearly between
> **cannot** (architecturally impossible or requiring the endpoint to be
> abandoned), **expensive** (possible, costs more than the other), and **equal**.
>
> **This is the only remaining input that can eliminate an architecture rather
> than rank it.** Look hardest for hard negatives. Specific things worth
> checking, not an exhaustive list: recursive subtree scope (fanotify marks are
> per-inode/mount/filesystem, and `FAN_EVENT_ON_CHILD` covers one level only);
> rename as a single decision over two directories; overlayfs upper-layer
> coverage; behaviour when the daemon dies; and per-process/per-profile identity
> at decision time.
>
> Write findings to `docs/p0-architecture-decision-technical.md` under Gate 1
> item 3. State plainly where evidence is insufficient. Do not recommend an
> architecture.
>
> Standing rules: report feasibility only, do not choose; do not trust the
> `-technical.md` docs, verify against Linux `v7.1` source and name it; label
> every claim verified-from-source / verified-by-running / judged; a clear
> negative is a success.

---

## Job B — P2: port the fanotify prior art to `v7.1` and recount (needs a VM)

> You are working in the Filemaster repository. The dev VM is at `/root/vm`,
> driven by `vmctl`. Reuse the P1 bundle at `/root/vm/share/lsm-p1/` rather than
> starting over; `docs/p1-rmdir-technical.md` records what it already does.
>
> **Background.** Filemaster is evaluating whether to build interactive
> structural file-operation prompts (`create`, `unlink`, `rmdir`, `rename`)
> behind a **fanotify** endpoint instead of its own LSM. The cost estimate for
> the fanotify route is currently **judged, not measured**:
> `~2,100–3,700 production lines / ~225–380M tokens`, derived in
> `docs/update-options-cost-technical.md`. Your job is to replace the judgement
> with a count, the same way P1 did.
>
> **The prior art is split across two branches of `amir73il/linux`.** Do not
> assume one is the base:
>
> | Branch | Base | Take from it |
> |---|---|---|
> | `fan_pre_dir_access` | v6.16-rc5 (2025-07-08) | The **event format**: `905163ce4` adds `FANOTIFY_EVENT_TYPE_FID_NAME_PERM`, a variable-length permission event carrying fsid + file handle + name that can sit on the response wait list. `43ffbf710` lifts the class restriction that forbids fid info in a permission group and adds `FAN_CLASS_PRE_CONTENT_FID`. |
> | `fan_pre_modify-wip` | v6.4 (2023-06-27) | The **directory-entry modify hooks** for create/mkdir/mknod/symlink/unlink/rmdir/link/rename. `fan_pre_dir_access` does lookup and readdir only and does not contain these. |
>
> `fan_vfs_filter` and `fan_pre_vfs` (2022–23) carry pre-lock placement and
> `FAN_CLASS_VFS_FILTER`. **Treat these as out of scope unless you find a reason
> otherwise** — P1 proved unwind-and-retry, and pre-lock placement carries a
> TOCTOU gap documented in `docs/update-option-fanotify-extension-technical.md`.
>
> **Answer this first, before porting anything — it may end the job.**
> `43ffbf710`'s commit message says the permission response was keyed on
> `event->fd`. Read how a fid+name permission event is correlated with its
> response. Then determine whether that correlation can carry (a) two-sided
> rename identity as **one** decision, and (b) fail-closed behaviour when the
> listener dies. Mainline `v7.1` fails open in two verified places:
> `fanotify_release()` drains pending permission lists with `FAN_ALLOW`, and
> `fanotify_handle_event()` returns success when `fsnotify_prepare_user_wait()`
> loses a mark-deletion race. If the response path cannot be made to carry these,
> say so and stop — that is a successful negative result.
>
> **Then, the port.** Rebase the two patch sets onto the exact `v7.1` source that
> will be built. Build it. Boot it in the VM. You do **not** need a working
> product — you need to know what survives and what has to be rewritten.
>
> **Deliverables, in `docs/update-option-fanotify-extension-technical.md`:**
>
> 1. **Measured** lines that applied cleanly, lines that needed rework, and lines
>    that had to be written fresh — per patch set, so the 2025 and 2023 bases can
>    be told apart.
> 2. **Measured** kernel diff against `v7.1` for the four structural operations,
>    comparable to P1's measured `fs/namei.c` +16/−1 and +38 generic plumbing.
> 3. Answers to the response-correlation questions above.
> 4. Whether the existing shipping `FAN_OPEN_PERM` path still works after the
>    patches are applied — Filemaster's current Open prompts depend on it, and
>    regression risk to that path is one of the main arguments against this route.
> 5. A **recount** of the cost estimate using the row structure already in
>    `docs/update-options-cost-technical.md` under "Fanotify extension in a custom
>    kernel — estimate entered". Say which rows the port proved wrong.
>
> Standing rules: report feasibility and cost only, do not choose an
> architecture; do not trust the `-technical.md` docs, verify against the `v7.1`
> source you actually build and name it; label every claim verified-from-source /
> verified-by-running / judged; a clear negative is a success.

---

## Not for Codex yet

**Gate 1 item 4 — the `O_RDWR` → read-only downgrade analysis.** Never
attempted, medium-to-large, no VM needed. It applies equally to both
architectures so it cannot break the tie, but it can invalidate the whole
custom-kernel family. Worth doing, but after Job A.
