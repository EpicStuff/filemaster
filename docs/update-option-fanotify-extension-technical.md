# Fanotify extension in a custom kernel — technical note

> **Status: newly identified, not yet evaluated.** This option was surfaced late
> and has not been costed or proven. Nothing here is verified against fanotify
> source; the load-bearing claims are marked and must be checked before this is
> weighed against the other options.
>
> **Its headline saving has already shrunk once.** The initial argument leaned on
> reusing Filemaster's existing fanotify client. Sizing found the daemon side
> needs 500–850 lines of new work whatever the transport, so the claim now rests
> on the kernel-side wait and queue only. Baseline to beat: pure native at
> **2,655–4,275 production lines / 234–350M tokens**.

> **Not the same as DKMS-only approach 2.**
> [DKMS only](update-option-dkms-only.md) lists a "runtime fanotify extension"
> among its approaches, but scopes it to an **unmodified distro kernel** —
> hooking stock fanotify at runtime from a loadable module. That framing is why
> the doc concludes the evaluation "does not currently support it as
> achievable." This note describes the same idea delivered as an ordinary
> **source patch to a custom kernel**, which removes the runtime-hooking problem
> entirely and is a materially different proposition.

## The idea

Rather than adding a Filemaster LSM that owns a userspace query and a wait,
extend the kernel's existing fanotify so that structural operations — `unlink`,
`rmdir`, `rename`, `link` — can raise fanotify **permission** events, the same
way `FAN_OPEN_PERM` already does for Open.

Filemaster then does not gain a new kernel interface at all. It registers for
more event types on the fanotify group it already has.

## Why this could be the cheapest route to prompting

The LSM route's remaining cost is no longer the kernel diff — P1 measured that
at 16 insertions in `fs/namei.c` for `rmdir`, plus 38 lines of one-time hook
plumbing. What remains expensive is the **Filemaster LSM module and its daemon
protocol**: transport, queueing, the untimed killable wait, response handling,
daemon-crash behaviour, overflow, and cancellation.

**Believed, not verified.** Fanotify already has every one of those, in-tree and
long-tested:

| Piece the LSM route must build | Fanotify's existing equivalent |
|---|---|
| Untimed, killable wait for a userspace answer | `fanotify_get_response()`, which blocks the accessing task until userspace replies |
| Event queue and delivery to userspace | The fanotify group event queue |
| Response validation and correlation | Existing permission-event response handling |
| Overflow behaviour | `FAN_Q_OVERFLOW` |
| Daemon crash / fd close while requests are pending | Existing group teardown path |
| Userspace client | **Filemaster's existing fanotify code** |

That last row looked like the real prize. **Sizing has since narrowed it.**
[LSM module sizing](lsm-module-sizing-technical.md) found, *measured from
source*, that Filemaster's current daemon event model is single-path and
Open/Read/Write/Execute-shaped: rename and link endpoints and their correlation
are real new Go work, "not a fanotify reader swap". It sizes the daemon protocol
and adapter at **500–850 lines regardless of transport**.

So the saving this option can claim is **not** the daemon side. It is confined
to the kernel-side transport, queue, response and wait — components sized inside
the native LSM module's 1,760–2,830 lines, not inside the daemon's 500–850. That
is still a real target, but it is a fraction of the module rather than most of
the remaining cost, and it must be weighed against modifying a subsystem the
working product already depends on.

The single hardest piece of the LSM design — an untimed wait that is killable,
cancellable, and safe against daemon death — is the piece fanotify already
solved.

## The kernel mechanism is unchanged

This option does **not** avoid the unwind-and-retry work. Adding
`FAN_RENAME_PERM` at the natural hook site hits exactly the same wall the LSM
design hit: at `security_path_rmdir()` the parent's `i_rwsem` is held for write
and a `mnt_want_write()` reference is held, so an untimed wait there stalls the
directory and blocks `fsfreeze`. Cross-directory `rename` adds
`s_vfs_rename_mutex`.

So the mechanism is identical to
[LSM + DKMS](update-option-lsm-dkms-technical.md#the-unwind-and-retry-mechanism):
sentinel, full unwind, wait at a point where nothing is held, `goto retry`,
ordinary second pass. P1's measured `fs/namei.c` diff applies here essentially
unchanged. What differs is only **who is called at the post-unwind point** —
fanotify instead of a Filemaster LSM.

## What is genuinely new work

**Believed, not verified.**

1. **Event format for two-path operations.** `rename` has a source and a
   destination. Fanotify's permission-event format is built around a single
   object. Note `FAN_RENAME` already exists as a *notification* event, so the
   information-carrying shape may be partly solved in-tree — that is the first
   thing to check, and it could be a large saving or a large cost.
2. **Cross-pass verdict carry.** Fanotify answers a permission event and the
   operation proceeds immediately. The retry design needs the verdict to survive
   the unwind and be consumed on the second pass, so per-task state is required
   regardless. This does not come free from fanotify.
3. **Mark semantics.** Which mark makes a structural operation reportable — a
   mark on the parent directory, the target, the mount? This needs a defensible
   answer and it is a design question, not plumbing.
4. **New UAPI.** New `FAN_*_PERM` constants and event structures. For a personal
   fork the stability burden is low, but the design still has to be coherent.

## Risks specific to this option

- **It modifies a subsystem Filemaster already depends on.** A Filemaster LSM
  touches nothing that exists; a fanotify patch touches the code path currently
  serving Open and Execute prompting. Regressions there break the working
  product, not just the new feature. This is the main argument against.
- **fanotify is opinionated and shared.** Its maintainers have clear views about
  permission events; an out-of-tree divergence may be awkward to rebase. Per
  kernel release this could be more work than the LSM route's ~16-line
  `fs/namei.c` patch, because the surface touched is larger.
- **Upstreamability is worse, not better.** The LSM route's diff can be kept
  generic. A fanotify permission-event extension is a substantial UAPI proposal.

## Interaction with the BPF question

This option changes what "wasted work" means for a BPF-first plan. BPF carries
over into an LSM endpoint reasonably well — hooks, path resolution, daemon
policy matching. It carries over into a fanotify-extension endpoint **worse**,
because the interception point, the transport, and the userspace client are all
different. A BPF stage discarded on the way to a fanotify extension wastes more
than a BPF stage discarded on the way to an LSM.

So the "should I do BPF first" question cannot be answered independently of
which endpoint is chosen.

## Evaluation

This option is evaluated against the LSM route by
[P0 — architecture decision](p0-architecture-decision-technical.md), which
supersedes the checklist below as the operative scope. The list is retained
because it names the same load-bearing questions.

## What must be established before this is weighed against the others

In rough order of how much they would move the answer:

1. **Does `fanotify_get_response()` actually provide an untimed, killable wait
   with acceptable daemon-death behaviour?** The entire cost argument rests on
   this. Read the source; do not assume.
2. **Can the existing `FAN_RENAME` notification event format carry what a
   permission decision needs**, or must a new two-path permission event be
   designed from scratch?
3. **How much of Filemaster's existing fanotify userspace actually gets reused**
   versus needing a parallel path for structural operations.
4. **What does the fanotify patch cost per kernel release**, compared with the
   LSM route's measured ~145–195 lines?
5. **Can the Open/Execute path be proven unregressed** by the patch.

Items 1 and 2 are cheap and decide most of it. Neither needs a VM.
