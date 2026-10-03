# LSM-only update option — technical implementation note

## Scope

This note covers the static, existing-upstream-hook native LSM only. It excludes
the targeted VFS changes in the [+ DKMS route](update-option-+dkms.md), and it
does not add an interactive LSM prompt. Fanotify remains the owner of interactive
Open and File Execute decisions.

The first native proof should mirror the four BPF-proven hooks exactly:
`inode_unlink`, `inode_rmdir`, `inode_link`, and `inode_rename`. It should use
the same static outcomes: only Allow proceeds; Deny, Ask, no policy, and an
unrepresentable policy deny without a prompt.

## Native implementation shape

1. Build the Filemaster LSM into the custom kernel, with its own Kconfig,
   Makefile, LSM registration, and an explicit position in the configured LSM
   order. Boot tests must verify both the custom configuration and its presence
   in `/sys/kernel/security/lsm`.
2. Keep each hook non-blocking and static. It may read an already-published
   answer table, but it must not wait for userspace, take a user-controlled
   lock, or perform filesystem/path resolution to manufacture context.
3. **The kernel holds precomputed answers, not rules.** The daemon does all
   rule matching, profile resolution, and precedence, then publishes a flat
   lookup table of decided outcomes. The kernel looks up; it does not evaluate.
   Do not port the matcher, the profile model, or rule precedence into kernel
   code, and do not let the kernel derive an outcome the daemon did not
   already decide. An entry that is missing, stale, or unrepresentable denies.
4. Choose a privileged control interface in a small proof before building the
   backend. Generic netlink and securityfs are candidate shapes; whichever is
   chosen must authorize writers, publish immutable tables safely (normally
   with RCU-style lifetime), and expose the active generation to diagnostics.
5. Reuse Filemaster's product-level operation enum, rule compiler, profile
   resolution, static outcome semantics, health status, and VM test corpus.
   The native kernel answer table and control-plane protocol are not reusable
   from BPF maps.
6. Treat the same hook-context limits as BPF as real LSM-only limits. Native C
   can inspect more kernel data, but the existing `inode_*` hook contract still
   does not itself supply a complete mount/path identity or rename flags. Do
   not claim that native LSM alone solves those gaps.

## What the answer table is keyed on

The table is **a set of marked directories identified by inode**, not a table
of path strings. At an `inode_*` hook the kernel is given a parent inode and a
dentry and no `vfsmount`, so it cannot construct a mount-qualified path. A
path-keyed table is therefore not implementable at these hooks, and it would be
unbounded in any case: there is no finite set of paths to precompute.

The lookup is a walk, not a match:

1. From the target dentry, walk parents with `dget_parent()` until a marked
   directory is found or the root is reached.
2. The nearest marked ancestor supplies the decided outcome.
3. No marked ancestor means the operation is out of scope and proceeds.

This keeps the kernel side a lookup rather than an evaluator, keeps the table
small enough to publish atomically, and needs neither path construction nor
mount identity. It is also the same mechanism the
[LSM + DKMS phase](update-option-lsm-dkms-technical.md) needs for scope marks,
so it is carried forward rather than discarded.

Constraints to state rather than hide:

- Inode-identified marks cannot distinguish two bind-mounted views of the same
  directory. Both views resolve to the same mark. Where a rule depends on which
  view was used, that rule is outside LSM-only's claimed scope.
- A disconnected dentry — an NFS filehandle-resolved object with no reachable
  parent chain — cannot be walked. Fail closed.
- The walk must tolerate concurrent rename. Take a reference on each parent
  rather than dereferencing `d_parent` directly, and treat a walk that leaves
  the expected tree as a failure, not as "no mark found".

## Rename without flags fails closed on both ends

`inode_rename` has no rename-flags argument; `path_rename` does. In the
LSM-only phase the flags are therefore not visible, and an ordinary rename
cannot be distinguished from a `RENAME_EXCHANGE`, which atomically swaps two
objects.

That gap is exploitable. A policy that asks only "may this source be renamed?"
can be defeated by exchanging a protected object with an unprotected one. The
required fallback:

- Require a permitting outcome for **both** endpoints of every rename.
- Treat a rename that touches a marked subtree on **either** side as in scope.
- Never report flag-specific rename policy as supported in this phase.

## Kernel-internal operations are not user operations

Filemaster must decide only on operations a user's process actually requested.
Two sources of false events need an explicit classification, in this phase and
the next:

- **Kernel threads.** Check `PF_KTHREAD` and exclude them.
- **Stacked filesystems.** Overlayfs performs operations on its underlying
  layers under overridden credentials, so a single user-visible delete can
  surface at the hook more than once. Decide explicitly whether Filemaster acts
  on the overlay-level operation, the underlying one, or both, and record the
  choice. Left unhandled this produces duplicate decisions in this phase and
  duplicate prompts in the next.

This is a design constraint, not only a test case.

## Startup and failure states

"No entry for this object" and "no table has ever arrived" must not be the same
state. Three are required:

| State | Behaviour |
|---|---|
| Uninitialised — no table published since boot | Allow, and report the backend as degraded. Enforcing here would make an unbootable system. |
| Active | Enforce the published table. |
| Failed — publication rejected, generation mismatch, or daemon lost | Explicit configured choice, defaulting to allow-and-degrade for this development fork. Do not let it be reached implicitly. |

The status must be visible to Filemaster's health reporting, so that
"protecting nothing" is never indistinguishable from "nothing matched".

## Transition to LSM + DKMS

The LSM-only phase is deliberately a static phase: an `Ask` result denies
because its existing upstream hook may be under VFS operation locks. It must
not attempt a userspace wait there.

The later [LSM + DKMS route](update-option-lsm-dkms-technical.md) retains the
native LSM build, registration, ordering, health reporting, hook adapters, and
the privileged kernel/daemon channel. It does **not** retain the published
answer table: in that phase the LSM stops answering from a table and becomes a
fanotify-shaped permission-event source, forwarding to the daemon and enforcing
its reply. The table itself is fully used during this phase but is not carried
forward; the publication machinery around it is, because phase two needs the
same mechanism for scope marks.

Keeping the kernel side to a lookup table rather than a matcher is what makes
that handover cheap. Rule evaluation never moves: the daemon decides in both
phases, precomputing in this one and answering live in the next.

The wait is not added at the existing hook. A targeted kernel change lets the
operation unwind normally after the hook returns an internal sentinel, then
calls one new generic security hook at the point where all locks, mount-write
references, and path references have already been released. The LSM waits
there, and VFS restarts the operation so that re-resolution, locking, and every
later security check happen as an ordinary second pass.

That also means the existing hook adapter is not gated off. Both passes go
through the same `path_*` hook; the LSM distinguishes them by whether it holds
a cached verdict for the task. The sentinel, event transport, killable wait,
verdict cache, and unwind/retry hook are additional targeted-kernel work; they
are not claimed by LSM only.

Note the hook-family change at this joint. This phase proves the four `inode_*`
hooks; LSM + DKMS uses `path_*`, which supplies the mount and path identity
`inode_*` does not. Static matcher code written against `inode_*` arguments
does not carry across unchanged, and in the fanotify-shaped model it does not
carry across at all.

## BPF LSM to LSM-only migration

Reusable work from a completed BPF backend includes:

1. Static policy semantics and the Go rule/profile compiler above the backend
   adapter.
2. The operation surface, fail-closed test matrix, FileAccess lifecycle/status
   contract, VM fixtures, and fanotify Open/File Execute coexistence tests.
3. The target-kernel hook evidence and negative cases, especially unsupported
   rename variants and unowned operations.

The following is a rewrite rather than a port:

1. BPF C programs, CO-RE object packaging, libbpf loader, map layout, links,
   and BPF-specific health checks.
2. The kernel answer table, safe userspace control path, kernel memory
   lifecycle, LSM registration, and custom-kernel packaging/CI.

Use a rebooted custom-kernel VM for the first cutover. Do not attach native and
BPF enforcement to the same structural operation merely to make the migration
look seamless: a disagreement can produce duplicate decisions or hide a
coverage gap. First compare the two backends in separate runs against one
frozen policy corpus. A live zero-gap hand-off needs its own proof of equivalent
policy generations; otherwise report the maintenance/reboot window honestly.

## Native proof sequence

1. Build and boot the exact custom kernel with a disabled-by-default native
   answer table.
2. Verify the LSM is active, then enable only the four proven hooks with an
   operation-only test policy.
3. Reproduce the BPF Allow/Deny/Ask/missing/unrepresentable matrix and verify
   side effects, link/delete/rename edge cases, restart, and policy replacement.
4. Add the Filemaster control-plane proof: writer authorization, table
   publication, failed update, kernel restart, and degraded-status reporting.
5. Prove the kernel evaluates nothing. For a corpus of rule sets, confirm every
   kernel outcome is one the daemon published, and that no kernel path can
   derive an outcome for an operation absent from the table. This is the
   property that keeps the phase-two handover cheap.
6. Prove the mark walk: nearest-ancestor selection, nested marks, an unmarked
   tree, a mark removed mid-walk, a concurrent rename of an ancestor, a
   disconnected dentry, and both views of a bind mount. The bind-mount case is
   a documented limitation to record, not a bug to fix here.
7. Prove the rename fallback denies a `RENAME_EXCHANGE` that swaps a protected
   object with an unprotected one, and that both endpoints are checked on every
   rename.
8. Prove the three startup states are distinguishable at runtime, that an
   uninitialised table never enforces, and that a failed publication is
   reported rather than silently reached.
9. Prove kernel threads raise no decision and that one delete on an overlayfs
   mount yields exactly one Filemaster decision.
10. Only then attempt the path/mount/original-path identity P1. Escalate to
    LSM + DKMS if the existing hooks cannot supply enough correct context.
