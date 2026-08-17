# DKMS backend technical exploration

> Shared and DKMS-specific evaluation checks are in
> [Backend Test Requirements](backend-test-requirements.md).
>
> Product behaviour is defined in
> [Backend Feature Requirements](backend-features.md). This document evaluates
> whether a DKMS-based implementation can deliver it safely.

Linux kernel backend for Filemaster using a DKMS-buildable
out-of-tree module, while users keep their normal distro kernel unchanged.

## Delivery approaches to evaluate

The DKMS option includes three possible approaches. None is selected by this
note.

1. **Standalone enforcement module:** mediate the required VFS operations and
   communicate with Filemaster's existing userspace policy and prompt pipeline.
2. **Runtime fanotify extension:** augment the stock kernel's existing
   fanotify/fsnotify machinery so additional operations become fanotify-style
   permission events.
3. **Generated livepatch:** write the change as an ordinary kernel source patch
   and let the in-tree `klp-build` tool generate a loadable livepatch module
   from it. The module is still shipped and rebuilt like any other out-of-tree
   module, but the maintained artefact is the source patch, not hand-written
   hook code.

Approaches 1 and 2 are hand-written modules that hook the kernel at runtime;
approach 3 generates the module from a patch. They differ mainly in what has to
be re-verified when a supported kernel changes.

The runtime-extension approach must prove all of the following before it is
preferred over a standalone module:

1. Existing fanotify marks, event queues, response handling, overflow handling,
   cancellation, and lifecycle can be reused without changing their current
   behaviour.
2. Notification-only create, delete, rename, and link information can be made
   available before an operation commits, with enough object and path context
   to revalidate an approval safely.
3. If the extension supports separate Filemaster Read and Write permissions, it
   obtains the requested access mode at the Open hook. It must not add or depend
   on fanotify read/write events.
4. The required kernel functions are traceable and safely patchable on each
   supported distro kernel, without unacceptable ftrace, livepatch, symbol,
   module-signing, or Secure Boot conflicts.
5. No wait for userspace occurs while VFS, inode, directory, or rename locks
   are held; a later commit-time validation closes the resulting race safely.
6. Kernel inlines, macros, data-layout assumptions, kernel upgrades, and DKMS
   compilation cannot leave the system appearing protected when an interception
   point has disappeared.

The generated-livepatch approach must prove all of the following before it is
preferred:

1. Target kernels are built with `CONFIG_LIVEPATCH=y` and `CONFIG_KLP_BUILD`,
   on an architecture with `HAVE_KLP_BUILD` (x86-64 today), and without
   `RANDSTRUCT` or `LATENT_ENTROPY`. Absent any of these the approach is
   unavailable, not merely harder.
2. The full kernel source and the exact config for each supported kernel are
   obtainable at build time. `klp-build` needs both; kernel headers alone are
   not sufficient.
3. The change carries no data-structure layout modification. Livepatch cannot
   resize or reorder a struct that running code already holds, so anything
   requiring a wider `i_fsnotify_mask` in `struct inode`, or new fields in
   existing fsnotify structures, must instead be carried on a parallel
   allocation. Shadow variables exist for this but are hashtable-backed and are
   not acceptable on a hot VFS path.
4. The patch touches no `__init` code and removes no functions, and any change
   to an exported prototype is checked against out-of-tree modules on the
   target systems.
5. The livepatch transition converges under realistic load. Consistency-model
   stalls on hot VFS paths must be measured, not assumed.
6. IPMODIFY conflicts with a distro livepatch service already running on the
   target are detected and reported rather than silently losing coverage.

The evaluation must compare all three routes on correctness, fail-safe
behaviour, maintenance burden, and the minimum runtime patch surface. Do not
prefer the runtime extension solely because it reuses fanotify, and do not
prefer the livepatch solely because `klp-build` writes the module.

Two constraints apply to any hand-written hooking approach and should be
settled early, since they bound approaches 1 and 2 but not 3:

- `kallsyms_lookup_name` is not exported. Resolving unexported symbols needs a
  documented workaround, and that workaround is itself a per-kernel
  compatibility surface.
- ftrace replaces a function at its entry; it cannot inject into the middle of
  one. Every mediated VFS function is therefore copied into the module and
  edited, along with the static helpers it calls. That copied code has to be
  re-diffed against every supported kernel. Inlined callees have no hook point
  at all and must be detected rather than assumed present.

First inspect the current Filemaster code/docs, especially the existing fanotify
backend, PendingEvent/decision pipeline, rule engine, and future-operation
model. Reuse the existing userspace policy/prompt machinery rather than
duplicating policy in the module.

## Tooling

`kpatch-build` is deprecated as of 6.19. Its replacement, `klp-build`, is in
the kernel tree at `scripts/livepatch/klp-build` and takes one or more patch
files. It builds the tree twice, diffs at object level, extracts the changed
functions with their reachable dependencies, and emits a loadable module that
registers the replacements through ftrace. Livepatching *is* ftrace underneath:
`klp_ftrace_handler` redirects execution by rewriting the instruction pointer.
A livepatch is an ordinary kernel module, so DKMS can build and install one.

That is what distinguishes approach 3: for approaches 1 and 2 the per-kernel
work is re-auditing hand-written hook code against a changed tree; for approach
3 it is re-applying a patch and rerunning the generator. Both are per-kernel
work — neither escapes it — but they are not the same size.

Rough size estimates, non-test lines, against 7.1.8. Treat as estimates; the
per-function measurements underneath them are real, the projections are not.

| | Approach 1/2 (hand-written) | Approach 3 (generated) |
|---|---|---|
| Implementation | ~3,400–5,300 | ~2,200–3,100 |
| Of which copied VFS code | ~1,000–1,600 | none |
| Per-kernel re-verification | full re-audit | re-apply patch |

The copied-VFS figure is the firmest number here: the mediated functions in
7.1.8 sum to 973 lines before their static helpers, led by `vfs_rename` (167),
`notify_change` (140), `do_dentry_open` (127) and `vfs_fallocate` (103).

## Technical goals

- Keep stock distro kernels; no custom/rebuilt kernel requirement.
- DKMS module should compile against the installed kernel headers.
- Reuse Filemaster's existing userspace policy and prompt machinery rather than
  duplicating policy inside the module.
- Allow a hybrid with fanotify only where it improves a documented capability
  without introducing fanotify read/write interception or classification.

Important correctness/security requirements:
- Do not sleep/wait for userspace while holding VFS/rename/directory locks. For operations such as delete/rename/create/link, use an earlier safe interactive decision and a fast final commit-time validation if necessary.
- Prevent TOCTOU: an approval must apply to the exact operation/object/source/destination that was presented, not merely a pathname string.
- Fail closed on unsupported/missing critical interception capabilities; never silently claim protection after a kernel update if coverage changed.
- Account for every modification path required by the feature requirements, not
  merely ordinary content writes: `O_TRUNC`, truncate, allocation, mappings,
  metadata, cloning/dedupe, io_uring/VFS paths, and relevant ioctls.
- Treat unknown filesystem ioctls as potentially mutating unless proven
  otherwise. Known clone/dedupe operations must carry the necessary source and
  destination context.
- Avoid recursion/deadlock when Filemaster itself performs filesystem operations while servicing a request. Do not use a fragile PID-only bypass.
- Handle daemon crash/restart, request cancellation, timeouts/signals, module unload, queue exhaustion and concurrent requests safely.
- Be aware of overlayfs/stacked-filesystem internal operations and avoid duplicate prompts or recursive mediation.
- Detect ftrace/IPMODIFY/livepatch conflicts or unavailable/non-traceable required functions.
- Do not rely on DKMS successfully compiling as proof that a new kernel version is still safely supported. Add runtime/startup capability verification.
- Prefer a maintainable solution over hooking many syscall entry points; enforcement should be at common VFS/kernel paths so io_uring and alternate syscalls cannot bypass it.

Development/testing:
- Make development self-contained in the existing container as much as practical.
- Add an automated QEMU test guest inside the container (KVM via /dev/kvm when available, TCG fallback) so kernel-module testing cannot crash the host.
- The normal workflow should be one command that builds the module, boots/resets the disposable guest, loads it, runs security/coverage tests, and reports results.
- Test against a stock kernel, since that is the intended user environment.
- Build adversarial tests for bypasses/races, not just happy paths.

Do not blindly follow my suggested implementation mechanism if kernel inspection reveals a safer/cleaner approach. The hard requirements are the resulting security semantics, stock-kernel/DKMS deployment, no silent coverage degradation, and safe interactive blocking.

Implement this incrementally, starting with a minimal end-to-end backend that
proves the first product requirements can be delivered safely:

1. separate Read/Write Open permissions;
2. frozen Delete;
3. frozen Rename with source and destination validation;
4. userspace Allow/Deny round-trip; and
5. automated QEMU testing.

Once those foundations are sound, extend coverage to the remaining operations.
