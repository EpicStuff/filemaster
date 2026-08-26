# BPF LSM + DKMS update option — technical implementation and final-scope note

## Endpoint

This is a BPF-first route. On a stock kernel, BPF LSM provides static
Allow/Deny enforcement for structural operations at proven upstream hooks.
Fanotify remains the sole owner of the current interactive Open and File
Execute path. Once targeted kernel changes are available, they take ownership
of every structural-operation decision as described below. The option name is
retained for continuity.

The shared product summary is in the [+ DKMS overview](update-option-+dkms.md).

Here, `+ DKMS` labels the later targeted-kernel route, not a settled delivery
method: direct custom-kernel compilation and `klp-build`/livepatch remain
separate decisions. Distribution of those changes is outside this design and
cost estimate.

## Transition to direct kernel decisioning

Once custom-kernel support exists, every structural-operation decision goes
directly to Filemaster. The custom kernel owns request creation, the safe
wait/cancellation lifecycle, the userspace reply, any operation transformation,
and final revalidation. BPF cannot provide those parts.

Do not retain a BPF map cache for known structural-operation rules. Fanotify
continues to handle the much more common Open and Execute path, so avoiding a
Filemaster round trip only for delete, rename, link, and similar operations does
not justify a second policy store or its synchronization and verifier/loader
lifecycle. The BPF program, maps, loader, and BPF-specific tests are therefore
temporary implementation work; reusable output is limited to policy behaviour,
the operation matrix, and VM findings.

## Interim BPF boundary

1. The stock-kernel BPF object attaches only to proven upstream LSM hooks and
   uses a product-level policy snapshot compiled into BPF maps. It is an
   independent interim capability, not a final custom-kernel layer.
2. It does not attach an Open or File Execute hook. Fanotify remains the only
   decision owner for those operations in both phases.
3. The policy compiler, rule semantics, and coverage status remain
   backend-neutral. BPF map layout is an interim implementation detail, not the
   product rule format.
4. At direct-kernel cutover, BPF structural hooks are not attached or consulted
   for the same operations. A deliberate return to the stock BPF phase is a
   separate capability transition, not a concurrent policy cache.

## One coherent decision

1. In the stock BPF phase, static Allow proceeds and every other result fails
   closed without a prompt.
2. In the direct-kernel phase, the custom kernel raises an event only before a
   lock-free safe wait. It supplies the operation, process, object or
   parent/name identity, mount/path context, and both sides where an operation
   has two objects.
3. Before the operation commits, the direct path revalidates the approved
   object, parent, name, and operation. A mismatch fails rather than using a
   stale approval.
4. A structural operation has one decision owner in each phase. There is no
   BPF/custom arbitration, duplicate prompt, unprotected hand-off, or BPF
   outcome that can bypass a direct Filemaster decision.
5. On a stock kernel, a profile or rule needing direct-kernel capability is
   reported as unsupported or fails closed. It must not silently fall back to a
   BPF Allow.

## Final-scope feature work

| Feature family | Required targeted work beyond BPF LSM | Main proof obligation |
| --- | --- | --- |
| Shared permission foundation | Custom event ABI, wait/response/cancellation, failure policy, capability status, and commit-time revalidation | No VFS, inode, directory, or rename lock across a wait |
| Open and listing | Read/Write request context, read-only downgrade, `O_TRUNC` cancellation, and one decision per directory open-file description | Returned descriptor and observed truncation behaviour |
| Create, delete, link, rename, replacement | Pre-lock source/destination context, atomic two-object approval, and revalidation | No rename/link replacement race or separate accidental approval |
| Truncate, metadata, range, clone/reflink | Safe VFS/ioctl decision points plus attribute, range, and two-file event context | Every relevant mutation path reaches the claimed decision |
| Metadata read and low-priority tail | Descriptor-free metadata identity, subtree suppression, write, dedupe, traversal retry, and listener self-exemption | Volume/performance, multi-destination semantics, and no lookup-path deadlock |
| Phase transition | Exact stock/direct capability reporting and clean BPF structural-hook detachment before the direct owner starts | No overlap, coverage gap, or false coverage at cutover |
| Cross-cutting correctness | io_uring attribution, overlay/stacked filesystems, daemon crash, queue exhaustion, recursion, kernel updates, and VM adversarial tests | No bypass, deadlock, duplicate decision, or silent coverage loss |

The final scope is a planning target, not a promise: each feature is advertised
only after its hook, safe-wait, context, and revalidation proof passes.

Metadata-read subtree suppression and directory-traversal retry are feasibility
gates, not routine implementation items. Their failure can require a different
architecture and can exceed the estimate.

## Required phase-transition proof

1. Prove the stock BPF backend independently on its supported stock-kernel
   scope, including lifecycle and fail-closed behavior.
2. Prove the custom kernel sends a structural request directly to Filemaster,
   waits without a conflicting lock, handles cancellation and replies, and
   revalidates before commit.
3. Prove a direct-kernel boot has no BPF structural hook attached for an
   operation it owns, and that switching capability modes cannot create an
   overlap, gap, or stale policy claim.
4. The direct path needs no custom BPF dispatcher, BPF-specific BTF contract,
   or new verifier/program-type work.

## Build boundary

The reference path builds, boots, and tests the direct-kernel decision path and
all targeted VFS or kernel changes together in one custom kernel. The BPF
interim backend is tested separately on its stock-kernel scope.
