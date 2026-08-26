# LSM + DKMS update option — technical implementation and final-scope note

## Endpoint

This is a native-LSM-first route. It begins with the static Filemaster LSM from
LSM only, then uses targeted VFS or kernel changes for operations whose required
semantics cannot be delivered at an existing static LSM hook. Once those changes
are present, they take ownership of every structural-operation decision. The
option name is retained for continuity.

The shared product summary is in the [+ DKMS overview](update-option-+dkms.md).

Here, `+ DKMS` labels the later targeted-kernel route, not a settled delivery
method: direct custom-kernel compilation and `klp-build`/livepatch remain
separate decisions. Distribution of those changes is outside this design and
cost estimate.

The native LSM remains non-blocking and static during its interim phase. It does
not turn an LSM hook into an interactive userspace prompt. Existing fanotify
Open and File Execute behaviour remains in place where sufficient. A custom
permission path is added only where the product needs a freeze, richer context,
a changed operation result, or a new safe decision point.

## Transition to direct kernel decisioning

Once custom-kernel support exists, every structural-operation decision goes
directly to Filemaster. The custom kernel owns request creation, the safe
wait/cancellation lifecycle, the userspace reply, any operation transformation,
and final revalidation. A static native LSM cannot provide those parts.

Do not retain a native-LSM policy cache for known structural-operation rules.
Fanotify continues to handle the much more common Open and Execute path, so
avoiding a Filemaster round trip only for delete, rename, link, and similar
operations does not justify a second policy store or its control-plane and
kernel-lifetime complexity. Native-LSM registration, policy-store,
control-interface, and static-hook tests are therefore temporary implementation
work; reusable output is limited to policy behaviour, the operation matrix, and
VM findings.

## One coherent decision

1. In the interim LSM-only phase, the native LSM evaluates already-published
   static policy at its claimed hooks. It never silently lets an unowned or
   unrepresentable operation become an Allow.
2. In the direct-kernel phase, the custom path raises an event only before a
   lock-free safe wait. It supplies the operation, process, object or
   parent/name identity, mount/path context, and both sides of a two-object
   operation where needed.
3. Before commit, the direct path revalidates the approved object, parent, name,
   and operation. A mismatch fails with a documented error rather than using a
   stale approval.
4. A structural operation has one decision owner in each phase. The native LSM
   may remain registered, but it makes no structural policy decision or cache
   lookup for an operation once direct decisioning owns it. There is therefore
   no duplicate decision, unprotected hand-off, or static outcome that can
   bypass Filemaster.
5. The daemon exposes exact feature capability and degradation state. A profile
   or rule needing the direct path is unavailable or fails closed on an
   LSM-only-capable kernel; it never becomes an implicit static Allow.

## Final-scope feature work

| Feature family | Required targeted work beyond LSM only | Main proof obligation |
| --- | --- | --- |
| Shared permission foundation | Event ABI, wait/response/cancellation, failure policy, capability status, and commit-time revalidation | No VFS, inode, directory, or rename lock across a wait |
| LSM transition | Disable native-LSM structural decision ownership before the direct owner starts, without retaining a second policy store | No overlap, coverage gap, or false coverage at cutover |
| Open and listing | Read/Write request context, read-only downgrade, `O_TRUNC` cancellation, and one decision per directory open-file description | Returned descriptor and observed truncation behaviour |
| Create, delete, link, rename, replacement | Pre-lock source/destination context, atomic two-object approval, and revalidation | No rename/link replacement race or separate accidental approval |
| Truncate, metadata, range, clone/reflink | Safe VFS/ioctl decision points plus attribute, range, and two-file event context | Every relevant mutation path reaches the claimed decision |
| Metadata read and low-priority tail | Descriptor-free metadata identity, subtree suppression, write, dedupe, traversal retry, and listener self-exemption | Volume/performance, multi-destination semantics, and no lookup-path deadlock |
| Cross-cutting correctness | io_uring attribution, overlay/stacked filesystems, daemon crash, queue exhaustion, recursion, kernel updates, and VM adversarial tests | No bypass, deadlock, duplicate decision, or silent coverage loss |

The final scope is a planning target, not a promise: each feature is advertised
only after its hook, safe-wait, context, and revalidation proof passes.
Metadata-read subtree suppression and directory-traversal retry are feasibility
gates, not routine implementation items. Their failure can require a different
architecture and can exceed a later estimate.

## Build boundary

The reference work builds, boots, and tests the LSM-only interim phase and the
direct-kernel phase as distinct capability configurations. The final direct
phase does not retain the native LSM as a structural policy cache. This permits
the required decision points and data layout to be designed as one coherent
backend.

Distribution of those changes is intentionally outside the option. It must not
change the claimed operation coverage, decision semantics, or test obligations.
