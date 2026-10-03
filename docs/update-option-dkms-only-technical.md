# Update option: DKMS only

> Shared and DKMS-specific evaluation checks are in
> [Backend Test Requirements](backend-test-requirements-technical.md).
>
> Product behaviour is defined in
> [Backend Feature Requirements](backend-features.md). This document evaluates
> whether a DKMS-based implementation can deliver it safely.

This is the standalone DKMS-only option: a Linux kernel backend for Filemaster
delivered as a DKMS-built module, with no BPF or native LSM phase before it. It
is separate from the [+ DKMS route](update-option-+dkms.md), which starts with a
BPF or native LSM backend and later adds targeted kernel changes.

**Running on an unmodified distro kernel is the defining constraint of this
option**, not a preference. No custom kernel, no rebuilt kernel, no kernel
source change: the whole point is deployment on the kernel the user's
distribution already ships. An approach that requires a modified kernel has
left this option and belongs to + DKMS.

## Delivery approach

**Standalone enforcement module:** mediate the required VFS operations and
communicate with Filemaster's existing userspace policy and prompt pipeline.

Two constraints bind this hand-written hooking approach and should be settled
early:

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

## Technical goals

- Unmodified distro kernels only. This is the option's defining constraint, not
  a preference to be traded away: an approach that needs a custom or rebuilt
  kernel is out of scope here and belongs to + DKMS.
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
- Test against stock distro kernels throughout, since that is both the intended
  user environment and the option's constraint. A result that only holds on a
  modified kernel does not count here.
- Build adversarial tests for bypasses/races, not just happy paths.

Do not blindly follow my suggested implementation mechanism if kernel inspection
reveals a safer/cleaner approach. The hard requirements are the resulting
security semantics, DKMS-based deployment, no silent coverage degradation, and
safe interactive blocking. Unmodified-kernel deployment is a hard requirement
here, not a preference — an approach that gives it up has left this option.

Implement this incrementally, starting with a minimal end-to-end backend that
proves the first product requirements can be delivered safely:

1. separate Read/Write Open permissions;
2. frozen Delete;
3. frozen Rename with source and destination validation;
4. userspace Allow/Deny round-trip; and
5. automated QEMU testing.

Once those foundations are sound, extend coverage to the remaining operations.
