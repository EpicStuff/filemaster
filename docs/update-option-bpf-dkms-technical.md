# BPF then DKMS — technical note on upgrading from a BPF backend

> **Naming.** This option was previously called "BPF LSM + DKMS". The `+` was
> misleading: the second stage does not extend the BPF backend, it **replaces**
> it. The option is now described as **BPF then DKMS**. The file name is
> unchanged so existing links keep working.

> **Status: an upgrade path to consider later, not a committed plan.**
> [BPF LSM](update-option-bpf.md) is a backend that may remain the final
> choice. This note exists so that the upgrade, if it is ever taken, is
> understood in advance — not to schedule it.

## What the upgrade is

BPF LSM enforces statically on a stock kernel: for a BPF-owned structural
operation, only Allow proceeds and everything else denies, with an
[asynchronous denial notice and a user-driven retry](update-option-bpf-technical.md#decided-behaviour-deny-with-feedback).
Fanotify keeps the interactive Open and File Execute path in every phase.

Upgrading means adding what BPF structurally cannot do: an **interactive prompt
before a structural operation commits**, with an untimed wait. That requires a
targeted kernel change, which is what `+ DKMS` labels — see the
[+ DKMS overview](update-option-+dkms.md) for what that term does and does not
commit to. Delivery by custom-kernel build or by `klp-build`/livepatch remains
an open decision, and distribution of the change is outside this design.

## BPF cannot host the wait

This is structural, not a gap a newer kernel closes.

- There is no BPF primitive that suspends a task until userspace answers. BPF
  can push data out through a ring buffer; it cannot block for a reply, and the
  verifier will not accept an unbounded wait loop.
- A BPF program *can* return the internal sentinel the retry design uses —
  `bpf_lsm_get_retval_range()` permits any value in `[-MAX_ERRNO, 0]`, so a
  value above 511 is legal from BPF. But returning the sentinel is the easy
  half. The queue, correlation, untimed wait, verdict cache, and reply
  transport are C in every route.

So the interactive owner is a native C component, and BPF's role at that point
is over.

## The second stage is LSM + DKMS

The settled architecture for an interactive structural decision is
`VFS -> LSM -> filemaster -> decision`: the existing `path_*` hook returns an
internal sentinel, VFS unwinds through its own error paths and calls one new
generic security hook at a point where every lock, mount-write reference, and
path reference has been released, the Filemaster LSM waits there, and the
operation restarts as an ordinary second pass. Full description in
[LSM + DKMS technical](update-option-lsm-dkms-technical.md#the-unwind-and-retry-mechanism).

That is the same endpoint every route reaches. It is not BPF-specific and not
reachable from BPF, so **the second stage of this route is the LSM + DKMS
backend**, built fresh, with the BPF backend detached at cutover.

Two consequences worth stating plainly:

1. There is no separate "BPF-flavoured custom-kernel backend" to design. Cost,
   risk, and proof obligations for stage two are the LSM + DKMS ones.
2. Reaching it from BPF means also building the native LSM parts that
   [LSM only](update-option-lsm-only.md) would otherwise have established —
   registration, ordering, the privileged control channel, and the marked-scope
   store.

## No split decisions at the cutover

Do not keep BPF answering some structural decisions while the kernel path
answers the rest. A BPF map cache for "already-known" rules is not worth a
second policy store, its generation synchronisation, or its verifier and loader
lifecycle — especially when fanotify already carries the far more frequent Open
and Execute traffic, so the round trips avoided are only delete, rename, link
and similar.

Keeping BPF in the picture at that point would also need glue built purely to
make the BPF part look reused: the verdict lives in the C side's per-task
storage, which BPF cannot read without a purpose-built kfunc or a parallel BPF
task-local-storage map.

At cutover, for every operation the kernel path owns:

1. No BPF structural hook remains attached for that operation.
2. No stale BPF policy can permit it.
3. There is exactly one decision owner, with no arbitration, duplicate prompt,
   or unprotected hand-off.
4. Returning to the stock BPF phase is a deliberate capability transition, not
   a concurrent fallback.
5. On a stock kernel, a rule needing the interactive path is reported as
   unsupported or fails closed. It must never silently degrade to a BPF Allow.

## Cost of going via BPF

Two questions here are easy to confuse:

1. **Reuse.** Of the work done in the BPF stage, how much survives the cutover?
2. **Total route cost.** What does reaching the endpoint by way of BPF cost,
   against going straight there?

Question 2 is the better measure of waste. Question 1 rewards a first stage for
being groundwork, which is the opposite of what a first stage should be.

All figures below are soft: percentages and ratios applied to estimates whose
own confidence [the cost note](update-options-cost-technical.md) rates
low-to-medium until the outstanding P1s pass. Treat them as sizing, not budget.

### What carries across the cutover

Applied to the BPF line items in
[the cost note](update-options-cost-technical.md#bpf-lsm), at midpoint:

| BPF work | Mid LoC | Carried | Why |
|---|---:|---:|---|
| CO-RE object, hook allow-list, static enforcement | 275 | ~10% | Hook viability evidence carries. The programs do not. |
| Static-policy compiler and BPF map schema | 475 | ~30% | Superseded by daemon-side decisioning, as the LSM answer table is. Scope publication survives. |
| Daemon loader, capability probe, object packaging | 325 | ~15% | libbpf-specific. The capability-probe pattern carries; its implementation does not. |
| Snapshot update, lifecycle, health, degraded status | 400 | ~70% | Filemaster-side. |
| FileAccess/config/diagnostic integration | 275 | ~90% | Filemaster-side. |
| VM, build, packaging support | 200 | ~60% | VM fixtures carry; BPF packaging does not; custom-kernel build is new. |
| **Production** | **1,950** | **~45%** | |

Tests carry ~50%: the operation matrix, fail-closed matrix, VM fixtures, and
fanotify coexistence coverage survive; verifier, loader, and map coverage does
not.

| | Carried |
|---|---|
| Production (1,950 mid) | ~45% |
| Tests | ~50% |
| **Combined** | **~45–50%** |

Carries in detail: the product operation enum, the Go rule/profile compiler and
static outcome semantics, `FileAccess` lifecycle/health/status integration, the
operation and fail-closed test matrices, the VM fixtures, the fanotify
coexistence coverage, and the hook-viability evidence — including whether
`path_*` behaves as expected under bind mounts, overlayfs and
destination-overwrite rename, which stage two depends on and which
[the BPF phase can establish first](update-option-bpf-technical.md#the-path_-hook-family).

Does not carry: the BPF C programs, the CO-RE object and its packaging, the
libbpf loader, the map layout and generation-switch design, and the verifier,
loader and map tests.

### Reuse is the wrong metric

For comparison, LSM only into LSM + DKMS — derivation in
[LSM + DKMS technical](update-option-lsm-dkms-technical.md#how-much-of-lsm-only-survives):

| Route | Production | Tests | Combined |
|---|---|---|---|
| LSM only → LSM + DKMS | ~80% | ~55% | **~65–75%** |
| BPF → LSM + DKMS | ~45% | ~50% | **~45–50%** |

BPF scores lower, and that is a point in its favour, not against it.

LSM only scores 65–75% because much of it is scaffolding for stage two: kernel
build and packaging, LSM registration, the control channel, and the
marked-directory store all exist as much to enable stage two as to ship stage
one. Work counts as "reused" precisely when it was never standalone. BPF scores
~45–50% because it is a shippable backend in its own right — it enforces on a
stock Arch kernel, with no custom kernel and no risk that a bad kernel change
breaks the machine. Then it is replaced.

A first stage that scores 100% reuse would be one that shipped nothing.

### Staged versus direct

| Route | Stage one | Stage two |
|---|---|---|
| **Staged** | BPF backend on a stock kernel | Replace it with the LSM + DKMS backend |
| **Direct** | — | Build the LSM + DKMS backend only |

Both end identically, so stage two's cost is common to both and cancels. The
difference is exactly the BPF work that does not carry:

| | Mid LoC | Not carried |
|---|---:|---:|
| BPF production | 1,950 | ~1,080 |
| BPF tests | 2,800 | ~1,400 |

Not all of that is *extra* against the direct route, because the direct route
needs its own equivalents of the Filemaster-side lifecycle, config, and
publication work, and both routes supersede a kernel-side policy compiler under
the daemon-decides model. The genuinely BPF-specific, no-counterpart,
no-afterlife portion is smaller:

| BPF-only artifact | Extra LoC |
|---|---:|
| CO-RE object, programs, hook allow-list | ~250 |
| libbpf loader, object packaging | ~275 |
| BPF map schema beyond a generic scope table | ~150 |
| Verifier, loader, and map-specific tests | ~700–900 |
| **Detour premium** | **~1,400–1,600** |

Against the cost note's own ratios that is roughly **55–100M extra billed
tokens**, or a **10–20% premium** on a direct route the cost table puts at
510M–1.1 billion tokens.

### What the premium buys

- A working, enforcing backend after roughly 8–12 sessions and 120M–180M
  tokens, instead of nothing until the full custom-kernel product lands.
- Stage one carries **no kernel-crash or filesystem-corruption risk**, because
  it changes no kernel code. That directly serves the stated reason for
  preferring a staged route.
- The hook viability evidence, operation matrix, and VM corpus that stage two
  depends on are produced and proven before any kernel is modified.

A 10–20% premium to de-risk the whole project and hold something shippable
three to four times sooner is, on these numbers, clearly worth paying. The
figure to revisit is the direct route's 510M–1.1B band, which the cost note
marks provisional and which may model a broader standalone backend than this
endpoint.

### Sources of error

1. Both reuse percentages are per-item judgement, not measurement.
2. The stage-two cost is unestimated pending the `rmdir`/`unlink`/`rename` P1s,
   so it is assumed equal across routes rather than known to be.
3. The direct route's band is provisional and may cover a wider scope than the
   shared endpoint described here, which would overstate the premium's
   denominator and understate the premium's percentage.
4. Line counts are a poor proxy for custom-kernel difficulty. The cost note's
   own token-per-line ratio is far higher for kernel work than for BPF or
   daemon work, which is why the premium is quoted in tokens as well as lines.

## Proof obligations for the upgrade

1. Prove the BPF backend independently on its stock-kernel scope, including
   lifecycle and fail-closed behaviour, before any kernel change.
2. Meet the
   [LSM + DKMS requirements](backend-test-requirements-technical.md#lsm--dkms-specific-requirements)
   for stage two in full. They are not reduced by having come from BPF.
3. Prove the cutover: no BPF structural hook attached for an operation the
   kernel path owns, no coverage gap or overlap in either direction, and no
   stale BPF policy claim.
4. Build, boot and test the kernel path on one custom kernel; test the BPF
   backend separately on its stock-kernel scope. Do not run them against the
   same operation concurrently to make the migration look seamless — a
   disagreement produces either a duplicate decision or a hidden gap.

## Superseded model

Earlier versions of this note described stage two as a custom kernel that
directly owns request creation, the wait/cancellation lifecycle, the userspace
reply, and commit-time revalidation, with Filemaster reached from VFS without a
native LSM in between. That model is superseded: it puts Filemaster policy and
permission transport inside VFS, which the selected architecture rejects. The
wait belongs to the LSM, and the "revalidation before commit" step is replaced
by the ordinary second pass, which re-resolves and re-locks normally and
enforces the cached verdict only when operation, parent, name, target identity,
mount and generation all still match.

The corresponding cost figures are marked superseded in
[the cost note](update-options-cost-technical.md#bpf-lsm-then-dkms).
