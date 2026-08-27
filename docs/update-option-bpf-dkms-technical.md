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

## Where BPF can and cannot sit

The precise claim matters, because there is a plausible-sounding BPF design
that appears to defeat it. State it carefully:

- **BPF bytecode cannot wait.** There is no BPF primitive that suspends a task
  until userspace answers. BPF can push data out through a ring buffer; it
  cannot block for a reply, and the verifier will not accept an unbounded wait
  loop.
- **A BPF program *can* return the internal sentinel** the retry design uses.
  `bpf_lsm_get_retval_range()` gives non-bool, non-void LSM hooks the range
  `[-MAX_ERRNO, 0]`, so a value above 511 is legal from BPF.

### The sleepable-kfunc route

A custom kernel could export a `KF_SLEEPABLE` kfunc that performs the native
wait, and call it from a sleepable BPF LSM program. The mechanical parts of
that idea are real:

- The relevant hooks are sleepable. `sleepable_lsm_hooks` in
  `kernel/bpf/bpf_lsm.c` contains `bpf_lsm_path_unlink`, `bpf_lsm_path_rmdir`,
  `bpf_lsm_path_rename` and `bpf_lsm_path_link`, among others.
- BPF attach stubs are generated from the shared hook list. `bpf_lsm.c` expands
  `LSM_HOOK` over `<linux/lsm_hook_defs.h>` to emit a `__weak noinline
  bpf_lsm_##NAME` for every hook, so a **new** hook added by a custom kernel
  gets a BPF attach point and a BTF id automatically, with no extra BPF-side
  plumbing.
- `KF_SLEEPABLE` kfuncs may block and are callable from sleepable programs, so
  the wait itself would be ordinary native C reached from BPF.

None of that rescues a wait at the stock hooks, because **"sleepable" is not
"safe to block indefinitely"**. The comment above the set says exactly what it
means: these are the hooks "called without pagefaults disabled and are allowed
to 'sleep'". That is a statement about atomic context, not about VFS locks. At
`security_path_rmdir()` in `filename_rmdir()`, `start_dirop()` has already taken
the parent directory's `i_rwsem` for write via `inode_lock_nested(dir,
I_MUTEX_PARENT)`, and `mnt_want_write()` holds a mount write reference. An
untimed wait there — in a kfunc, in a native LSM, or anywhere else — stalls every
operation in that directory and blocks `fsfreeze` on that filesystem for as long
as the prompt is unanswered. Cross-directory `rename` adds
`s_vfs_rename_mutex`. This is the same trap TOMOYO caps at ten seconds; see
[Why the stock hooks cannot host the wait](update-option-lsm-dkms-technical.md#why-the-stock-hooks-cannot-host-the-wait).

So the kfunc idea removes a limitation that was never the binding one. The
binding constraint is **where** the wait happens, not **who** sleeps. It does
not follow that BPF has no place in stage two — see
[BPF LSM + DKMS as a distinct candidate](#bpf-lsm--dkms-as-a-distinct-candidate).
What follows is only that the wait cannot sit at the stock hooks. The
sentinel, the VFS unwind, the new post-unwind hook, and the `goto retry` are all
native changes to `fs/namei.c` and the security plumbing, in a custom kernel,
whatever calls the wait at the end.

### BPF LSM + DKMS as a distinct candidate

Given the custom kernel is being built anyway, the Filemaster side *could* be
BPF across all three passes, with native C supplying only the mechanism BPF
lacks. This is a coherent architecture, not a trampoline in front of a native
LSM, and it is retained as a **separate candidate**:

```
pass 1 — existing path_* BPF LSM hook
    stage the operation context in native Filemaster-owned state,
    return the internal sentinel
VFS  — unwind all locks, mount-write refs, first-pass path refs
post-unwind hook — sleepable BPF program -> KF_SLEEPABLE kfunc
    native C: transport to userspace, killable untimed wait, store verdict
VFS  — goto retry, re-resolve
pass 2 — existing path_* BPF LSM hook
    validate and consume the stored verdict, return Allow/Deny
```

Userspace remains the only policy engine in both candidates, so this is not a
question of where decisions are made. It is a question of whether a BPF
frontend avoids enough native work to pay for the BPF↔native interface.

#### The cost ledger

Native-LSM work avoided: a `struct lsm_id`, a `DEFINE_LSM()` blob,
`security_add_hooks()`, a Kconfig entry, LSM ordering. Real, but boilerplate.

Work added in its place: `__bpf_kfunc` definitions, `BTF_KFUNCS_START/END`,
`BTF_ID_FLAGS(func, ..., KF_SLEEPABLE)`, and `register_btf_kfunc_id_set(
BPF_PROG_TYPE_LSM, ...)`. On volume this is close to a wash.

One asymmetry runs against BPF. A **registered** LSM gets per-task blob storage
free — declare `lbs_task` and `lsm_task_alloc()` (`security/security.c`)
allocates it inside `security_task_alloc()`, with teardown on task exit. That is
exactly the cross-pass state this design needs, with correct fork/exit
lifecycle. A kfunc reached from a BPF attach stub is not a registered LSM and
has no blob, so it must build a task-keyed store and its own lifecycle by hand —
native code the native candidate does not write, in an area where bugs are
use-after-free on task exit.

In favour of BPF: the libbpf loader, skeleton generation, and attach lifecycle
carry over from stage one, and the kernel diff can stay generic — a hook plus an
"ask userspace and wait" kfunc with no Filemaster identity — which helps
upstreamability and narrows livepatch scope. That advantage is smaller than it
first appears, because the selected native LSM is *already* policy-free: it
forwards to the daemon and holds no policy snapshot. The difference narrows to
naming and a Kconfig symbol.

#### The question that decides it — P1 answer

**Does an untimed wait inside a `KF_SLEEPABLE` kfunc hold tasks-trace RCU?**

**Yes, confirmed from source on `v7.1`.** `__bpf_prog_enter_sleepable()` takes
`rcu_read_lock_trace()` before invoking the program and
`__bpf_prog_exit_sleepable()` releases it after, so a task parked in the kfunc
sits in a tasks-trace RCU read-side critical section for the entire prompt.

**But the predicted symptom did not occur.** The prediction was that BPF program
teardown would block machine-wide. It does not. With a prompt parked, a second
SSH session attached and detached an unrelated sleepable program in ~44 ms
(attach ~35 ms, link destruction ~9 ms), and detaching the in-flight
post-unwind program's own pinned link returned in ~7 ms.

**The reason is deferral, not absence.** `bpf_link_free()` routes sleepable
links through `call_rcu_tasks_trace()` — its own comment says it must "first
wait for RCU tasks trace sync, and then go through 'classic' RCU grace period".
The *command* returns immediately; the *reclamation* queues behind the parked
reader. So the measurement is real and the hazard is real, and neither
disproves the other.

What this leaves is a **deferred-reclamation backlog** rather than a stall:
while any prompt is parked, no tasks-trace grace period completes, so every
sleepable BPF program, map and trampoline freed during that window stays
allocated. Severity scales with BPF churn multiplied by prompt duration, and on
a long prompt the kernel will also emit `rcu_tasks_trace` stall warnings. That
is a lifecycle cost, not a correctness failure — materially less severe than
predicted, and still not nothing. It has no counterpart in the native design,
where the post-unwind hook holds nothing at all.

Unquantified, and the remaining work if this candidate is pursued: whether any
*synchronous* `synchronize_rcu_tasks_trace()` caller sits on a path that
matters. P1 exercised the deferred paths only.

#### BPF LSM + native wait

Naming note: this was previously called "the hybrid", which caused confusion.
Throughout these docs **BPF means BPF LSM** — BPF programs attached to LSM
hooks. There is no other kind of BPF here, and no candidate combines "BPF" with
"BPF LSM". The three stage-two candidates differ only in what runs where:

| Candidate | Interception at `path_*` | The wait |
|---|---|---|
| Native LSM + DKMS | Native LSM | Native LSM |
| **BPF LSM + native wait** | BPF LSM | Native LSM |
| BPF LSM + kfunc wait | BPF LSM | `KF_SLEEPABLE` kfunc called from BPF LSM |

This section covers the middle one.

P1 independently demonstrated all three pieces:

```
pass 1        — non-sleepable BPF at lsm/path_rmdir, returns the sentinel   [verified]
post-unwind   — native LSM at the generic ask hook, performs the wait       [verified]
pass 2        — non-sleepable BPF, validates and consumes the verdict       [verified in the Allow path]
```

Non-sleepable programs run under ordinary RCU and never park, so this avoids the
tasks-trace liability entirely.

**Measured against the stated product goal** — one BPF codebase, with the user
choosing whether to install the custom kernel — this and the full BPF variant
deliver the *same product*. On a stock kernel the programs run in report-only
mode; on the custom kernel they detect the extra hook and prompt. The BPF
codebase is one codebase in both. The difference is entirely inside the custom
kernel: whether the wait is performed by a registered LSM module or by a kfunc
called from a sleepable BPF program.

| Candidate | One BPF codebase | Tasks-trace cost | If BPF programs are absent |
|---|---|---|---|
| **BPF LSM + native wait** | Yes | **None** | Fails closed, deterministic (P1-verified `EIO`) |
| BPF LSM + kfunc wait | Yes | Yes, unmeasured | Fails closed (P1-verified) |
| Native LSM + DKMS | N/A — no BPF LSM at stage two | None | N/A |

The kfunc-wait variant's only advantage over this is skipping LSM registration boilerplate,
and it pays for that with the tasks-trace reclamation cost. Same BPF story,
worse kernel story.

The pure-native candidate is a different shape rather than a worse one, and it
is only penalised under one specific plan: if a stock-tier BPF backend is built
**and** kept in service **and** stage two is native, the project maintains two
interception implementations in parallel. If LSM + DKMS is custom-kernel-only
with no BPF tier, there is exactly one implementation and this whole section is
moot. Do not carry "native means two implementations" as a general claim; it is
conditional on the BPF tier existing.

Both variants still need the same native C — daemon transport, the wait, the
verdict store. Registration is not the module; it is the paperwork on top of it.
This candidate additionally gets `lbs_task` per-task storage free by being a
registered LSM, which the full BPF variant must build by hand.

**The question that decides one-codebase versus two.** Can a single BPF program
set serve both tiers via a feature-detected branch — if the running kernel
exposes the ask hook, return the sentinel and let the native side wait;
otherwise report and allow? BPF does this kind of capability detection
routinely. If yes, the goal is met exactly. If the two behaviours need
substantially different programs, the fallback is two closely-related program
sets with high reuse, which is a worse but still workable outcome. Settle this
during module sizing, concretely against the programs P1 actually wrote.

**Where the tiers actually sit.** Fanotify remains responsible for interactive
Open and File Execute in every plan, so an optional upgrade already exists
without BPF:

| Tier | Capability |
|---|---|
| Stock kernel, fanotify only — already built | Open and Execute prompting; no structural visibility |
| Stock kernel + BPF | Adds structural *visibility* (delete, rename, link), no prompting |
| Custom kernel | Adds structural *prompting* |

BPF's real contribution is the middle row. That is a decision on its own merits,
separate from how stage two is built — and if the stock BPF tier is not built,
candidates b and c do not arise and pure native wins by default.

**When this candidate does not apply.** If no stock-tier BPF backend is built,
there is no second BPF-served tier and the reasoning above is moot. An optional upgrade is a
nice-to-have, not a requirement, and that product decision is open. The relevant
unmeasured input is what a dual-tier product costs to run, and the natural unit
is **per kernel release**, not per year: rebasing the custom-kernel patches,
CO-RE/BTF breakage in the BPF programs, re-running a doubled test matrix, and
supporting two capability levels. That figure is an output of module sizing, not
an assumption to feed into it.

**What the P1 evidence supports regardless.** A non-sleepable BPF program can
return the sentinel at a stock `path_*` hook, and a non-sleepable program can
validate and consume a stored verdict on the second pass. Those facts hold
whichever candidate is chosen.

#### Two further obligations if it survives

1. **Two detachable programs, no atomic attach across them.** Pass 1 returning
   the sentinel and the post-unwind program converting it have separate
   lifecycles. Pass 1 attached with post-unwind missing gives `goto retry` with
   no progress — a soft lockup — or a fail-open if both are gone. The fix is
   cheap and belongs in the kernel, not in policy: `fs/namei.c` must swallow the
   sentinel unconditionally and bound the retry natively, so the kernel never
   depends on a program being attached. Prove it with the programs detached
   mid-flight.
2. **Revalidation wants to be in C.** Pass 2 must confirm the re-resolved
   operation is the one the user approved. That is the TOCTOU-critical step of
   the whole design; in a userspace-loadable, replaceable program it is a weaker
   position than compiled C. Moving it into the kfunc restores the guarantee but
   reduces pass 2 to a one-line BPF trampoline — which is a legitimate outcome,
   just not an argument for the BPF frontend.

#### Standing after P1

The candidate is **functional but not cleared**, which is where P1 was designed
to leave it. Two further facts from the run:

- With pass 1 attached and the post-unwind program absent, `rmdir` failed
  closed with `EIO` and raised no second prompt. Obligation 1 below is
  discharged for that case — the kernel did not depend on a program being
  attached.
- The BPF verifier rejected returning the kfunc's unconstrained `int` directly
  from an LSM program, since LSM return range is restricted to errno values.
  The experiment normalizes every nonzero kfunc result to fail-closed
  `-EACCES`. Any production version inherits that constraint.

No standing lean. The tasks-trace backlog counts against the full BPF variant,
whose offsetting saving is only the LSM registration boilerplate, not the
module; it still needs the synchronous-caller question answered. Against that,
offering an optional upgrade counts against pure native, which would then
maintain two interception implementations for the life of the product — but
whether an optional upgrade is offered at all is undecided. Under the stated
goal of one BPF codebase with an optional kernel install, the
[one-codebase candidate](#bpf-lsm--native-wait) is
strongest; it additionally turns on one testable technical assumption. Size all
three when the module is sized, and size the dual-tier maintenance burden
alongside them so the product question can be settled on numbers.

## The second stage is LSM + DKMS

The settled architecture for an interactive structural decision is
`VFS -> LSM -> filemaster -> decision`: the existing `path_*` hook returns an
internal sentinel, VFS unwinds through its own error paths and calls one new
generic security hook at a point where every lock, mount-write reference, and
path reference has been released, the Filemaster LSM waits there, and the
operation restarts as an ordinary second pass. Full description in
[LSM + DKMS technical](update-option-lsm-dkms-technical.md#the-unwind-and-retry-mechanism).

That is the same endpoint every route reaches, and it is not BPF-specific, so
**the second stage of this route is the LSM + DKMS backend**, built fresh, with
the BPF backend detached at cutover.

Two consequences worth stating plainly:

1. There is no separate "BPF-flavoured custom-kernel backend" to *cost*. The
   `fs/namei.c` sentinel, unwind, post-unwind hook and retry are identical
   whether the Filemaster side is a native LSM or a BPF frontend over a
   `KF_SLEEPABLE` kfunc. That choice is a live open question — see
   [BPF LSM + DKMS as a distinct candidate](#bpf-lsm--dkms-as-a-distinct-candidate)
   — but it sits inside stage two and does not create a second route or a second
   estimate.
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

Keeping the *stage-one* BPF programs in the picture at that point would also
need glue built purely to make them look reused: the verdict lives in the C
side's per-task storage, which BPF cannot read without a purpose-built kfunc or
a parallel BPF task-local-storage map. This is a separate question from whether
stage two's own new hook is driven from BPF — see
[BPF LSM + DKMS as a distinct candidate](#bpf-lsm--dkms-as-a-distinct-candidate).
The objection here is to two decision owners running at once, not to BPF as an
implementation detail of a single owner.

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

> **This premium framing assumes BPF is transitional — built, then discarded
> once the custom kernel exists.** That assumption is not settled. If the stock
> BPF tier turns out to be permanent, work you would do anyway is not a detour
> premium but a shipped deliverable, and the only genuine question becomes the
> incremental cost of adding the kernel change on top. The figures below are a
> valid answer to "what does staging cost if the first stage is thrown away",
> and an overstatement otherwise. Which applies is an open product decision;
> see [BPF LSM + native wait](#bpf-lsm--native-wait).
> Recount both readings alongside module sizing.

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
