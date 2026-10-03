# Backend option cost estimates — technical detail

Working detail behind [Backend option cost estimates](update-options-cost.md).
Every figure here is a model output, not a measurement, except where marked
*measured*.

## Baseline: Portmaster → Filemaster

*Measured* from the repository on 2026-08-16, from the fork commit
`f621feb0 fork: strip network stack and SPN` (2026-06-11) to `f0386ab7`
(2026-08-13):

| | |
|---|---|
| Commits | 186 |
| Days with commits | 21 |
| Commits touching `service/fileaccess` | 93 |
| Commits touching `desktop/angular` | 43 |
| `service/fileaccess` + `service/filequery`, production | 10,598 lines |
| `service/fileaccess` + `service/filequery`, tests | 9,415 lines |
| `cmds/`, production | 2,133 lines |
| `desktop/angular/src`, excluding specs | 32,760 lines |
| `docs/` | 2,381 lines |
| Gross churn, excluding lockfiles, assets, vendored | +443,622 / −304,100 |

Two of these need qualifying:

- **The churn figure overstates the work.** Its `.h` column is
  +126,928/−126,928 — a pure file move — and most of the 149k deleted Go lines
  are the network-stack strip, which costs far less per line than writing new
  code.
- **The Angular total is mostly inherited.** `desktop/angular/src` is largely
  upstream Portmaster code the fork never touched; only the 43 Angular commits
  represent fork work.

Netting those out, production code written for the fork — excluding tests and
docs — is roughly **20,000 lines**: 10,598 measured in the core packages, plus
the Angular changes, `cmds/` tooling, and module wiring.

The 60–90-session baseline is a planning judgment informed by the 186-commit
history and an assumed 2–4 commits per working session. It is not derived by
dividing production lines by a fixed rate; code and test scope are cross-checks,
while each option's session band is selected separately for its kernel, VM, and
integration uncertainty.

| | |
|---|---|
| Sessions | 60–90 |
| Billed tokens | 900M–1.3B |
| Cost | $1,600–2,400 |
| Widened for stated ±2× uncertainty | 450M–2.6B, $800–4,800 |

Only the repository counts above are measured. Session, token, and currency
figures are inferred planning estimates; no session log or billing export was
used.

About **$9–13 per commit**, or ~45–65k tokens per surviving line.

## Second fanotify group — dropped

> **Dropped.** Moved to [dropped/](dropped/update-option-2ndfanotify.md). The
> figures below are retained because they are the only sizing evidence for
> FID/TLV parsing, path reconstruction from directory handles, and per-fsid mark
> management — all of which resurface in any fanotify-endpoint costing.


Scoped to the design settled in
[dropped/update-option-2ndfanotify.md](dropped/update-option-2ndfanotify.md): origin-only
overrides, unknown-origin handling for first hard links, move classification
evaluated as Open on effective source and destination, and refuse-to-start on
unsupported filesystems.

| Piece | Production LoC |
|---|---|
| Second NOTIF group: init, poll loop, lifecycle, shutdown | 250–300 |
| FID/TLV parsing (info headers, fsid, `file_handle`, dfid+name, target FID) | 200–250 |
| Path reconstruction from directory handles | 150–250 |
| Per-fsid filesystem marks, scope filtering, startup capability probe | 250–350 |
| Mover identification and profile resolution at notify time | 100–150 |
| Effective source/destination Open policy evaluation | 60–100 |
| Override store: origin/unknown state, persistence, cap, clearing | 250–400 |
| Decision integration: `name_to_handle_at`, origin-only rewrite | 150–200 |
| Folder-subtree ancestor resolution | 100–150 |
| Drain barrier before answering a permission event | 150–250 |
| Overflow handling, diagnostics | 100–150 |
| **Production total** | **1,750–2,550** |

`service/fileaccess` and `service/filequery` currently run 9,415 test lines to
10,598 production lines, a ratio of 0.89:1. This feature skews well above that —
kernel ABI parsing, races, and VM integration tests need more coverage per line —
so 1.3–1.6× applies.

| | Low | High |
|---|---|---|
| Production | 1,750 | 2,550 |
| Tests | 2,300 | 4,100 |
| **Total including tests** | **4,050** | **6,650** |

| | |
|---|---|
| Sessions | 9–12 |
| Billed tokens | 130M–175M |
| Cost | $250–350 expected, $200–500 realistic ceiling |

### Relative scale

The second fanotify group is roughly one tenth of the fork's production code
(~2,000 lines against ~20,000), but about one seventh of its session and token
work (9–12 sessions against 60–90).

The session ratio is more trustworthy than either absolute figure, because both
come from the same session model: errors in the per-session cost largely cancel.

### Why the ratio is not a difficulty ratio

Most of the work already done had a known shape: deletion, `service/filequery`
ported from `service/netquery` under an explicit copy-with-minimal-changes
mandate, Angular work in an established framework with a screenshot loop for
immediate feedback, and a fanotify source built over 93 commits where each phase
was testable on its own.

Two pieces of the second group are not like that:

- **FID/TLV parsing** — variable-length records parsed with `unsafe` against a
  kernel ABI `x/sys` provides no struct for. Wrong offsets produce silently
  wrong data, not a crash.
- **The drain barrier** — a second reader goroutine must catch up while the
  kernel blocks a process in `open()` with no timeout.

Neither is meaningfully testable until both exist, and both need real kernel
events in the dev VM rather than the fake sources the current tests use. Expect
a disproportionate share of the debugging here.

## BPF LSM

> **Superseded 2026-10-03** by
> [BPF LSM re-costed as a Cordon port](#bpf-lsm-re-costed-as-a-cordon-port-2026-10-03):
> 8.5–11.5 sessions / ~125–170M per the [implementation plan](bpf-lsm-implementation-plan-technical.md), including the combined process-labelling design. The table below is the from-scratch C/libbpf
> estimate.

[BPF LSM](update-option-bpf.md) is a separate static-enforcement option.
Fanotify remains the sole owner of interactive Open and Execute decisions. BPF
LSM initially handles only structural operations fanotify cannot deny; it does
not attach an Open hook in the initial design.

For a BPF-owned operation, Ask, no matching static policy, an unsupported
operation, or an unrepresentable policy case is a deny. A BPF LSM program cannot
use the existing Filemaster prompt flow or wait for a userspace decision.

The first target-kernel hook proof passes for `inode_unlink`, `inode_rmdir`,
`inode_link`, and `inode_rename`. Its exact evidence and deliberately narrow
scope are in [BPF LSM update option — technical proof](update-option-bpf-technical.md).

The estimate below is for a first production backend limited to those four
static hooks. It includes resolving one safe Filemaster policy identity,
service lifecycle/status, and coexistence with fanotify's Open and File Execute
path. It excludes any operation whose hook/context has not passed its own
proof, and it must be redone if the identity work needs kernel changes.

| Piece | Production LoC |
|---|---:|
| CO-RE BPF object, hook allow-list, static enforcement | 200–350 |
| Static-policy compiler and BPF map schema | 350–600 |
| Daemon loader, capability probe, object packaging | 250–400 |
| Snapshot update, lifecycle, health, degraded coverage status | 300–500 |
| FileAccess/config/diagnostic integration | 200–350 |
| VM, build, and packaging support | 150–250 |
| **Production total** | **1,450–2,450** |

| | Low | High |
|---|---:|---:|
| Production | 1,450 | 2,450 |
| Tests | 2,050 | 3,550 |
| **Total including tests** | **3,500** | **6,000** |

| | Estimate |
|---|---|
| Sessions | **8–12** |
| Billed tokens | **120M–180M** |
| Cost at the session model | **$220–350** |

The 824-line VM proof is not counted as production code. Keep it as a
target-kernel regression fixture; it removed uncertainty about the four hooks,
but not about identity, atomic multi-map publication, or daemon-crash behavior.
The estimate confidence is low-to-medium until those three P1s pass.

## LSM only

[LSM only](dropped/update-option-lsm-only.md) is a native LSM built into a custom
kernel and restricted to existing hooks. It is a static-enforcement route: it
does not claim an interactive prompt at an LSM hook. The BPF proof supplies
evidence for four candidate hook locations, but a native LSM still needs its
own kernel answer table, userspace control plane, bootable custom-kernel path,
and safety proof. See the [LSM-only technical note](dropped/update-option-lsm-only-technical.md).

The kernel side is a lookup table of decisions the daemon already made, not a
matcher. That is why the evaluation row below is modest: rule matching,
profiles, and precedence stay in the daemon and are already counted against
existing Filemaster work.

The direct estimate uses the same four-hook static scope as BPF. It excludes
LSM + DKMS changes, new hook placement, or richer context.

| Piece | Production LoC |
|---|---:|
| Built-in LSM registration, Kconfig, and hook implementation | 250–450 |
| Kernel answer table, safe snapshot lifetime, control interface | 500–850 |
| Identity derivation, table lookup, and operation coverage status | 300–550 |
| Daemon policy writer, lifecycle, and diagnostics | 300–500 |
| Custom Arch kernel build, packaging, and VM support | 250–450 |
| FileAccess/config integration | 200–350 |
| **Production total** | **1,800–3,150** |

| | Low | High |
|---|---:|---:|
| Production | 1,800 | 3,150 |
| Tests | 2,700 | 4,800 |
| **Total including tests** | **4,500** | **7,950** |

| | Estimate |
|---|---|
| Sessions | **11–17** |
| Billed tokens | **160M–250M** |
| Cost at the session model | **$300–460** |

Native code is less verifier-constrained but does not eliminate the missing
hook context. Its extra cost over BPF is primarily the custom-kernel policy
transport, memory-lifetime work, and boot/package test loop. Confidence is low
until the four-hook native proof and policy-control P1 pass.

The test band is deliberately about 1.5× production, above BPF's ~1.4×:
native table publication, writer/control failure, boot/LSM-order checks, and
the custom-kernel VM loop need their own proof rather than inheriting BPF
loader coverage.

Roughly 65–75% of this work carries forward into LSM + DKMS — nearer 80% of
production, nearer 55% of tests. Note that a high reuse score partly reflects
how much of this stage is groundwork rather than shipped capability; see
[Reuse is the wrong metric](update-option-bpf-dkms-technical.md#reuse-is-the-wrong-metric).
The per-item derivation is in
[How much of LSM only survives](update-option-lsm-dkms-technical.md#how-much-of-lsm-only-survives).

## BPF LSM → LSM only

This is the incremental cost after the BPF backend above is complete and its
shared rule compiler, lifecycle contract, VM corpus, and operation matrix have
been kept backend-neutral. It is not the cost of running both backends forever.

| Piece | Additional production LoC |
|---|---:|
| Native hook implementation and LSM registration | 250–400 |
| Kernel policy store and control interface | 350–600 |
| Custom-kernel packaging and native health integration | 200–350 |
| Cutover adapter, differential tests, and removal of BPF-specific plumbing | 200–350 |
| **Additional production total** | **1,000–1,700** |

| | Low | High |
|---|---:|---:|
| Additional production | 1,000 | 1,700 |
| Additional tests | 1,400 | 2,500 |
| **Additional total including tests** | **2,400** | **4,200** |

| | Estimate |
|---|---|
| Additional sessions | **6–10** |
| Additional billed tokens | **90M–150M** |
| Additional cost at the session model | **$160–270** |

The migration reuses the completed BPF corpus and VM harness, but still needs
new native policy-publication, reboot, failed-update, and differential-cutover
tests. The BPF-first route therefore totals roughly 14–22 sessions and
210M–330M billed tokens if it later migrates. It costs more than starting LSM
only, but it delivers a lower-kernel-risk static backend first and keeps open
the option to stop there. The migration discount disappears if BPF policy
compilation is coupled to BPF map layout or if native LSM needs context
unavailable at the same hooks.

## BPF LSM then DKMS

Formerly "BPF LSM + DKMS". Stage two replaces the BPF backend rather than
extending it, and stage two is the LSM + DKMS backend; see
[BPF LSM then DKMS](update-option-bpf-dkms-technical.md).

This is **only** the later kernel-change phase after a completed BPF LSM
backend. It does not include BPF LSM's 1,450–2,450 production lines, its
120M–180M-token estimate, or a BPF LSM → LSM-only migration.

> **Re-estimate pending.** The figures below predate the selected
> unwind-and-retry architecture, in which the LSM owns the wait and the daemon
> owns all rule evaluation. That architecture applies here identically, so this
> section inherits the [LSM + DKMS](#lsm--dkms) re-estimate and the same
> expected direction: materially lower. Treat the numbers below as an upper
> bound until the `rmdir`/`unlink`/`rename` P1 lands.

The kernel path owns each structural-operation decision. It therefore removes
the former custom BPF dispatcher, BTF/version contract, verifier work, and
permanent BPF policy cache. It still includes the all-feature planning scope:
safe waits and revalidation; Open read/write context, read-only downgrade, and
O_TRUNC cancellation; listing; namespace mutation; truncate, metadata, range,
and clone/reflink; metadata reads; the low-priority tail; and adversarial
coverage.

### Current incremental targeted-kernel estimate

| Piece | Added production LoC |
|---|---:|
| Permission-event, wait/cancel, revalidation, response, and failure foundation | 1,200–1,900 |
| VFS hooks and event context for the listed operation families | 1,300–2,100 |
| BPF detachment, direct-mode capability status, and no-gap/no-overlap cutover | 250–450 |
| Filemaster event ABI, rule/prompt/response/status integration | 700–1,100 |
| One custom-kernel build, diagnostics, and VM harness | 350–750 |
| **Added production total** | **3,800–6,300** |

| Test area | Added test LoC |
|---|---:|
| Kernel/VFS/revalidation matrix | 1,800–3,000 |
| Userspace rule and response matrix | 900–1,400 |
| Lifecycle, queue, io_uring, overlay, and adversarial coverage | 1,800–3,100 |
| Stock/direct cutover, detachment, capability, and differential coverage | 600–1,100 |
| **Added tests total** | **5,100–8,600** |

| | Estimate |
|---|---|
| Added sessions | **23–35** |
| Added billed tokens | **335M–510M** |
| Added cost at the session model | **$620–945** |

This excludes the BPF-first phase, added-kernel distribution, and the separate
second-fanotify origin-tracking option. Metadata-read subtree suppression and
directory-traversal retry remain feasibility gates; a redesign lies outside this
range.

The route uses BPF as a stock-kernel backend, then replaces it with the
LSM + DKMS backend once a targeted kernel change exists. BPF bytecode cannot host an
untimed wait, so it has no role in the interactive stage; the option is
"BPF LSM then DKMS", not "BPF + DKMS". See the
[technical note](update-option-bpf-dkms-technical.md) and, for what carries
across the cutover (~45% production, ~50% tests),
[Cost of going via BPF](update-option-bpf-dkms-technical.md#cost-of-going-via-bpf).

The previous model covers an attempt to implement every currently listed
Filemaster feature family: the BPF static base; lock-free permission waits and
final revalidation; Open read/write context and read-only downgrade; listing;
namespace mutation; truncate, metadata, range, clone/reflink; metadata reads;
the low-priority write, dedupe, traversal, and self-exemption tail; plus
io_uring, overlay, lifecycle, and adversarial VM coverage. It is a planning
scope, not a claim that every feature has passed its feasibility gate.

Its baseline is one custom kernel containing the extension support and targeted
changes, alongside the portable BPF core. Distribution of those changes is
outside that estimate. The separate second-fanotify origin-tracking option is
also excluded unless a later design explicitly merges that work.

> **Superseded architecture.** The figures below model a permanent BPF
> static-policy layer and a custom BPF dispatcher. They are retained as the
> previous model, not as an estimate for the current direct-kernel design.

### Superseded targeted-kernel work after BPF (permanent-BPF model)

| Piece | Additional production LoC |
|---|---:|
| Custom BPF-extension ABI/dispatcher, BTF/version contract, and custom-only programs | 650–1,100 |
| Permission-event, wait/cancel, revalidation, response, and failure foundation | 1,200–1,900 |
| VFS hooks and event context for the listed operation families | 1,300–2,100 |
| Static-BPF/custom-path arbitration, identity, stock/custom fallback, and capability reporting | 450–750 |
| Filemaster event ABI, rule/prompt/response/status integration | 600–1,000 |
| Custom-kernel build, diagnostics, and VM harness | 400–750 |
| **Additional production total** | **4,600–7,600** |

| Test area | Additional test LoC |
|---|---:|
| Kernel/VFS/revalidation matrix | 1,800–3,000 |
| Userspace rule and response matrix | 900–1,400 |
| Lifecycle, queue, io_uring, overlay, and adversarial coverage | 1,800–3,100 |
| BPF extension ABI/version and stock/custom differential coverage | 1,300–2,300 |
| **Additional tests total** | **5,800–9,800** |

| | Estimate |
|---|---|
| Additional sessions | **27–40** |
| Additional billed tokens | **395M–590M** |
| Additional cost at the session model | **$730–1,100** |

### Superseded full BPF-first custom-kernel product

| | Low | High |
|---|---:|---:|
| BPF LSM production | 1,450 | 2,450 |
| Added targeted-kernel production | 4,600 | 7,600 |
| **Final production** | **6,050** | **10,050** |
| BPF LSM tests | 2,050 | 3,550 |
| Added targeted-kernel tests | 5,800 | 9,800 |
| **Final tests** | **7,850** | **13,350** |
| **Final code including tests** | **13,900** | **23,400** |

| | Estimate |
|---|---|
| Sessions | **35–52** |
| Billed tokens | **515M–770M** |
| Cost at the session model | **$950–1,450** |

Under the superseded design, the final BPF-first route was roughly the same cost
class as the former LSM direct-owner model, and could be slightly higher. BPF
avoids the native-LSM policy store, but adds the custom BPF dispatcher/ABI,
verifier/CO-RE/BTF compatibility, stock/custom lifecycle split, and differential
tests. This is not a cost comparison with the selected
[LSM-owned permission bridge](update-option-lsm-dkms-technical.md).

Those assumptions do not apply to the current direct-kernel route: it has no
custom BPF dispatcher or BPF verifier/BTF work in the final phase. Re-estimate
temporary BPF work and final direct-kernel work separately. Metadata-read
subtree suppression and directory-traversal retry remain separate feasibility
gates and can still exceed the eventual range.

## LSM + DKMS

The selected route is the later targeted-kernel phase after a completed
LSM-only backend. It does not include LSM only's 1,800–3,150 production lines
or its 160M–250M-token estimate.

Unlike the BPF direct-owner route, the selected LSM route keeps the native
LSM in the structural-operation path. The existing `path_*` hook returns an
internal sentinel; VFS unwinds through its existing error paths and calls one
new generic security hook at the point where nothing is held; the LSM waits
there and VFS restarts the operation. The LSM owns the request/wait/reply
lifecycle. It does **not** hold a policy snapshot — in this phase it forwards
to the daemon and enforces the answer. VFS owns only the sentinel check, the
retry hook call, and the `goto retry`, not a second Filemaster policy path.

### Superseded direct-owner estimate

| Piece | Added production LoC |
|---|---:|
| Permission-event, wait/cancel, revalidation, response, and failure foundation | 1,200–1,900 |
| VFS hooks and event context for the listed operation families | 1,300–2,100 |
| Native-LSM handoff, direct-mode capability status, and no-gap/no-overlap cutover | 200–350 |
| Filemaster event ABI, rule/prompt/response/status integration | 700–1,100 |
| One custom-kernel build, diagnostics, and VM harness | 400–750 |
| **Added production total** | **3,800–6,200** |

| Test area | Added test LoC |
|---|---:|
| Kernel/VFS/revalidation matrix | 1,800–3,000 |
| Userspace rule and response matrix | 900–1,400 |
| Lifecycle, queue, io_uring, overlay, and adversarial coverage | 1,800–3,100 |
| LSM-only/direct capability, cutover, and differential coverage | 500–1,400 |
| **Added tests total** | **5,000–8,900** |

| | Estimate |
|---|---|
| Added sessions | **24–35** |
| Added billed tokens | **350M–510M** |
| Added cost at the session model | **$650–945** |

These figures describe the **former** direct-owner topology only. They exclude
the LSM-only phase, added-kernel distribution, and the separate second-fanotify
origin-tracking option. They must not be used to choose or size the selected
native-LSM permission-bridge architecture.

The selected [LSM + DKMS technical route](update-option-lsm-dkms-technical.md)
uses a native LSM first for static enforcement and retains that LSM after the
targeted change. The new generic hook invokes the LSM; it does not send
structural decisions directly to Filemaster. The LSM queues and waits, and the
daemon decides.

A new estimate follows only after the `unlink`/`rmdir` and `rename` P1s measure
the actual sentinel, retry-hook, and transport diff. The eventual scope remains
operation-by-operation: a feature is not counted as delivered merely because
another operation's unwind-and-retry succeeded.

Direction of the change, pending that measurement. Against the superseded
direct-owner tables above:

| Line item | Direction | Reason |
|---|---|---|
| VFS hooks and event context | **Down sharply** | No new hook family and no copied context struct. Per operation the VFS diff is a sentinel check, one generic call, and a `goto retry`, in the idiom `retry_estale` already uses. |
| Permission-event, wait/cancel, revalidation, response foundation | **Down** | Revalidation is no longer bespoke code: pass two is an ordinary VFS pass. The verdict cache and key match replace it. |
| Native-LSM handoff and cutover | **Down** | Hook adapters are reused rather than gated off, so there is no dual-decision transition to manage per operation. |
| Kernel policy store port | **Removed** | The phase-two LSM holds no rules. This is also a reuse loss: the LSM-only policy store is used in its own phase but not carried forward. |
| Scope marks | **New, small** | Kernel-side subtree filter so unwatched paths raise no event. |
| Kernel/VFS test matrix | **Roughly flat** | Smaller diff, but new obligations: sentinel containment, one-ask-retry bound, LSM stacking and audit duplication, and doubled-resolution performance. |

The net expectation is a materially lower figure than the 3,800–6,200
superseded production range, driven mostly by the VFS and revalidation rows.
Do not quote a number until P1 measures one.

### P1 measured the kernel portion (2026-08-27)

The `rmdir` P1 ran on Linux `v7.1` in the dev VM and the design held. Full
report and evidence bundle: [P1 `rmdir` unwind-and-retry proof](p1-rmdir-technical.md)
and `/root/vm/share/lsm-p1/`.

**Measured**, by applying the patch series against the tag with
`git apply --cached --check`:

| Area | Diffstat | One-time or per-operation |
|---|---:|---|
| `fs/namei.c` (`rmdir`) | +16 / −1 | Per operation |
| Generic security hook plumbing (`errno.h`, LSM hook definition, `security.h`, `security/security.c`) | +38 | One-time, serves every operation |
| BPF sleepable-hook set | +1 | One-time, only if the BPF candidate is pursued |
| Filemaster stub LSM | +593 / −1 | **Scaffolding, not a production figure** |
| Total | +648 / −2, 12 files | |

The `fs/namei.c` number is the one that matters, and it is small for the reason
the design predicted: it reuses the existing failure and unwind labels instead
of duplicating resolution or lock handling. **The custom-kernel modification is
no longer the expensive or risky part of this backend.**

**Extrapolation, not measured.** `rmdir` is the cheapest operation because
`break_deleg_wait()` already sat at the fully released point. `unlink` and
`rename` must move the wait out one level; `link` needs a small restructure to
release `old_path` first. Scaling the measured 16 accordingly:

| Operation | Expected `fs/namei.c` lines |
|---|---:|
| `rmdir` | 16 (measured) |
| `unlink` | ~25–40 |
| `rename` | ~25–40 |
| `link` | ~40–60 |
| Plus one-time hook plumbing | 38 |
| **Custom-kernel diff, four operations** | **~145–195** |

That is the whole targeted-kernel change. It replaces the superseded model's
kernel rows outright.

**Still unmeasured, and now the dominant term.** P1's 593-line stub is a
securityfs experiment, not a daemon protocol — the report says so explicitly.
The production Filemaster LSM still has to carry the real daemon transport, the
verdict cache and its identity revalidation, the four-operation matrix, scope
marks, and the fail-closed matrix. That module, plus its daemon side, is now
essentially the entire cost of this backend, and P1 was not scoped to size it.

So the guidance changes shape rather than resolving: the kernel-change figure
can be quoted, the module figure still cannot. A second measurement pass on the
module is what would close this row.

#### Confirmed and corrected by P1

- **Confirmed.** `break_deleg_wait()` follows the ordinary `rmdir` unwind on
  `v7.1`, after `end_dirop()`, `mnt_drop_write()` and `path_put()`.
- **Corrected.** The line references cited in the design doc had drifted, and
  the branch is conditional on a delegated inode, so the new wait is placed
  after that branch rather than reusing it.
- **Confirmed.** Lock freedom is real, not theoretical: a same-superblock
  cross-directory `rename` and an `fsfreeze` both completed while a prompt was
  parked.
- **Confirmed.** Second-pass semantics are ordinary VFS: an Allow on a nonempty
  directory returned `ENOTEMPTY` rather than treating the first-pass decision as
  the result. This is the revalidation row's "down" direction holding up.

> **Older superseded model.** The figures below model a different permanent
> native-LSM/custom arbitration design. They are retained only as historical
> context, not as an estimate for the selected LSM-owned permission bridge.

### Superseded targeted-kernel work after LSM only

| Piece | Additional production LoC |
|---|---:|
| Permission-event, wait/cancel, revalidation, response, and failure foundation | 1,200–1,900 |
| VFS hooks and event context for the listed operation families | 1,300–2,100 |
| LSM/extension arbitration, static fallback, identity, and capability reporting | 400–650 |
| Filemaster event ABI, rule/prompt/response/status integration | 700–1,100 |
| Custom-kernel build, packaging, and VM harness | 400–750 |
| **Additional production total** | **4,000–6,500** |

| Test area | Additional test LoC |
|---|---:|
| Kernel/VFS/revalidation matrix | 1,800–3,000 |
| Userspace rule and response matrix | 900–1,400 |
| Lifecycle, queue, io_uring, overlay, and adversarial coverage | 1,800–3,100 |
| Packaging, upgrade, and differential coverage | 1,000–2,000 |
| **Additional tests total** | **5,500–9,500** |

| | Estimate |
|---|---|
| Additional sessions | **24–36** |
| Additional billed tokens | **350M–526M** |
| Additional cost at the session model | **$650–975** |

### Superseded full custom-kernel product

| | Low | High |
|---|---:|---:|
| Native LSM-only production | 1,800 | 3,150 |
| Added targeted-kernel production | 4,000 | 6,500 |
| **Final production** | **5,800** | **9,650** |
| Native LSM-only tests | 2,300 | 4,000 |
| Added targeted-kernel tests | 5,500 | 9,500 |
| **Final tests** | **7,800** | **13,500** |
| **Final code including tests** | **13,600** | **23,150** |

| | Estimate |
|---|---|
| Sessions | **34–51** |
| Billed tokens | **496M–745M** (rounded: **500M–750M**) |
| Cost at the session model | **$918–1,377** (rounded: **$900–1,400**) |

The high end in the older model is driven by the safe wait/revalidation
foundation, two-object namespace operations, read-only Open conversion,
metadata-read subtree suppression, traversal retry, write/dedupe tail work, and
LSM/custom-path arbitration. The selected route replaces that topology with
the LSM-owned permission bridge and needs a P1-based estimate. Metadata-read
suppression and traversal retry remain feasibility gates; a redesign can exceed
a later range.

## DKMS only — generated livepatch (route deleted 2026-08-30)

> **This route is deleted. The figures below are retained as a record only and
> must not be quoted as the cost of DKMS only.** Two independent reasons:
>
> 1. **Verified by running it (2026-08-17,
>    `/root/vm/share/fanotify/route3-poc/`).** Both stock Arch kernels tested —
>    `7.1.8-arch1-3` and `6.18.44-1-lts` — have `CONFIG_LIVEPATCH` unset, and
>    distro headers do not supply the exact source `klp-build` requires.
> 2. **Verified from source (v7.1).** Livepatch cannot resize a struct that
>    running code already holds, and `__init` code is not livepatch-able
>    (`Documentation/livepatch/callbacks.rst:125`; `DEFINE_LSM` places
>    `struct lsm_info` in `.lsm_info.init`, `include/linux/lsm_hooks.h:187`).
>    So generated livepatch can carry neither the fanotify-extension design
>    (needs wider fsnotify records) nor the LSM design (cannot register an LSM
>    at runtime). It is a delivery mechanism with no design left to deliver.
>
> The surviving DKMS-only approach is the hand-written standalone enforcement
> module. It is **not costed** — see
> [update-option-dkms-only-technical.md](update-option-dkms-only-technical.md).

The generated-livepatch kernel patch and a complete standalone Filemaster
backend have different scopes, so they are estimated separately. The kernel
patch is not directly comparable with the other option rows: it does not
include Filemaster's new event source, transport/protocol, richer event and
response model, rule/prompt/status integration, or related lifecycle work.

### Generated-livepatch kernel patch only

This estimated only the ordinary kernel source patch maintained for the deleted
generated-livepatch route,
from which in-tree `klp-build` generates a loadable module. It excludes the
generated module, Filemaster userspace integration, and test lines.

| | Estimate |
|---|---|
| Clean kernel-patch design | 2,200–3,100 lines |
| Kernel patch, including debugging residue | **2,500–3,600 lines** |
| Session equivalent at the session model | **27–62** |
| Billed tokens, no-surprises band | **400M–900M** |
| Cost at the session model | **$740–1,670** |

The token band includes ordinary kernel debugging: roughly 10% source/design
reading, 20% first draft, 25% compile and `klp-build` iteration, 35% runtime
debugging, and 10% tests and flake chasing. It is not a complete product
estimate merely because it contains some kernel-side tests.

### Provisional full standalone Filemaster backend

Had the generated-livepatch route passed its feasibility gates, a
scope-comparable standalone backend
also needs Filemaster userspace work and end-to-end test coverage. This is a
planning estimate, not a commitment that generated livepatch can deliver every
listed feature safely.

| Piece | Production LoC |
|---|---:|
| Generated-livepatch kernel source patch | 2,500–3,600 |
| Filemaster event source/protocol, event and response model, rules, prompts, and status | 1,200–2,000 |
| Capability, lifecycle, diagnostics, QEMU, and deployment glue | 500–1,500 |
| **Production total** | **4,200–7,100** |

| Test area | Test LoC |
|---|---:|
| Kernel/VFS/livepatch and target-kernel coverage | 2,600–4,500 |
| Filemaster event, rule, prompt, and response coverage | 1,500–2,600 |
| Lifecycle, queue, QEMU, upgrade, and adversarial coverage | 2,000–4,000 |
| **Tests total** | **6,100–11,100** |

| | Estimate |
|---|---|
| Sessions | **35–75** |
| Billed tokens | **510M–1.1B** |
| Cost at the session model | **$950–2,050** |

The full-product range includes ordinary implementation, tests, and debugging,
but not changing route after an early assumption proves false. The main risks
are a livepatch transition that does not converge on hot VFS paths, an
unacceptable cost for the parallel mask allocation required by livepatch's
no-layout-change constraint, deadlocks in freeze-before-lock revalidation, and
a target-kernel VFS refactor that requires a real port. A hand-written module
has a different, likely larger kernel-side estimate and must be modelled
separately — it is now the only surviving DKMS-only approach, so that
re-estimate is required rather than conditional.

## FUSE

This estimate is for the design described in
[update-option-fuse.md](dropped/update-option-fuse-technical.md). FUSE replaces the fanotify
platform layer but keeps the existing backend-agnostic event, rule, profile,
prompt, lifecycle, and shutdown pipeline.

The line estimate excludes P0 throwaway verification spikes and excludes tests
from the headline figure:

| Phase | Production LoC | Test LoC |
|---|---:|---:|
| Passthrough filesystem core | 2,000–3,000 | 600–1,000 |
| Identity and pipeline integration | 900–1,400 | 1,000–1,500 |
| Freeze, interrupt, and failure handling | 500–800 | 600–900 |
| Passthrough policy | 150–300 | 300–500 |
| Deployment and mount lifecycle | 500–900 | 300–500 |
| Optional revocation | 200–400 | 200–400 |
| Cross-cutting work | 300–600 | 200–400 |
| **Total** | **4,550–7,400** | **3,200–5,200** |

The total scope is about 7,750–12,600 new or changed lines when tests are
included. The filesystem core is the main source of uncertainty: it must cover
filesystem semantics, not merely emit access events.

The estimate is **19–28 working sessions**, derived from the second fanotify
group's 9–12 sessions for 4,050–6,650 lines including tests, then widened for
the FUSE-specific feasibility work and its more expensive integration testing.
At the [session model](#session-model)'s ~14.6M billed tokens per session, that
is **280M–410M Claude API tokens**. “Tokens” in this document means total
Claude API billed tokens — cached input re-reads, cache writes, fresh input,
and output — rather than generated output tokens alone.

This includes P0 investigation but excludes P0 throwaway code from the line
count. P0 must test the backing-store containment and open-downgrade assumptions
before the filesystem implementation begins. The token range also includes
implementation, tests, and debugging: hung mounts, D-state processes,
interrupt behaviour, and mount/recovery failures can require a root/VM reset
and repeat of the investigation. It does not include a change of direction if
P0 invalidates an assumption, or later scope such as required revocation;
those risks are skewed upward rather than downward.

## Fanotify extension in a custom kernel — not costed (2026-08-27)

Gate 1 of [P0](p0-architecture-decision-technical.md) was run against Linux
`v7.1` and returned negative, so this option carries no line or token estimate.
Full findings: [technical note](update-option-fanotify-extension-technical.md).

**Verified from source.** `fanotify_get_response()` is an untimed
`TASK_KILLABLE | TASK_FREEZABLE` wait — genuine reuse. But `fanotify_release()`
drains both pending permission lists with
`finish_permission_event(..., FAN_ALLOW, NULL)`, and `fanotify_handle_event()`
returns success when `fsnotify_prepare_user_wait()` loses a mark-deletion race.
Both are fail-open, so fail-closed teardown is new kernel work.

**Verified from source.** A blocking permission group cannot carry `DFID_NAME`,
two-sided rename identity, target identity or mount context. `fanotify_init()`
refuses FID reporting and `FAN_REPORT_MNT` outside `FAN_CLASS_NOTIF`, and
refuses permission masks inside it, so `FAN_RENAME`'s existing rich records are
unreachable from a blocking group.

**REOPENED (second revision, 2026-08-27).** The judgement below was made before
`fan_pre_modify-wip` was read and before the module row breakdown was checked.
It closed the option on the argument that "the daemon protocol and the module
wait/queue are unchanged either way" — which holds for adopting pre-lock
placement into the LSM design, but is **false for the fanotify endpoint**, where
fanotify supplies the transport.

**Derived** from the 1,760–2,830 line native module rows in
[LSM module sizing](lsm-module-sizing-technical.md): the transport/queue/
correlation/receiver/reply/wait row is **380–600** lines and the scope-marks row
is **420–680** — and sizing describes scope marks as "an event-origin filter,
never a kernel policy matcher", which is what fanotify marks are. Together that
is ~600–1,050 of 1,760–2,830, or **34–37% mid-range**, making an offered 25–40%
band consistent with this document's own numbers.

**Verified — not free:** fail-closed teardown; revalidation against the
raced-replacement attack (decision on *(parent, name)* before
`lookup_one_qstr_excl()`; SRCU is quiescence, not exclusion); rename as two
cookie-joined events; overlayfs upper-layer uncovered; the 500–850 daemon lines
unchanged. **Judged:** regression risk to the shipping Open/Execute path, and a
24-patch rebase from v6.5-rc1 plus a larger per-release surface than the LSM
route's measured ~16 lines per operation.

**A number was subsequently entered** by owner decision — see
[Fanotify extension in a custom kernel — estimate entered](#fanotify-extension-in-a-custom-kernel--estimate-entered-2026-08-30).
A port of the delete/rename patch to `v7.1` and a recount — the P1 method — still
supersedes it.

**Scope warning.** The `+ DKMS` rows are incremental later-phase only and cover
more than the four structural operations; they cannot be compared directly
against the four-operation LSM sizing without mixing scopes.

**Effect on this document.** The option's cost argument was that fanotify already
owned the wait, queue, response and client. [LSM module sizing](lsm-module-sizing-technical.md)
had already removed the client claim (500–850 daemon lines regardless of
transport); Gate 1 removed the rest. The row eventually added is far smaller
than the option was proposed on, and overlaps candidate A on tokens.

## Prior art (2026-08-27)

Surveyed in [prior art](prior-art-technical.md). Two findings bear on cost.

**The unmerged `fan_pre_modify-wip` branch does not change the estimate.**
Fetched and read (`amir73il/linux`, tip `4a8b6401`, 24 patches on v6.5-rc1). It
prototypes `FAN_CLASS_VFS_FILTER`, delivering permission events before the VFS
locks for create, unlink, rmdir and two-parent rename — removing the Gate 1.2
class conflict on paper. **Verified from source**, it decides on *(parent, name)*
before `lookup_one_qstr_excl()`, so the target inode is not a decision input,
and `b31ab27` states its SRCU barrier "never blocks new writers" — it is
quiescence, not exclusion. That leaves a raced-replacement window which P1
measured failing closed. Adopting it would trade already-proven retry plumbing
for a rebase from v6.5-rc1 plus closing that gap; the daemon protocol and module
wait/queue are unchanged either way. Its separable idea, **pre-lock ask
placement**, is orthogonal to the endpoint choice and is not costed.

**Prior art for the wait/queue layer reduces risk, not the estimate.** The
dominant remaining term is the module's wait, queue, cancellation, response
handling and daemon-death behaviour, plus 500–850 daemon lines. Four sources
address it; two are mainline and need no fork.

| Source | In-tree? | Wait | Verified |
|---|---|---|---|
| `kernel/seccomp.c` notify | Yes | `wait_for_completion_interruptible()` — untimed (`:1202`) | Yes |
| AppArmor prompting | No — Ubuntu SAUCE | reported untimed, `interruptible` variant | No |
| `security/tomoyo/common.c` | Yes | `wait_event_interruptible_timeout` (`:2260`) | Yes |
| Tetragon / KubeArmor | n/a — BPF route only | n/a | No |

All are GPL kernel code, so reuse of the queue and response machinery is
licence-compatible with a Filemaster LSM rather than design-inspiration only.

**No estimate change.** The module range is already 1,760–2,830 lines; good
prior art plausibly lands the outcome near the bottom of that range rather than
creating a lower one, and reading a large codebase to extract a small mechanism
can cost more than writing it. The return is failure semantics — daemon death,
cancellation, overflow, stale or recycled response IDs, malformed replies —
which belongs against
[backend test requirements](backend-test-requirements-technical.md), not against
the line count.

## FUSE — estimate overstated, option stays dropped (2026-08-27)

**Verified from source.** `hanwen/go-fuse` is New BSD licensed. Its
`fs.LoopbackNode` already implements Lookup, Mknod, Mkdir, Rmdir, Unlink,
Rename, Create, Symlink, Link, Readlink, Open, Opendir, Readdir, Getattr,
Setattr, Getxattr, Setxattr, Removexattr and CopyFileRange. Kernel passthrough
is present: `FOPEN_PASSTHROUGH` (`fuse/types.go:259`), `CAP_PASSTHROUGH`
(`:309`), `BackingID` (`:265`), with backing-fd registration in `fs/bridge.go`.

**Judged.** The 2,000–3,000 line "passthrough filesystem core" row above is
the largest single row and is largely replaceable by a maintained dependency
rather than written. Some glue remains — go-fuse supplies `LoopbackNode`, not
Filemaster's interception around it. A revised production range of roughly
**3,000–5,400 lines** is credible (judged, not measured).

**The token figure should not be revised proportionally.** The FUSE estimate of
19–28 sessions was **not** derived from line count. Per the section above it was
derived from the second fanotify group's sessions and then "widened for the
FUSE-specific feasibility work and its more expensive integration testing",
with the named risks being "hung mounts, D-state processes, interrupt behaviour,
and mount/recovery failures can require a root/VM reset and repeat of the
investigation". go-fuse removes lines; it does not remove D-state debugging or
VM resets. An externally offered revision to ~200–320M tokens is therefore
**too optimistic** and is not adopted. The token range is left at 280–410M
pending a reason to move it that is about debugging difficulty rather than
typing.

**Cost is no longer a reason to reject FUSE.** All candidate totals are
full-product-from-today (sizing report: "They do not assume that a prior
LSM-only or stock-BPF backend has already been delivered"), so the comparison is
like-for-like:

| Option | Production lines | Tokens |
|---|---|---|
| LSM + DKMS | 2,655–4,275 | 234–350M |
| BPF + DKMS (full BPF) | 2,985–4,835 | 277–423M |
| FUSE, revised | ~3,000–5,400 | ~200–320M |
| ~~DKMS only (generated livepatch)~~ — route deleted | ~~4,200–7,100~~ | ~~510M–1.1B~~ |

Revised FUSE is **tied with BPF + DKMS** at the low end and **cheapest of all on
tokens**. It was also recorded as cheaper than DKMS-only; that comparison rested
on the deleted generated-livepatch figure and no longer stands until the
standalone module is sized. An earlier note here said it "exceeds
LSM + DKMS" — true on lines, but it framed FUSE as remaining the expensive
outlier, which the revised figures do not support.

**The option stays dropped for architectural reasons, not cost.** Of the three
recorded reasons — dislike of mounting, cost, and "doesn't do anything custom
kernel doesn't" — go-fuse spends the second. The first stands. The third stands
on the reading that FUSE's distinguishing feature is stock-kernel deployment,
which is the job the BPF tier already does; if a BPF tier is kept, FUSE is
redundant with it rather than additive. The row is left as-is; if FUSE is ever
reconsidered, reopen it on those grounds and not on cost.

## `+ DKMS` increment after a finished BPF LSM (2026-08-27)

> **Checked against the 2026-10-03 BPF LSM re-cost; increment left at
> ~2,400–3,900 / 16–25 sessions.** The re-cost moves the BPF side to Rust/Aya
> with a Go cilium/ebpf loader. That nudges carry-over up: the loader and
> pinning lifecycle carry, and the policy compiler still does not. The effect is
> perhaps 100–200 lines, which is inside the noise.
>
> The increment's expensive rows (kernel patch, kfunc, wait, revalidation,
> daemon protocol) are kernel C or daemon Go and are untouched.
>
> **New unknown, not costed:** whether Aya can build a sleepable LSM program
> that calls a custom `KF_SLEEPABLE` kfunc, which this design requires. If it
> cannot, the pass-one/pass-two BPF programs stay in C. That would be acceptable
> under the avoid-C-where-reasonable rule, but it would be a second BPF
> toolchain.

**Judged; derived** by row-level subtraction from candidate C in
[LSM module sizing](lsm-module-sizing-technical.md) using the BPF LSM row
breakdown above. The sizing report declines to subtract retained artifacts
before code exists. That caution is noted and overridden deliberately: every
other figure in this document is a judged estimate, and refusing to estimate one
cell while estimating all the others is not a defensible standard. The number
below is an estimate of the same kind and quality as its neighbours.

| Candidate C row (from today) | Lines | Paid by a finished BPF LSM? | Carries over |
|---|---:|---|---:|
| Four-operation VFS/generic security change | 145–195 | No — stage one has no kernel patch | 0 |
| `KF_SLEEPABLE` kfunc/BTF registration | 60–100 | No | 0 |
| Hand-built task-keyed verdict store and lifecycle | 300–480 | No — stage one is static, no cross-pass state | 0 |
| Native daemon transport, correlation, killable wait | 380–600 | No — stage one has no wait | 0 |
| Native identity/revalidation, scope marks, fail-closed | 900–1,450 | Identity groundwork only | 100–200 |
| BPF pass-one/pass-two matrix, maps, CO-RE context | 280–460 | Yes — same four hooks, same CO-RE object | 150–250 |
| Loader, pinning, pair lifecycle, capability detection | 170–300 | Largely — loader and capability probe exist | 120–200 |
| Daemon protocol and adapter | 500–850 | Partly — lifecycle/status/config plumbing only | 100–200 |
| Custom build/package/boot health and VM support | 250–400 | Partly — custom *kernel* build is new | 80–130 |
| **Total carried over** | | | **550–980** |

**Increment: ~2,400–3,900 production lines** (candidate C's 2,985–4,835 less the
carried 550–980).

**Only ~40% of BPF LSM's 1,450–2,450 lines survive into the custom-kernel
product.** Its second-largest row — static-policy compiler and BPF map schema,
350–600 — is architecturally wrong for the destination: candidates A and C both
keep the rule engine in the daemon and use kernel-side marks as an event-origin
filter, "never a kernel policy matcher". Stage one's in-kernel policy matching is
discarded, not carried.

**Sessions scale worse than lines here.** Everything carried over is cheap
(loader, CO-RE object, packaging); everything new is expensive (the wait,
revalidation, the adversarial matrix). Increment estimated at **16–25 sessions /
~234–365M nominal tokens**, against candidate C's 19–29 sessions for the whole
product from today.

### Staging premium

| Route | Sessions | Nominal tokens |
|---|---:|---:|
| Straight to pure native custom kernel | 16–24 | 234–350M |
| Straight to full-BPF custom kernel | 19–29 | 277–423M |
| BPF LSM first, then upgrade | **24–37** | **355–545M** |

**Staging through BPF costs about 5–8 extra sessions, a ~26–28% premium**
(**judged; derived** from the rows above). This supersedes the older 10–20%
detour premium, which assumed more reuse than the row breakdown supports and
which [LSM module sizing](lsm-module-sizing-technical.md) already warned must
not be quoted literally.

Buying that premium is not irrational: it ships structural visibility on stock
kernels years earlier and defers the custom-kernel decision. It is a schedule
and reach purchase, not a cost saving. This section prices it; it does not
recommend for or against it.

## Fanotify extension in a custom kernel — estimate entered (2026-08-30)

**Deliberate override, same as the `+ DKMS` cell.** The
[technical note](update-option-fanotify-extension-technical.md#effect-on-the-cost-case--reopened-2026-08-27-second-revision)
declined to enter a number, on the grounds that a defensible figure needs the P2
port first. The owner ruled that every figure in this document is an estimate
and that a good estimate beats a blank cell. A number is therefore derived here
by the same row-subtraction method used for `+ DKMS`. **The P2 port supersedes
it**; until then it is `judged`, and its band is deliberately wide.

**Method.** The destination product is identical to
[LSM + DKMS](update-option-lsm-dkms-technical.md) candidate A — the same four
structural operations, the same daemon, the same custom kernel. Only the
kernel/userspace endpoint differs. So candidate A's four production components
are re-costed row by row against a fanotify endpoint.

### Component 1 — the module body

Candidate A's **1,760–2,830** line native LSM module, row by row:

| Native module row | Native | Fanotify endpoint | Why |
|---|---:|---:|---|
| Registration, ordering, Kconfig/Makefile, boot/health | 80–130 | 40–80 | fanotify is already in-tree and already registered; a new class and mark flag still need config and health reporting. |
| Per-task verdict cache, `lbs_task` lifecycle | 170–270 | 170–270 | Unchanged. fanotify has no per-task verdict concept. |
| Daemon transport, queue, correlation, authenticated receiver, reply validation, killable wait | 380–600 | 120–220 | **The main saving.** fanotify owns the queue, the wait, the fd-based receiver and reply matching. Residual is new structural permission masks, a combined event serialization, and two-sided rename correlation. |
| Identity payload and pass-two revalidation | 220–340 | 220–340 | Unchanged, and the prototype specifically lacks it — see the TOCTOU finding. |
| Scope marks and publication lifetime | 420–680 | **350–550** | **Revised up 2026-08-30** — see below. Originally 180–330 on the assumption that fanotify marks largely supply scope. The feature sweep verified they do not for the events this option needs. |
| Four-operation hook matrix | 260–430 | 150–280 | `fan_pre_modify-wip` already inserts hooks for create/mkdir/mknod/symlink/unlink/rmdir/link/rename. Discounted, not free, because the ported hooks answer the wrong question and both rename sides still need work. |
| Fail-closed, cancellation, recursion, classification, diagnostics | 230–380 | 200–350 | Near-zero saving, and **inverted**: fanotify is fail-open in two verified places, so this row starts from the wrong default rather than from nothing. |
| **Module body** | **1,760–2,830** | **1,250–2,090** | **derived** sum (revised) |

**Revised: a 26–29% saving on this component**, down from the 34–39% first
derived. The externally offered 25–40% band still contains it, but the original
34–37% figure — which came from crediting fanotify's marks with most of the
scope machinery — does not survive the feature sweep.

**Why the marks row went up. Verified from source (`v7.1`).** Directory-entry
events are **refused on a `FAN_MARK_MOUNT` mark**
(`fs/notify/fanotify/fanotify_user.c:2013-2016`), with the in-tree comment that
they "do not carry enough information (i.e. path) to be filtered by mount
point". A mount mark is the only mark type Filemaster uses
(`service/fileaccess/mount_linux.go:532`). So mount-scoped structural events
require plumbing a `struct path` through **every** structural hook site before
marks apply at all — which is new work, not reuse. Subtree suppression has the
same defect: mark types are inode/mount/filesystem/mount-namespace only, and
`__fsnotify_parent()` consults exactly one level
(`fs/notify/fsnotify.c:207`). Detail:
[Gate 1 item 3 — the feature sweep](p0-architecture-decision-technical.md#gate-1-item-3--the-feature-sweep-2026-08-30).

### Components 2–4, and what is new

| Production component | Candidate A | Fanotify endpoint | Why |
|---|---:|---:|---|
| Four-operation VFS/generic security change | 145–195 | 100–170 | Hook insertion is ported rather than written, but placement must change to satisfy revalidation. |
| Module body (above) | 1,760–2,830 | 1,250–2,090 | **derived** (revised) |
| Daemon protocol and adapter | 500–850 | 450–800 | Small saving only. The 1,121 measured Go lines of existing fanotify reader supply fd/metadata plumbing; the four-operation structural event model (180–310) is new either way. |
| Custom build/package/boot health, VM support | 250–400 | 250–400 | Unchanged — a custom kernel either way. |
| *New:* rebase of 24 patches, v6.5-rc1 → `v7.1` | — | 150–350 | Five releases of drift across `fs/namei.c`, `fs/notify/`, and the fanotify UAPI. |
| *New:* isolating the shipping Open/Execute path | — | 60–120 | Class and mark gating so the new event type cannot disturb the groups the product already depends on. Mostly a test cost; some production code. |
| **Production total** | **2,655–4,275** | **~2,300–3,900** | **derived** sum (revised 2026-08-30) |

### Tokens

Straight line-proportional conversion against candidate A's own ratio
(234–350M over 2,655–4,275 lines, i.e. ~82–88k tokens/line) gives **185–305M**.

**A difficulty premium of ~20–25% is applied**, giving **~245–400M** (revised
2026-08-30 from ~225–380M), or **16–27 sessions**. This document has stated since the FUSE revision that token
cost tracks debugging difficulty rather than line count, and three factors here
raise difficulty per line above candidate A's:

1. **Porting third-party kernel patches across five releases.** The failure mode
   is compile-and-boot cycles in a VM against code nobody on this project wrote.
2. **Regression verification on working code.** Candidate A adds an LSM and
   cannot break Open/Execute. This option edits the subsystem that *serves*
   Open/Execute, so the existing path must be re-verified every cycle.
3. **The revalidation redesign is unsolved.** Closing the *(parent, name)* TOCTOU
   gap against a fanotify event shape is research, not implementation. P1 solved
   it for the LSM route and measured it working.


### Correction to the direction of travel (2026-08-30)

An earlier note said the Q1 response-correlation finding meant this band should
be "read toward its low end". **That was wrong in direction.** Two findings
landed the same day and they push opposite ways:

| Finding | Effect |
|---|---|
| Response correlation is solved — the fd stays the key, and it transfers to `create`/`unlink`/`rmdir`/`rename` | Down. Removes a design risk; few lines. |
| Fail-closed is a small change, but there is a **third** fail-open site (queue overflow) | Roughly neutral. |
| **Mount marks refuse dirent events; subtree scope is not expressible** | **Up, and by more than the other two go down.** |

Net: the band moves **up**, not down. It is revised above rather than
re-weighted.

### The finding that matters

**The saving is on the module, not on the option.** The headline "a quarter to
two fifths" is a saving on the module body, which is only about two thirds of
the production total; the daemon, the build integration and the VFS change
barely move. On the whole option the line saving is **~11%** after revision, and
after the difficulty premium the token bands **overlap, with this option now
slightly worse at the top end** — 245–400M against candidate A's 234–350M.

**Judged.** On cost alone these two routes are a tie, and the choice between
them should be made on the dimensions in
[P0 Gate 3](p0-architecture-decision-technical.md#gate-3--minimum-designs-and-comparison)
— blast radius, rebase burden, and regression risk to a shipping path — not on
these numbers.

## Port base — the work splits across two branches, not one (2026-08-30)

**Verified from the remote.** `amir73il/linux` carries ~30 fanotify branches.
Enumerating the candidates by tip date and base `Makefile` version:

| Branch | Tip date | Base | Subject of tip |
|---|---|---|---|
| `fan_pre_dir_access` | **2025-07-08** | **v6.16-rc5** | nfsd: add pre-dir-content fsnotify hooks |
| `fan_pre_modify` | 2025-03-31 | v6.14 | FAN_PRE_MODIFY before write to file range |
| `fan_pre_access` | 2024-10-29 | v6.12-rc3 | xfs: opt-in for pre-content events |
| `fan_pre_modify-wip` | 2023-06-27 | v6.4 | nfsd: generate pre-modify path permission events |
| `fan_lookup_perm` | 2023-06-27 | v6.4 | fanotify: introduce FAN_LOOKUP_PERM |
| `fan_vfs_filter` | 2023-06-27 | v6.4 | fanotify: allow permission events with FAN_CLASS_VFS_FILTER |
| `fan_pre_vfs` | 2022-11-06 | v6.1-rc3 | fanotify: prepare for more pre-vfs permission events |
| `fan_modify_perm` | 2022-11-03 | v6.0 | fsnotify: acquire sb write access inside pre modify permission event |

The branch this project read and costed against — `fan_pre_modify-wip` — is the
**oldest relevant one but one**. `fan_pre_dir_access` is two years newer and
sits on v6.16-rc5, roughly one release series from the `v7.1` target instead of
about a dozen.

> **Do not read this as "the newer branch is the port base."** A follow-up source
> read established that `fan_pre_dir_access`'s **hook placement is unusable** for
> Filemaster — `fsnotify_lookup_perm()` only fires on a dcache **miss**, so it is
> a cache-population hook, not an access-control gate. What transfers is its
> **event plumbing**, nothing else. `fan_pre_modify-wip` remains the only source
> of the structural modify hooks Filemaster actually needs. Detail:
> [Response correlation, one-decision rename, and fail-closed](update-option-fanotify-extension-technical.md#response-correlation-one-decision-rename-and-fail-closed--read-from-source-2026-08-30).

### What `fan_pre_dir_access` contains

**Verified.** 15 patches on `d7b8f8e2 Linux 6.16-rc5`. Its *feature* is
pre-content events on **directories for lookup and readdir** — the HSM
populate-on-demand case. That is **not** Filemaster's feature; it does not touch
create/unlink/rmdir/rename.

**But two of its patches are exactly the Gate 1 item 1 blocker, already solved:**

| Commit | Diffstat | What it does |
|---|---|---|
| `905163ce4` fanotify: add support for a variable length permission event | 68+/20− over `fanotify.c`, `fanotify.h` | Adds `FANOTIFY_EVENT_TYPE_FID_NAME_PERM` — "a combination of the variable length `fanotify_name_event` prefixed with a fix length `fanotify_perm_event`". **A permission event that carries fsid + file handle + name info and can go on the user response wait list.** |
| `43ffbf710` fanotify: allow pre-content events with fid info | 59+/15− over `fanotify_user.c`, `fsnotify_backend.h`, `fanotify.h` (uapi) | Lifts the class restriction. Its own message states the problem verbatim: "the high priority classes … were not allowed to report events with fid info … partly because the `event->fd` is used as a key for the permission response". Adds `FAN_CLASS_PRE_CONTENT_FID`. |

**Verified from the diff** of `905163ce4` against `fanotify.h`: the new event
type is threaded through `fanotify_event_fsid()`, `fanotify_event_object_fh()`
and `fanotify_event_info()` alongside `FANOTIFY_EVENT_TYPE_FID_NAME`.

### Effect on Gate 1 item 1

Gate 1's **verified facts about `v7.1` mainline stand**: a blocking permission
event there carries one held path, and `fanotify_init()` refuses FID reporting
outside `FAN_CLASS_NOTIF` while refusing permission masks inside it.

What does **not** stand is the inference drawn from them — that "a new
structural permission event type and serialization is required" and would have
to be designed from scratch. It exists, in ~127 added lines, on a mid-2025
branch. It is unmerged, so mainline `v7.1` is unchanged; the cost consequence is
that this piece is a **port**, not a design.

### Consequence for the port base

**Judged.** There is no single branch to port. The work splits:

1. **Event format and class rules** — take from `fan_pre_dir_access`
   (v6.16-rc5, 2025). Short drift to `v7.1`.
2. **Directory-entry modify hooks** for create/unlink/rmdir/rename — only
   `fan_pre_modify-wip` has these (v6.4, 2023). Long drift.
3. **Pre-lock placement / `FAN_CLASS_VFS_FILTER`** — `fan_vfs_filter` and
   `fan_pre_vfs` (2022–23). Long drift, and Filemaster may not want it, since
   [P1](p1-rmdir-technical.md) proved unwind-and-retry and pre-lock placement
   carries the TOCTOU gap.

### Effect on the estimate

**Judged — no re-derivation, but the band should be read low.** The
[entered estimate](#fanotify-extension-in-a-custom-kernel--estimate-entered-2026-08-30)
priced a rebase from v6.5-rc1 at 150–350 lines and applied a 20–25% difficulty
premium whose first factor was "porting third-party kernel patches across five
releases". The hardest infrastructure piece turns out to start from 2025 rather
than 2023, which lowers both. The structural hooks still start from 2023, so
neither goes away. Treat **~2,100–3,700 lines / ~225–380M** as unchanged in span
but weighted toward its low end, and let the port measure it.

### Unresolved, and the first thing the port must answer

~~`43ffbf710`'s own message says the fd was the response key. How a fid+name
permission event is correlated with its response has not been read.~~
**Answered 2026-08-30 by reading the source.** The branch kept the fd as the
key — a pre-dir-content event always has a parent-directory path to open, and so
do `create`/`unlink`/`rmdir`/`rename`. No new correlation mechanism is needed,
and this is **not** a blocker. Fail-closed is also cheaper than assumed, though
a **third** fail-open site (queue overflow) was found. What did not survive is
one-decision rename. Full findings:
[Response correlation, one-decision rename, and fail-closed](update-option-fanotify-extension-technical.md#response-correlation-one-decision-rename-and-fail-closed--read-from-source-2026-08-30).

## Daemon protocol row revised upward (2026-09-01)

**Trigger.** Verifying AppArmor prompting produced the first external
measurement of a comparable userspace layer. snapd's
`sandbox/apparmor/notify/` is **2,448 non-test lines** against the **500–850**
in [LSM module sizing](lsm-module-sizing-technical.md). Detail:
[prior art — AppArmor prompting](prior-art-technical.md#apparmor-prompting--verified-2026-09-01-not-reusable-two-designs-worth-copying).

**Not apples-to-apples**, and the discount is real:

| snapd carries | Filemaster needs it? |
|---|---|
| Multi-version wire negotiation (protocol v3 and v5) | No, not initially |
| AppArmor-specific marshalling (labels, profiles, DFA filter) | No |
| Its own generic prompt pipeline | **No** — Filemaster reuses 2,082 measured Go lines it already has |
| **Daemon-restart reclaim: persisted listener ID, RESEND, readiness barrier** | **Yes — and it was never a row in our estimate** |

**Judged — revise 500–850 → 800–1,400.** Roughly +60%, not the 3–5× the raw
comparison suggests, because three of the four rows above are genuinely
discountable. The increase is driven by the fourth: restart reclaim is
production-proven necessary work that the original breakdown simply omitted.

**Confidence: low-to-medium.** This is one external data point against a
differently-shaped codebase, not a re-derivation. It should be replaced by a row
breakdown of the reclaim design when that design is written.

**Effect — it moves both live options by the same amount, and reorders nothing.**
The daemon protocol is endpoint-agnostic; sizing has said so throughout.

| Option | Production lines | Tokens |
|---|---|---|
| LSM + DKMS | 2,655–4,275 → **~2,950–4,800** | 234–350M → **~260–395M** |
| Fanotify extension | ~2,300–3,900 → **~2,600–4,450** | ~245–400M → **~275–455M** |

BPF LSM is **unaffected** — it is static enforcement with no prompt path, so it
has no daemon prompt protocol to grow.

**Judged — a second-order consequence.** The estimate's largest single line item
is now the daemon protocol plus the module's own wait/queue layer, i.e. the
ask-and-wait machinery, in both architectures. The kernel hook remains small
(P1: 16 lines for `rmdir`). Any future effort to reduce cost should be aimed
there and not at the kernel diff.

## BPF LSM — Cordon as an external measurement (2026-10-03)

A long-tail prior-art sweep turned up three projects; details in
[prior art](prior-art-technical.md#cordon--verified-2026-10-03-an-independent-bpf-lsm-implementation-of-our-row).
Only Cordon bears on a number.

**Verified from source** (`nikicat/cordon` at `b40a8c7`, Apache-2.0, Rust/Aya,
2026-06-23 → 2026-08-05, 125 commits, nearly all co-authored by Claude). It is
an independent, Claude-built implementation of essentially the BPF LSM row:
in-kernel static enforcement on `inode_link`, `inode_rename`, `inode_unlink`,
`inode_rmdir`, `inode_mkdir`, plus `file_open` and `bprm_check_security`.

Production lines, non-blank, non-comment, inline `#[cfg(test)]` modules cut,
mapped onto our pieces:

| Our piece | Our range | Cordon equivalent | Cordon |
|---|---:|---|---:|
| CO-RE BPF object, static enforcement | 200–350 | `bpf/src/main.rs` + `kernel.rs` | 546 (≈400–430 without Open/Exec) |
| Static-policy compiler and map schema | 350–600 | `bpf-common/*` + `policy/compile.rs` | 817 |
| Daemon loader, capability probe | 250–400 | `bpf_lsm.rs` + `btf.rs` + `backend/mod.rs` | 557 |
| Snapshot update, lifecycle | 300–500 | `seed.rs` + `pin.rs` | 236 |
| FileAccess/diagnostic integration | 200–350 | `events.rs` | 386 |
| **Comparable total** | **1,450–2,450** | | **2,542 (≈2,350–2,400 at our scope)** |

Excluded as having no Filemaster counterpart or already existing in
Filemaster: blessing (626), CLI and policy editor (1,112), rule DSL
parse/resolve (1,006), IPC/proto (532), config and misc.

**Judged — the line range holds, but the realistic outcome is its top.** An
independent implementation at our scope lands at ≈2,350–2,400 against our
2,450 ceiling. Per piece, the BPF object and loader rows look low and the
lifecycle row high. Treat the low end (1,450) as unlikely.

**Judged — the risk drops, which offsets the lines in tokens.** Cordon has
working, VM-tested answers to three items
[BPF technical](update-option-bpf-technical.md#implementation-consequences)
lists as unproven: atomic multi-map publication (banked maps plus one
`active_bank` flip), daemon-crash behaviour (LSM links pinned to bpffs, tested
by SIGKILL), and destination-overwrite rename (classified off the destination
dentry). It also documents a 6.12 verifier rejection of LSM return values and
its fix. Those were the open problems behind the "low-to-medium confidence"
note. **Token band 120–180M unchanged**; higher lines and lower debugging risk
roughly cancel. This is a judgement, not a measurement.

**Reuse can be direct: a Go loader works with Cordon's Rust program (spike,
2026-10-03).** Filemaster's BPF proof was C/libbpf only by default; nothing
chose it. The spike built Cordon's object with its pinned nightly and
`bpf-linker` 0.11.0. It then loaded the object with cilium/ebpf v0.20.0 (already
in `go.mod`), attached it with `link.AttachLSM`, seeded the maps from Go, and
observed EPERM on protected `unlink`/`rmdir` with unprotected ones allowed.
That ran on VM kernels 7.1.0 and 6.18.46. No C is needed. The object has no BTF,
so Go writes `.rodata` directly rather than using `VariableSpec.Set`.

Changes needed, which become work items:

- **Verifier, return value:** with this toolchain every program failed on the R0
  range. A one-line change in `clamped()` fixed it for 5 of 7 programs.
- **Verifier, stack:** `inode_link` and `inode_rename` still fail with a combined
  stack of 528 bytes (`decide_reparent`). They need restructuring and are
  untested.
- **Toolchain:** the verifier outcome depends on the LLVM/linker build, so the
  BPF toolchain must be pinned.
- **Filesystem identity:** on btrfs, `stat`'s `st_dev` does not match
  `sb->s_dev`. A key seeded from `stat` silently missed, and Cordon failed open.
  Keys must use `sb->s_dev`.

The BPF program and map layouts (~1,140 lines) are liftable. The seeding and
offset-resolver code (~390 lines of Rust) is rewritten in Go; the spike's
resolver was ~40 lines using `cilium/ebpf/btf`.

### BPF LSM re-costed as a Cordon port (2026-10-03)

**Supersedes the 2026-08-27 BPF LSM table.** The route is now:

- Cordon's Rust/Aya BPF program and map layouts, lifted and cut to the four
  structural hooks plus `mkdir`;
- a Go loader and policy publisher on cilium/ebpf;
- no C.

The scope is unchanged: static enforcement only, no prompt. *Lifted* means
lines that stay in the tree but are not written from scratch.

| Piece | Language | In tree | Written or changed |
|---|---|---:|---:|
| BPF program (`main.rs`/`kernel.rs`, minus `file_open`/exec/blessing; fail-closed inversion; `decide_reparent` stack fix) | Rust | 400–500 | 150–250 |
| Map layouts (`bpf-common`, trimmed) | Rust | 450–550 | 50–100 |
| Go mirror of map layouts and a layout-agreement check | Go | 150–250 | 150–250 |
| Policy compiler: Filemaster rules → maps (Cordon `compile.rs` as design) | Go | 250–400 | 250–400 |
| Loader, BTF offset resolver, capability probe, self-test | Go | 300–450 | 300–450 |
| Banked seeding, bpffs pinning, generation sweep (Cordon design) | Go | 250–350 | 250–350 |
| Events → FileAccess/monitor, coverage status | Go | 250–400 | 250–400 |
| Pinned nightly + `bpf-linker` build, object embedding, VM support | — | 150–250 | 150–250 |
| **Production total** | | **2,200–3,150** | **1,550–2,450** |

**Why the in-tree figure went up.** The old 1,450–2,450 was low (see the
Cordon measurement above). The lifted Rust is also more verbose than the
200–350 lines of C it replaces, and the Go side needs a mirror of the map
layouts. The written figure is the one that tracks effort.

**Tests unchanged at 2,050–3,550.** Tests scale with behaviours to prove, not
with where the code came from. Cordon's 2,040-line shell smoke suite is design
input only.

**Sessions: 8–12 → 6–9 (judged).**

- **Saved:** most BPF-side discovery and verifier debugging (about 2–3
  sessions), and design time on the three previously unproven items (about 1).
- **Added:** the `decide_reparent` restructure, the Rust toolchain in the build,
  and keeping the Go and Rust layouts in agreement (about 1–1.5 together).

| | Estimate |
|---|---|
| Sessions | **6–9** |
| Billed tokens | **~90–130M** (6–9 × 14.6M) |

**Confidence: medium, raised by the 2026-10-03 gate.** The `decide_reparent`
stack fix turned out to be one line. With it, all five mutation hooks load and
enforce from Go: 21/21 cases on 7.1 and 6.18, on tmpfs and btrfs. See
[BPF technical](update-option-bpf-technical.md#implementation-consequences).

Process identity is partly expressible: interpreter, cmdline, env and tag
profiles lose precision in-kernel; resolved by daemon-assisted labelling below. **Sessions stay 6–9 before labelling.** The verifier time
that was budgeted moves to:

- refreshing exe inodes on binary upgrade;
- reporting degraded profiles;
- expanding globs when the policy is built.

Still unproven:

- coexistence with fanotify Open;
- attaching on 6.12;
- overlayfs and bind mounts.

**Daemon-assisted process labelling added (2026-10-03, owner decision).** This
is the fix for the in-kernel identity gap.

- **Labelling:** the daemon identifies each process with its existing
  fingerprint logic (cmdline, env, tag, interpreter MatchingPath), then writes a
  profile label into a BPF map keyed by `(tgid, start_time)`, so a recycled PID
  cannot inherit a label.
- **Enforcement:** the mutation hooks match on the label, following the pattern
  of Cordon's blessing class.
- **Trust:** the same as today's fanotify path, which reads the same spoofable
  cmdline.
- **Unlabelled processes:** a process not yet labelled is denied. This covers
  the window between exec and labelling; holding exec via fanotify could close
  it, which is untested.
- **Children:** child processes need labelling too, by the daemon or by copying
  the label at fork.

Judged at **+0.5–1 session**, all untested.

**Strengthened to the combined design (2026-10-03, owner decision).** This
followed a survey of alternatives.

1. **In-kernel label map:** keyed by `(tgid, start_time)` in an LRU hash, not
   task storage, since Cordon's object has no BTF. The label is copied at
   `tp_btf/sched_process_fork` and recomputed at `bprm_committed_creds`. It is
   carried through an `env`/interpreter re-exec when the new argv names the
   script.
2. **Shebang exec:** records the script inode in-kernel. `security_bprm_check`
   runs once per binfmt pass (`fs/exec.c:1660`, `:1705-1709`, v6.18).
3. **Script-open labelling:** the daemon labels interpreter processes during the
   fanotify `FAN_OPEN_PERM` for the script they open, so the label is tied to the
   inode actually opened. On CPython the script open comes after site/`.pth`
   processing and before any script code runs. Other interpreters are untested.
4. **argv:** captured in BPF at exec, not read from `/proc`, so a process cannot
   rewrite it.
5. **Pending or unlabelled processes are denied.** Only interpreter startup code
   is affected.

Rejected:

- **Per-profile cgroups:** a child that execs `rm` keeps the script's label.
- **Holding at fanotify exec-permission:** argv is not yet copied at that point
  (`exec.c:1420` vs `:1831`).

Untested:

- bash, node and perl open order;
- the `env` carry rule;
- `-m` matching;
- LRU pressure under heavy fork load.

**New totals: 8–11 sessions, ~115–160M tokens.** The
[implementation plan](bpf-lsm-implementation-plan-technical.md) then summed
its milestones to **8.5–11.5 sessions, ~125–170M**. Three reasons:

- Cordon's decision logic is replaced by a verdict table checked against
  Filemaster's rule engine;
- the hidden Write list forces an `audit` default plus UI work;
- feeding captured argv in means a boundary change in the ported `process`
  package.

**Knock-on, not re-derived.** The staging-premium table uses BPF LSM at 8–12
sessions. Substituting 8–11 gives BPF-first-then-upgrade ≈24–36 sessions, and a
premium of ≈5–7 sessions over going straight to full-BPF. The `+ DKMS` increment's
"~40% carries over" was derived for a C/libbpf BPF LSM and has not been
re-checked for the Rust/Go split.

**Gaps Cordon does not close:** process identity in Filemaster's profile
terms, coexistence with fanotify Open, regular-file create, truncate, and
overlayfs on the mutation hooks. Its overlayfs measurement covers `file_open`
only. Its BPF also fails **open** on unreadable kernel fields, which a
Filemaster deny-on-unknown backend must invert.

**No other row moves.** Bulwark duplicates the fanotify Open prompt Filemaster
already has. RSBAC's UDF, verified from source, is a per-request
`call_usermodehelper` limited to open and exec, with no queue, no request IDs
and no cancellation. Its namespace-operation hooks sit inside the VFS directory
locks. It offers nothing to the wait/queue layer that dominates the
custom-kernel rows.

## Session model

Cost is dominated not by output code but by the active conversation context
reused by tool and agent turns.

There is no fixed lines-per-session constant in this document. Each session
band is a planning judgment based on implementation, test, and debugging scope;
the implied line density is only a cross-check. The only mechanical conversion
is selected sessions × ~14.6M billed tokens/session and × ~$27/session.

One working session uses a planning proxy of ≈120 assistant turns at ~120k
average context, or ≈14.6M billed Claude API tokens including ~180k output.

Pricing (Claude Opus 5, first-party, 1-hour cache TTL): $5/M input, $25/M
output, $0.50/M cache read, $10/M cache write.

| Component | Share | Tokens | Cost |
|---|---|---|---|
| Cache reads | ~85% | 12.2M | $6.10 |
| Cache writes | ~8% | 1.15M | $11.50 |
| Fresh input | ~7% | 1.0M | $5.00 |
| Output | — | 0.18M | $4.50 |
| **Per session** | | **~14.6M** | **~$27** |

### Measured correction (2026-08-27)

*Measured* from a `/usage` readout covering one 5-hour Claude Opus 5 window.
The window aggregates more than one session, so it calibrates **composition and
rate**, not the per-session totals above.

| Component | Modelled share | Measured share | Measured tokens | Measured cost |
|---|---|---|---|---|
| Cache reads | ~85% | **~96%** | 25.2M | $12.60 |
| Cache writes | ~8% | **~2.9%** | 759k | $7.59 |
| Fresh input | ~7% | **~0.04%** | 11.4k | $0.06 |
| Output | — | ~0.8% | 216k | $5.39 |
| **Window total** | | | **~26.2M** | **$24.45** |

Two model errors, both structural rather than noise:

1. **Fresh input is negligible, not 7%.** Under the 1-hour cache TTL almost
   every turn is a cache hit. The model overstated this line by roughly 90×.
2. **Cache reads are ~96% of all tokens, not 85%**, and cache writes are well
   under the modelled 8%.

The consequence is a rate error. Measured all-in cost is **~$0.93 per million
tokens**; the model implies $1.85 ($27 / 14.6M) — about **2× too expensive per
token**.

So one of the two columns in every estimate must move, and this measurement
cannot say which:

- If **~$27/session** is right, a session is **~29M tokens**, and every token
  figure in this document roughly doubles.
- If **~14.6M tokens/session** is right, a session costs **~$13.60**, and every
  currency figure roughly halves.

Resolving it needs an assistant-turn count per session, which `/usage` does not
report. Until then, treat the **ratio between the token and currency columns as
wrong by ~2×**, and prefer whichever column matters for the decision at hand
rather than treating both as jointly valid.

**Window size, for planning.** One 5-hour Opus 5 window is roughly **44M all-in
tokens / ~$41**. That is the useful budgeting unit, and it is measured rather
than modelled. A piece of work sized at *N* million all-in tokens consumes
about `N / 44` of a window.

### Known sources of error

- **One data point.** The per-session figure is extrapolated from a single
  measured session and has not been checked against billing. Nothing in this
  repository records token spend. Treat every token and currency figure as ±2×;
  the line counts are firmer, being grounded in code that exists.
  **Partly superseded** by [Measured correction](#measured-correction-2026-08-27):
  one real `/usage` readout now exists. It confirms the ±2× band is real and
  locates the error — the token-to-currency ratio is off by about 2× — but it
  covers a multi-session window, so it does not yet fix the per-session figure.
- **Compaction and cache boundaries are unmeasured.** The model does not record
  whether the source session compacted, how often, or how that changed cache
  reuse. A compaction can add summary output, fresh input, and cache writes
  while reducing later context size. The ~120k average is therefore an all-in
  empirical proxy only if the source session already included those effects; it
  is not a no-compaction formula. No separate multiplier is applied without
  transcript and billing data.
- **Model and pricing drift.** Current Opus 5 rates are applied to work starting
  2026-06-11. There is no record of which model ran which session.
- **Screenshots push the estimate up.** `CLAUDE.md` requires reading every UI
  screenshot with the Read tool rather than assuming it looks right. Those are
  image tokens — up to ~4.8k each on high-resolution models — and 43 Angular
  commits implies many of them.
- **Deletion pushes it down.** The June work was mostly stripping the network
  stack. Removing 149k lines costs far less per line than writing 20k.

Comparing the baseline against the Anthropic Console usage page for
2026-06-11 → 2026-08-13 would calibrate the per-session figure and tighten every
estimate in this document.
