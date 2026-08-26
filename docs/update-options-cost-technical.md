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

Applying the [session model](#session-model) at 2–4 commits per session:

| | |
|---|---|
| Sessions | 60–90 |
| Billed tokens | 900M–1.3B |
| Cost | $1,600–2,400 |
| Widened for uncertainty | 700M–1.5B, $1,200–3,000 |

About **$9–13 per commit**, or ~20–25k tokens per surviving line.

## Second fanotify group

Scoped to the design settled in
[update-option-2ndfanotify.md](update-option-2ndfanotify.md): origin-only
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

A deliberately narrow first pass — rename only, in-memory overrides, no hard
links, fail closed everywhere else — is **~1,100 production lines and 3–4
sessions**. Nothing in it is throwaway; it all survives into the full version.

### Relative scale

The second fanotify group is **roughly one tenth** of the fork to date, on both
axes — ~2,000 production lines against ~20,000, and 9–12 sessions against 60–90.
The narrow first pass is a tenth of that again.

That ratio is more trustworthy than either absolute figure, because both come
from the same session model: errors in the per-session cost largely cancel.

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

[BPF LSM](update-option-bpf-lsm.md) is a separate static-enforcement option.
Fanotify remains the sole owner of interactive Open and Execute decisions. BPF
LSM initially handles only structural operations fanotify cannot deny; it does
not attach an Open hook in the initial design.

For a BPF-owned operation, Ask, no matching static policy, an unsupported
operation, or an unrepresentable policy case is a deny. A BPF LSM program cannot
use the existing Filemaster prompt flow or wait for a userspace decision.

The first target-kernel hook proof passes for `inode_unlink`, `inode_rmdir`,
`inode_link`, and `inode_rename`. Its exact evidence and deliberately narrow
scope are in [BPF LSM update option — technical proof](update-option-bpf-lsm-technical.md).

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

[LSM only](update-option-lsm-only.md) is a native LSM built into a custom
kernel and restricted to existing hooks. It is a static-enforcement route: it
does not claim an interactive prompt at an LSM hook. The BPF proof supplies
evidence for four candidate hook locations, but a native LSM still needs its
own kernel policy store, userspace control plane, bootable custom-kernel path,
and safety proof. See the [LSM-only technical note](update-option-lsm-only-technical.md).

The direct estimate uses the same four-hook static scope as BPF. It excludes
LSM + DKMS changes, new hook placement, or richer context.

| Piece | Production LoC |
|---|---:|
| Built-in LSM registration, Kconfig, and hook implementation | 250–450 |
| Kernel policy store, safe snapshot lifetime, control interface | 500–850 |
| Identity/policy evaluation and operation coverage status | 300–550 |
| Daemon policy writer, lifecycle, and diagnostics | 300–500 |
| Custom Arch kernel build, packaging, and VM support | 250–450 |
| FileAccess/config integration | 200–350 |
| **Production total** | **1,800–3,150** |

| | Low | High |
|---|---:|---:|
| Production | 1,800 | 3,150 |
| Tests | 2,300 | 4,000 |
| **Total including tests** | **4,100** | **7,150** |

| | Estimate |
|---|---|
| Sessions | **10–15** |
| Billed tokens | **150M–225M** |
| Cost at the session model | **$275–425** |

Native code is less verifier-constrained but does not eliminate the missing
hook context. Its extra cost over BPF is primarily the custom-kernel policy
transport, memory-lifetime work, and boot/package test loop. Confidence is low
until the four-hook native proof and policy-control P1 pass.

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
| Additional tests | 1,200 | 2,200 |
| **Additional total including tests** | **2,200** | **3,900** |

| | Estimate |
|---|---|
| Additional sessions | **5–8** |
| Additional billed tokens | **75M–120M** |
| Additional cost at the session model | **$140–230** |

The BPF-first route therefore totals roughly 13–20 sessions and 195M–300M
billed tokens if it later migrates. It costs more than starting LSM only, but
it delivers a lower-kernel-risk static backend first and keeps open the option
to stop there. The migration discount disappears if BPF policy compilation is
coupled to BPF map layout or if native LSM needs context unavailable at the
same hooks.

## BPF LSM + DKMS

This is **only** the later targeted-kernel/direct-decision phase after a
completed BPF LSM backend. It does not include BPF LSM's 1,450–2,450 production
lines, its 120M–180M-token estimate, or a BPF LSM → LSM-only migration.

The final direct path owns each structural-operation decision. It therefore
removes the former custom BPF dispatcher, BTF/version contract, verifier work,
and permanent BPF policy cache. It still includes the all-feature planning scope:
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

> **Superseded architecture.** The figures in this section model a permanent
> BPF static-policy layer and a custom BPF dispatcher. They are retained as the
> previous model, not as an estimate for the current direct-kernel design.

The current [BPF LSM + DKMS](update-option-+dkms.md) route uses BPF as an
interim stock-kernel backend, then sends structural decisions directly to
Filemaster once targeted kernel support exists. See the
[BPF LSM + DKMS technical note](update-option-bpf-lsm-dkms-technical.md).

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

### Superseded targeted-kernel work after BPF LSM

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

Under the superseded design, the final BPF-first route is roughly the same cost
class as [LSM + DKMS](update-option-+dkms.md), and can be slightly higher. BPF
avoids the native-LSM policy store, but adds the custom BPF dispatcher/ABI,
verifier/CO-RE/BTF compatibility, stock/custom lifecycle split, and differential
tests. The expensive VFS wait/revalidation/context/mutation work is common to
both routes.

Those assumptions do not apply to the current direct-kernel route: it has no
custom BPF dispatcher or BPF verifier/BTF work in the final phase. Re-estimate
temporary BPF work and final direct-kernel work separately. Metadata-read
subtree suppression and directory-traversal retry remain separate feasibility
gates and can still exceed the eventual range.

## LSM + DKMS

This is **only** the later targeted-kernel/direct-decision phase after a
completed LSM-only backend. It does not include LSM only's 1,800–3,150
production lines or its 150M–225M-token estimate.

The final direct path owns each structural-operation decision. The native LSM
does not retain a structural policy cache or make a decision for an operation
the direct path owns. This model retains the same all-feature planning scope as
the BPF LSM + DKMS estimate, but replaces BPF detachment with the native-LSM
handoff.

### Current incremental targeted-kernel estimate

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

This excludes the LSM-only phase, added-kernel distribution, and the separate
second-fanotify origin-tracking option. Metadata-read subtree suppression and
directory-traversal retry remain feasibility gates; a redesign lies outside this
range.

> **Superseded architecture.** The figures in this section model a permanent
> native-LSM policy layer and LSM/custom arbitration. They are retained as the
> previous model, not as an estimate for the current direct-kernel design.

The current [LSM + DKMS](update-option-+dkms.md) route uses a native LSM as an
interim static backend, then sends structural decisions directly to Filemaster
once targeted kernel support exists. The complete endpoint and its architecture
are in the separate [LSM + DKMS technical note](update-option-lsm-dkms-technical.md).

The previous model covers an attempt to implement every currently listed
Filemaster feature family: the static LSM base; lock-free permission waits and
final revalidation; Open read/write context and read-only downgrade; listing;
namespace mutation; truncate, metadata, range, clone/reflink; metadata reads;
the low-priority write, dedupe, traversal, and self-exemption tail; plus
io_uring, overlay, lifecycle, and adversarial VM coverage. It is a planning
scope, not a claim that every feature has passed its feasibility gate.

Its baseline is one custom kernel containing the native LSM and the targeted
changes. Distribution of those changes is outside that estimate. This is not
the standalone stock-kernel DKMS route, and it does not include the separate
second-fanotify origin-tracking option unless a later design explicitly merges
that work.

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

The high end in the superseded model is driven by the safe wait/revalidation
foundation, two-object namespace operations, read-only Open conversion,
metadata-read subtree suppression, traversal retry, write/dedupe tail work, and
the LSM/custom-path arbitration. The current route removes the latter
arbitration and needs a new estimate that separates temporary LSM work from
final direct-kernel work. Metadata-read suppression and traversal retry remain
feasibility gates; a redesign can exceed the eventual range.

## DKMS only (generated livepatch / Route A)

This estimate applies only to the generated-livepatch route within
[DKMS only](update-option-dkms-only.md): maintain an ordinary kernel source patch,
generate its loadable livepatch module with in-tree `klp-build`, and ship the
generated module through DKMS. It excludes the generated module and tests from
the line count.

| | Estimate |
|---|---|
| Clean design, production code | 2,200–3,100 lines |
| Production code, including debugging residue | **2,500–3,600 lines** |
| Billed tokens, no-surprises band | **400M–900M** |

The token band already includes ordinary debugging. Roughly 10% is source and
design reading, 20% a first draft, 25% compile and `klp-build` iteration, 35%
runtime debugging, and 10% tests and flake chasing. About 70% is therefore
post-draft work. The line range includes the defensive checks, error paths,
and revalidation that survive that debugging; it is the number used in the
summary document.

The band does not cover changing the approach after an early assumption proves
false. The main risks are a livepatch transition that does not converge on hot
VFS paths, an unacceptable cost for the parallel mask allocation required by
livepatch's no-layout-change constraint, deadlocks in freeze-before-lock
revalidation, and a target-kernel VFS refactor that requires a real port. Each
could add about 200M–500M tokens. The distribution is consequently skewed
above the stated band rather than below it.

## FUSE

This estimate is for the design described in
[update-option-fuse.md](update-option-fuse.md). FUSE replaces the fanotify
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

## Session model

Cost is dominated not by the code written but by the fact that every tool call
re-sends the whole conversation.

One working session ≈ 120 assistant turns at ~120k average context ≈ 14.6M
billed Claude API tokens, including ~180k output.

Pricing (Claude Opus 5, first-party, 1-hour cache TTL): $5/M input, $25/M
output, $0.50/M cache read, $10/M cache write.

| Component | Share | Tokens | Cost |
|---|---|---|---|
| Cache reads | ~85% | 12.2M | $6.10 |
| Cache writes | ~8% | 1.15M | $11.50 |
| Fresh input | ~7% | 1.0M | $5.00 |
| Output | — | 0.18M | $4.50 |
| **Per session** | | **~14.6M** | **~$27** |

### Known sources of error

- **One data point.** The per-session figure is extrapolated from a single
  measured session and has not been checked against billing. Nothing in this
  repository records token spend. Treat every token and currency figure as ±2×;
  the line counts are firmer, being grounded in code that exists.
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
