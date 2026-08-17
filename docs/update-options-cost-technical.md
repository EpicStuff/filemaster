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
[update-option-2ndfanotify.md](update-option-2ndfanotify.md#decided-design):
origin-path overrides, move permission evaluated as Open on source and
destination, refuse-to-start on unsupported filesystems.

| Piece | Production LoC |
|---|---|
| Second NOTIF group: init, poll loop, lifecycle, shutdown | 250–300 |
| FID/TLV parsing (info headers, fsid, `file_handle`, dfid+name, target FID) | 200–250 |
| Path reconstruction from directory handles | 150–250 |
| Per-fsid filesystem marks, scope filtering, startup capability probe | 250–350 |
| Mover identification and profile resolution at notify time | 100–150 |
| `RenameRequest` construction, `DecideRename` wiring | 60–100 |
| Override store: origin path, persistence, cap, clearing | 250–400 |
| Decision integration: `name_to_handle_at`, dual-path eval | 150–200 |
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

## LSM only

This estimate is for an ordinary LSM implementation using existing LSM hooks.
It excludes DKMS packaging, generated livepatches, and custom VFS interception.
It does include the Filemaster-side event, rule, prompt, lifecycle, and
capability work needed to use the LSM; it does not re-cost Filemaster work
already completed in the fork.

The headline line count excludes tests and documentation but includes
production hardening and diagnostics that survive debugging:

| Area | Production LoC |
|---|---:|
| LSM registration, hook state, and kernel/userspace protocol | 700–1,050 |
| Filemaster event, rule, and prompt integration | 550–850 |
| Open, read, write, execute, and static-enforcement paths | 600–900 |
| Existing-hook operations: metadata, truncate, links, rename, and delete | 450–700 |
| Capability reporting, cancellation/failure handling, metadata context, suppression, and listener self-exemption | 500–850 |
| Compatibility and defensive production code | 400–650 |
| **Total** | **3,200–5,000** |

The estimate is **24–45 working sessions**. At the
[session model](#session-model)'s ~14.6M billed tokens per session, that is
**350M–660M Claude API tokens**. The token band includes design investigation,
implementation, tests, QEMU/kernel testing, debugging back-and-forth, failed
spikes, and rework. Tests and docs are excluded only from the line count.

LSM-only is deliberately narrower than the full feature list. Existing hooks
cannot provide the requested exact semantics for descriptor-mode downgrade,
`O_TRUNC` cancellation on downgrade, safely interactive pre-operation waits
with commit-time revalidation on all directory paths, one event per directory
enumeration, range-aware fallocate/hole-punch events, complete clone/dedupe
context, or guaranteed io_uring submitter attribution. Those require custom
VFS/kernel plumbing and belong to the separate DKMS/VFS route, not this number.

## DKMS livepatch (Route A)

This estimate is for the [generated-livepatch route](update-option-dkms.md):
maintain an ordinary kernel source patch, generate its loadable livepatch
module with in-tree `klp-build`, and ship the generated module through DKMS.
It excludes the generated module and tests from the line count.

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
