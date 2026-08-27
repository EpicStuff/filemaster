# Production Filemaster LSM module and daemon-protocol sizing

> **Status: sizing and design exercise, not an implementation plan.** This note closes the selected LSM + targeted-kernel route's previously unmeasured module/protocol row. It covers structural prompting for unlink, rmdir, rename, and link; existing fanotify remains the sole interactive owner of Open and File Execute.

## Scope, evidence, and figure convention

This is deliberately a line-and-session estimate, not a claim that the four operations have been proved. P1 proved native rmdir only. Its unlink, rename, and link kernel figures remain extrapolations, and the production transport, scope marks, and all four operation adapters have not been written.

Every number below has one of these labels:

| Label | Meaning |
| --- | --- |
| **measured** | Counted in existing source, a patch, or a completed P1 run. |
| **derived** | Arithmetic over measured and/or judged input. |
| **judged** | An engineering estimate. It is explicitly a **guess** where no existing source directly bounds it. |

The cost method is intentionally the one in [the costing note](update-options-cost-technical.md#session-model), rather than a new lines-to-token formula. Sessions are judged from implementation, test, and debugging scope; lines are a cross-check only. Nominal tokens are then derived as sessions times 14.6M. The measured correction says that this token-to-currency ratio is wrong by roughly twofold: if the old $27/session column is right, a session is instead about 29M tokens. Consequently this note reports nominal and alternate token readings, not a currency total.

The [44M-token five-hour planning window](update-options-cost-technical.md#measured-correction-2026-08-27) is **measured**. The roughly twofold token-to-currency uncertainty is also **measured**. Line ranges are the firmer unit.

Included: the four-operation custom-kernel patch; the policy-free native LSM or full-BPF alternative's native C support; a daemon-side fileaccess.Source adapter and structural prompt model; the acceptance-test scope in [Backend Test Requirements](backend-test-requirements-technical.md); and custom-kernel build, boot, health, and disposable-VM test support.

Excluded: a stock BPF backend unless a table explicitly says “dual tier”; distribution, signing, and support beyond one maintained custom-kernel release line; operations outside the four structural operations; and existing generic Filemaster rules, prompt UI, WebSocket flow, and fanotify Open/Execute path.

## Measured P1 base

The native rmdir proof was run on Linux v7.1, commit 8cd9520d35a6c38db6567e97dd93b1f11f185dc6 (**measured**); the full result is in [P1 rmdir unwind-and-retry proof](p1-rmdir-technical.md). Its patch series is saved under /root/vm/share/lsm-p1/.

| Area | Figure | Basis | Consequence for this sizing |
| --- | ---: | --- | --- |
| fs/namei.c, rmdir | +16 / −1 lines | **measured** | The unwind/retry insertion is small. |
| Generic security-hook plumbing | +38 lines | **measured** | One-time cost shared by all four operations. |
| Four-operation VFS change | about 145–195 lines | **derived** from measured rmdir plus documented extrapolations | This is the only sanctioned current kernel-diff range. |
| Filemaster P1 patch | +593 / −1 lines | **measured** | A disposable securityfs experiment, not a production-module size. |
| BPF sleepable-hook plumbing | +1 line | **measured** | Only relevant to the full-BPF candidate. |

The P1 result changes the cost shape: the targeted VFS change is no longer the dominant uncertainty. The dominant work is the LSM's request/wait/reply lifecycle, scope filtering, identity key, daemon transport, and failure matrix.

## What the 593-line P1 stub really contains

The “593 lines” is the patch's insertion count, not the C file's physical length. Patch 0002-security-filemaster-add-p1-rmdir-stub.patch adds 577 physical lines of security/filemaster/filemaster_lsm.c and 16 lines of Kconfig, Makefile, and LSM-ID integration, for 593 additions (**measured**). Its one deletion is an unrelated trailing blank line in security/Kconfig (**measured**).

The following is a semantic tag of the 593 additions, not a claim that the tagged lines can be copied into production unchanged. Several functions mix useful state-machine shape with deliberately singleton test storage.

| Portion of the patch | Lines | Share of 593 | Basis | What survives |
| --- | ---: | ---: | --- | --- |
| Native production-shaped core: task key/state, lbs_task, first/second-pass rmdir shape, killable wait shape, LSM registration and build integration | about 264 | about 45% | **derived** semantic tagging of the measured patch | The architecture and much control-flow shape survive; operation-specific code must be generalized. |
| Transport-shaped but rewritten: authenticated control-file checks, pending-request presentation, answer parsing/wakeup | about 90 | about 15% | **derived** semantic tagging | Request IDs, receiver authorization, reply validation, and wakeup semantics survive; securityfs text files do not. |
| P1-only scaffolding: global one-request slot, enable/reset/stats files, test counters/logs, fixed rmdir command shape, optional BPF kfunc bridge | about 239 | about 40% | **derived** semantic tagging | Discard or replace. Production needs concurrent request ownership, daemon lifecycle, scope publication, and four operations. |
| **Total** | **593** | **100%** | **measured / derived** | |

So **about 60% is production-shaped in concept** (**derived**: about 264 + about 90 lines), but **only about 45% is a direct starting shape** (**derived**: about 264/593). **About 40% is disposable P1 scaffolding** (**derived**: about 239/593), most visibly the securityfs test surface and the approximately 93-line optional BPF kfunc bridge (**derived**).

Useful exact-source locations are:

| Source span | Basis | Production interpretation |
| --- | --- | --- |
| filemaster_lsm.c:22–90 | **measured** | Verdict/task state, identity key fields, and registered-LSM lbs_task use. |
| filemaster_lsm.c:92–247 | **measured** | Rmdir pass one, bounded second pass, identity mismatch denial, cancellation, and wait control flow. |
| filemaster_lsm.c:249–341 | **measured** | Full-BPF experiment only; not part of the pure-native module. |
| filemaster_lsm.c:343–552 | **measured** | Securityfs P1 control plane, singleton request, counters, and reset logic; replace with real transport. |
| filemaster_lsm.c:554–577 plus patch integration | **measured** | Registered-LSM setup that survives, extended to all hooks and production health/order checks. |

## Native LSM module estimate

The selected architecture keeps Filemaster a registered LSM and gives it the native per-task blob. The daemon remains the only rule engine: scope marks are an event-origin filter, never a kernel policy matcher. The verdict cache is single-use and must be cleared on every generic ask-helper exit.

| Native module work | Added production lines | Basis | Why it is needed |
| --- | ---: | --- | --- |
| Registration, ordering, Kconfig/Makefile, boot/health report | 80–130 | **judged; guess** | P1 demonstrates the registration shape; production adds all hooks, LSM-last validation, and capability/health state. |
| Per-task verdict cache and lifecycle using lbs_task | 170–270 | **judged; guess** | Operation/identity/generation key, one-ask budget, single-use consume, clear-on-all-exits, and task/fork/exit-safe semantics. Blob allocation and task teardown come from registered-LSM infrastructure. |
| Kernel daemon transport, request queue, correlation, authenticated receiver, reply validation, killable wait | 380–600 | **judged; guess** | Replaces the P1 singleton/securityfs text protocol with concurrent owned requests, receiver loss handling, and flow control. |
| Identity payload and pass-two revalidation | 220–340 | **judged; guess** | Parent, name, target, mount, generation, and two-endpoint identity; answer-generation match and fail-closed mismatch. |
| Scope marks and publication lifetime | 420–680 | **judged; guess** | Mark store, subtree/ancestor lookup, mount identity, snapshot publication, nested marks, removal/rename/bind-mount cases, and no rule matcher. |
| Four-operation hook matrix | 260–430 | **judged; guess** | path_unlink, path_rmdir, path_rename, and path_link; both rename sides and link source/target context. |
| Fail-closed, cancellation, self-recursion, kernel-thread/overlay/io_uring classification, diagnostics | 230–380 | **judged; guess** | No listener, malformed reply, queue exhaustion, signal, daemon restart, receiver recursion, and explicit coverage status. |
| **Native LSM module** | **1,760–2,830** | **derived** sum of judged rows | Does not include VFS patch, daemon Go, or test code. |

The lbs_task row is smaller than an equivalent hand-built task store, not zero. The blob supplies allocation and teardown through the LSM framework; Filemaster still has to define state transitions, key matching, consumption, and cleanup correctly.

## Daemon-side protocol estimate

The daemon is not a new prompt product. It is a new kernel-facing source adapter that feeds existing PendingEvent, rule, prompt, and Respond(Verdict) machinery.

| Existing daemon evidence | Lines / tests | Basis | Reuse conclusion |
| --- | ---: | --- | --- |
| Generic pending-event, decision, prompt, profile, and notification path | 2,082 Go lines | **measured** | Reuse; do not charge these lines again. |
| Generic-path tests | 2,189 lines / 54 test functions | **measured** | Reuse for prompt ownership, lifecycle, grouping, and WebSocket flow. |
| Fanotify source plus response writer | 1,121 Go lines | **measured** | Mostly fanotify-only metadata, descriptors, marks, polling, and FAN_ALLOW/FAN_DENY; not the correct size analogue. |
| Fanotify kernel-facing tests | 2,493 lines / 42 test functions | **measured** | Useful behavioural precedent, not code to reuse. |
| Small socket-source precedent | 113 Go lines / 140 test lines / 3 test functions | **measured** | A source receives a request, creates a PendingEvent, provides a reply closure, then calls generic delivery. |

service/fileaccess/source.go already exposes the required source boundary: Run, Close, and SetWatchPaths. The existing PendingEvent ownership and prompt pipeline are reusable. The current FileEvent is not sufficient for this route, however: it has one path and an Open/Read/Write/Execute operation set, while namespace operations need correlation/generation, stable object identity, parent/name/target fields, and two endpoints for rename/link.

| New daemon work | Added production lines | Basis | Relation to fanotify path |
| --- | ---: | --- | --- |
| Wire request/reply model, parse/length checks, correlation and answer-generation validation | 110–180 | **judged; guess** | Analogous to the small socket source, not to fanotify's descriptor reader. |
| fileaccess.Source adapter, PendingEvent response closure, lifecycle/receiver-loss handling | 160–260 | **judged; guess** | Reuses the generic pipeline after admission. |
| Four-operation structural event model and endpoint-aware rule/prompt bridge | 180–310 | **judged; guess** | New because existing prompt admission is single-path. Existing static rename/link decisions are only partial precedent. |
| Source selection, capability/status reporting, diagnostics | 50–100 | **judged; guess** | Integrates the source without a second UI/WebSocket protocol. |
| **Daemon protocol and adapter** | **500–850** | **derived** sum of judged rows | Excludes the 2,082 reusable generic lines. |

This is intentionally not “zero lines because Source exists,” and it is not “1,121 lines because fanotify exists.” The 113-line socket source establishes the lower-level shape; the richer four-operation identity model establishes the additional work.

## Test-code estimate

P1's positive rmdir result is a regression seed, not completion of the acceptance matrix. The requirements demand existing fanotify Open/Execute coexistence, rules/prompts/concurrency/restart, identity races, all failure modes, common workflows, and adversarial testing. LSM + DKMS additionally requires sentinel containment, exactly-one-decision/bounded-retry proof, real LSM stacking, parked-prompt fsfreeze and cross-directory rename, revalidation races, doubled-resolution measurement, and disposable-VM destructive tests.

| Test area | Added test lines | Basis | Required evidence covered |
| --- | ---: | --- | --- |
| Daemon adapter protocol | 800–1,500 | **judged; guess** | Malformed input/reply, response ownership, receiver loss, daemon restart, answer generation, shutdown, and all four request shapes. |
| Four-operation VFS/sentinel/retry/stacking matrix | 900–1,500 | **judged; guess** | Allow/Deny/Ask/unsupported, one decision, one retry, userspace containment, later-LSM second pass, and real SELinux/AppArmor stacking. |
| Revalidation, lifecycle, and adversarial kernel matrix | 1,100–1,800 | **judged; guess** | Replacement/stale/two-side rename races, cancellation, queue exhaustion, io_uring, overlay, self-recursion, kernel threads, and daemon loss. |
| Shared coexistence, parked-prompt liveness, performance, boot/VM harness | 650–1,100 | **judged; guess** | Open/Execute coexistence, fsfreeze, same-superblock rename, rm -rf/git checkout double-resolution measurement, diagnostics, kernel update, and automated reset. |
| **Native candidate tests** | **3,450–5,900** | **derived** sum of judged rows | Test code only; it includes P1 expansion and all stated acceptance obligations. |
| Full-BPF-only verifier, loader/pinning, program replacement/detach, CO-RE/BTF, and tasks-trace tests | +700–1,250 | **judged; guess** | Added only when BPF owns the hook front end. |
| **Full-BPF candidate tests** | **4,150–7,150** | **derived** | Native matrix plus BPF-specific coverage. |

The scope-mark row is intentionally material. It includes the marked-directory-walk requirements — nested, unmarked, removal, rename, disconnected, and bind-mount cases — rather than assuming a simple membership check is enough.

## Stage-two candidate totals

The candidate totals are incremental from today's Filemaster tree. They do not assume that a prior LSM-only or stock-BPF backend has already been delivered. If one has, its actual retained artifacts should be subtracted only after code exists; historic reuse percentages are not a substitute for that measurement.

### A. Pure native: registered LSM + targeted custom kernel, no BPF

This is one structural interception implementation: the native LSM's path hooks. It does **not** imply a second implementation. Stock users already have an optional-upgrade product through fanotify Open/Execute; this candidate makes structural prompting available to users who install the custom kernel.

| Production component | Lines | Basis |
| --- | ---: | --- |
| Four-operation VFS/generic security change | 145–195 | **derived** P1 extrapolation |
| Native LSM module | 1,760–2,830 | **derived** above |
| Daemon protocol and adapter | 500–850 | **derived** above |
| Custom build/package/boot health and VM support | 250–400 | **judged; guess** |
| **Native production total** | **2,655–4,275** | **derived** sum |
| Native test total | 3,450–5,900 | **derived** above |
| **Native code including tests** | **6,105–10,175** | **derived** sum |

### C. Full BPF: BPF front end + native KF_SLEEPABLE kfunc, no registered LSM

This alternative still needs native C for the request transport and wait. Its only genuine removal is registered-LSM paperwork and the free per-task blob; it replaces both with BPF mechanics and a hand-built task-keyed lifetime store. It also inherits P1's unresolved tasks-trace-RCU lifecycle cost.

| Full-BPF kernel-side work | Lines | Basis | Comparison with native |
| --- | ---: | --- | --- |
| KF_SLEEPABLE kfunc/BTF registration, including the P1-measured one-line sleepable-hook entry | 60–100 | **judged; guess** | Replaces part of native registration boilerplate. |
| Hand-built task-keyed verdict store and lifecycle | 300–480 | **judged; guess** | Required because no registered LSM provides lbs_task; must handle task exit and reuse safely. |
| Native daemon transport, correlation, killable wait | 380–600 | **judged; guess** | Still native C, essentially the same role as candidate A. |
| Native identity/revalidation, scope marks, and fail-closed machinery | 900–1,450 | **judged; guess** | Still required; BPF cannot make protocol obligations disappear. |
| BPF pass-one/pass-two four-operation matrix, maps, CO-RE-safe context handling | 280–460 | **judged; guess** | Replaces native hook adapters and adds verifier constraints. |
| Loader, pinning, pair lifecycle, feature/capability detection | 170–300 | **judged; guess** | New BPF-specific work. |
| **Full-BPF kernel Filemaster implementation** | **2,090–3,390** | **derived** sum | **+330–560** lines versus native module estimate, despite skipping registration. |

| Production component | Lines | Basis |
| --- | ---: | --- |
| Four-operation VFS/generic security change | 145–195 | **derived** P1 extrapolation |
| Full-BPF kernel Filemaster implementation | 2,090–3,390 | **derived** above |
| Daemon protocol and adapter | 500–850 | **derived** above |
| Custom build/package/boot health and VM support | 250–400 | **judged; guess** |
| **Full-BPF production total** | **2,985–4,835** | **derived** sum |
| Full-BPF test total | 4,150–7,150 | **derived** above |
| **Full-BPF code including tests** | **7,135–11,985** | **derived** sum |

The 80–130 native registration/order row is the real saving being claimed here (**judged; guess**). It is not a saving of the whole LSM. The full-BPF candidate adds kfunc/BTF setup, loader/pinning state, a verifier-constrained frontend, and an estimated 130–210 additional task-lifecycle lines beyond the native lbs_task cache (**judged; guess**).

### Sessions and tokens

| Candidate | Sessions | Nominal tokens | Alternate tokens if $27/session is right | 44M-token windows | Basis |
| --- | ---: | ---: | ---: | ---: | --- |
| Pure native custom kernel | 16–24 | 234–350M | 464–696M | 5.3–8.0 | Sessions **judged; guess**; token/window arithmetic **derived**. |
| Full BPF custom kernel | 19–29 | 277–423M | 551–841M | 6.3–9.6 | Sessions **judged; guess**; token/window arithmetic **derived**. |

The full-BPF range is not a cost argument in its favour: it is larger despite the registration saving. Its additional test/debugging uncertainty is driven by verifier, CO-RE, pinning/replacement behaviour, and the tasks-trace-RCU question, not by a large code volume.

## The pivotal BPF codebase question

### What P1 actually wrote

P1's scripts/bpf/rmdir-p1.bpf.c is 105 physical lines (**measured**); its minimal loader is 217 physical lines (**measured**). The source does **not** implement a stock/custom feature branch:

1. rmdir_pass1 at lines 46–71 returns the sentinel whenever its P1 command filter matches and state is absent (**measured from source**).
2. rmdir_post_unwind at lines 73–103 is a sleepable ask program and calls the custom filemaster_bpf_wait kfunc (**measured from source**).
3. The loader's set_selected_autoload function manually selects one named program; it has no BTF feature probe or stock report-only mode (**measured from source**).

Therefore P1 does not prove a single stock/custom BPF program set. Loading the literal current pass-one program on stock would leak the private sentinel into an unpatched VFS, and loading its post-unwind program requires a hook target that stock lacks.

### Concrete answer

**Believed from source: no, not as one identical attached-program set with a runtime branch inside BPF.** A stock kernel has no custom ask attach target, so a sleepable ask program cannot be made safe merely by taking a different branch after it has attached. A BPF program also has no portable runtime query for “does the kernel expose this custom hook?” that can make an already-loaded target disappear.

**Believed from source: yes, as one source/object build with two loader-selected attachment profiles.** The production loader can inspect target BTF before object load. If bpf_lsm_ask is present, it enables the post-unwind program and sets a map or read-only feature bit that permits pass one to return the sentinel. If absent, it disables autoload for the ask program and sets report-and-allow mode. The pass-one program must never return the sentinel unless the post-unwind pair is attached and healthy. Pair-attachment failure must fail closed and clear state.

**Verified by running P1, but incomplete:** detaching the pinned post-unwind link while its kfunc invocation was parked returned in about 7 ms; the already-running invocation later consumed Allow and completed rmdir. Separately, pass one with the post-unwind program absent failed rmdir with EIO and no second prompt. Those cases do not yet establish every replacement or detach phase across all four operations.

This is one maintained source tree and potentially one object file, but two real attachment profiles. Calling it a “single attached set” would hide the lifecycle difference.

| BPF material across stock and custom profiles | Shared fraction | Basis | Detail |
| --- | ---: | --- | --- |
| Operation enum, scope/identity helpers, event schema, map definitions, stock reporting, build plumbing, most loader/pinning code | about 60–70% | **judged; guess** from the 105-line P1 program and 217-line loader | Shared source/loader core. |
| Custom-only sentinel branch, sleepable ask program, kfunc use, pair-health checks | about 15–20% | **judged; guess** | Cannot attach on stock. |
| Stock-only report-and-allow configuration/capability reporting | about 15–25% | **judged; guess** | Must not accidentally turn structural visibility into enforcement. |

If a project insists on physically separate objects instead, the fallback is two closely related program sets with the same **60–70% judged source reuse**. The extra split, loader, and CI burden is included in the full-BPF ranges above; it is not free simply because the C text is shared.

## Maintenance per kernel release

The unit here is a new supported kernel release, not a calendar year. These are maintenance sessions after initial delivery, not feature-development sessions. They include source audit/rebase, build/boot, regression, and diagnostic work; they do not assume a clean no-op rebase.

| Product shape | Rebase and custom-kernel audit | CO-RE/BTF and BPF lifecycle | Regression/test matrix | Capability/support split | Sessions / release | Nominal tokens / release | Alternate tokens / release | Basis |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Pure-native, single custom tier | 0.35–0.75 | 0 | 0.75–1.40 | 0.35–0.85 | 1.45–3.00 | 21–44M | 42–87M | Components and sessions **judged; guess**; token arithmetic **derived**. |
| Full-BPF, single custom tier | 0.35–0.75 | 0.35–0.90 | 0.85–1.60 | 0.20–0.45 | 1.75–3.70 | 26–54M | 51–107M | Components and sessions **judged; guess**; token arithmetic **derived**. |
| Native custom tier plus retained stock-BPF tier | 0.35–0.75 | 0.35–0.90 | 1.50–2.90 | 0.60–1.45 | 2.80–6.00 | 41–88M | 81–174M | Components and sessions **judged; guess**; token arithmetic **derived**. |
| Full-BPF custom tier plus retained stock-BPF tier | 0.35–0.75 | 0.45–1.00 | 1.35–2.65 | 0.50–1.30 | 2.65–5.70 | 39–83M | 77–165M | Components and sessions **judged; guess**; token arithmetic **derived**. |

The actual price of a stock BPF tier is therefore not “native means two interceptors.” For the native custom-kernel product, retaining a stock BPF tier adds **1.35–3.00 judged sessions per kernel release** (about **20–44M nominal tokens**, **derived**) over the 1.45–3.00-session single-tier baseline. If the custom tier is also full BPF, sharing its source/loader reduces that incremental range to **0.90–2.00 judged sessions** (about **13–29M nominal tokens**, **derived**) but does not remove two capability levels or the second matrix.

The full-BPF rows also carry a qualitative maintenance risk absent from native: P1 showed that the kfunc wait is inside tasks-trace RCU. Unrelated sleepable program attach/detach returned promptly in the P1 timing run because teardown defers reclamation; it did not prove the absence of a deferred-reclamation backlog or a relevant synchronous tasks-trace waiter. That unresolved test work is why the BPF regression row is larger.

## Reading the existing “10–20% BPF premium” honestly

The old [BPF-then-DKMS cost section](update-option-bpf-dkms-technical.md#cost-of-going-via-bpf) quotes a 1,400–1,600-line, 55–100M-token, 10–20% detour premium (**judged in that older note**). Its own text says this assumes the stock BPF stage is built and then discarded; its 510M–1.1B token denominator is a superseded estimate (**judged in that older note**). It must not be used as a literal percentage of the newly sized permission bridge.

| Reading | One-time interpretation | Ongoing interpretation | Basis |
| --- | --- | --- | --- |
| Stock BPF tier is retired after custom native delivery | Historic BPF-only detour: 1,400–1,600 lines and 55–100M nominal tokens; the old 10–20% is historical only. Recasting against this note's native range is a **3–5-session judged guess**, 44–73M nominal tokens, with an approximately 20% midpoint and a broad 12–31% range. | No stock-BPF release maintenance after retirement. | Historic figures **judged** in the old note; recast sessions **judged; guess**; token/percentage arithmetic **derived**. |
| Stock BPF tier is kept as a product capability | It is not a detour premium: the stock backend is a shipped deliverable. Relative to pure native plus existing fanotify, initial stock-BPF delivery remains the earlier **8–12-session judged** scope, 117–175M nominal tokens. | Add 1.35–3.00 judged sessions per supported kernel release for native-custom + stock-BPF, or 0.90–2.00 when full-BPF custom shares the BPF source/loader. | Sessions **judged**; token arithmetic **derived**. |

The contradiction to flag is useful: “10–20%” is a valid historical answer only to “what did a disposable BPF detour cost under the old broad denominator?” It is not the honest incremental price of maintaining a permanent stock capability. For that product the incremental release burden above is the decision-relevant number.

## Findings that change the estimate or need follow-up

1. **Positive, measured:** P1 reduces the custom VFS portion to a 145–195-line four-operation estimate, rather than the former thousand-line VFS/context model. That lowers the selected route materially.
2. **Negative, judged:** scope marks, concurrent daemon transport, and the four-operation identity/revalidation matrix dominate the native module. They were deliberately absent from the 593-line P1 stub.
3. **Negative, measured from source:** the current daemon event model is single-path and Open/Read/Write/Execute-shaped. Rename/link endpoints and correlation are real new Go work; they are not a fanotify reader swap.
4. **Negative, believed from source:** the full-BPF candidate's only material saving is registration boilerplate. It loses lbs_task, adds BTF/kfunc, loader/pinning, verifier, and tasks-trace lifecycle concerns, and therefore sizes larger than pure native in this scope.
5. **Documentation drift to resolve:** the opening status wording in [the LSM + DKMS technical note](update-option-lsm-dkms-technical.md) says there is no BPF-flavoured variant because BPF cannot host an untimed wait. The later BPF technical note and the test requirements retain the distinct candidate in which native C hosts the wait in a KF_SLEEPABLE kfunc. The latter is the candidate sized here; it does not contradict “BPF bytecode itself cannot wait,” but the two documents should use one current wording.
6. **Boundary:** no number above claims a proof for unlink, rename, or link, a production transport, scope marks, or a dual-tier BPF loader. Those remain implementation and test work, not success inferred from P1.

## Bottom line

For the four-operation structural-prompting scope, the best current estimate is **2,655–4,275 added production lines plus 3,450–5,900 test lines** for the pure-native custom-kernel product (**derived**), planned as **16–24 judged sessions** or **234–350M nominal tokens** (**derived**). The full-BPF frontend is larger at **2,985–4,835 production plus 4,150–7,150 test lines** (**derived**), planned as **19–29 judged sessions** or **277–423M nominal tokens** (**derived**), while retaining an unresolved tasks-trace lifecycle question.

The native candidate has exactly one structural interceptor unless Filemaster chooses to ship and retain a stock BPF product. That is a product decision, not a property of native LSM + DKMS. If it is chosen, the real ongoing price is the per-release dual-tier range above, not the historical one-time 10–20% detour label.
