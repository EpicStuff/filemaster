# UI changes needed to reflect the backend rewrite

Status: **partial** — **A2, A3, A5 are done**, and **A1 is verified working**
(optional cosmetic polish only); **A4 is largely already covered by generic
rendering** (optional curation only). **A6 and the section C network-UI cleanup
still remain.** This file is the note of what's left.

## How this list was derived

This is a *delta* analysis, not a from-scratch UI audit. The file-access UI
(prompts, monitor page, per-app events, a diagnostics panel) was already built
during phases 3–8. What follows is the set of things that later **backend
feature commits changed the UI-facing contract for**, checked against what the
current Angular app actually consumes. Each item is attributed to the
commit(s) that created the gap.

Backend UI-facing surfaces reviewed:
- `service/fileaccess/diagnostics_linux.go` (`FileAccessDiagnostics`)
- `service/fileaccess/filequery_bridge.go` (`ObservationDiagnostics`)
- `service/fileaccess/decision_pipeline.go` (`DecisionPipelineDiagnostics`)
- `service/fileaccess/prompt_coordinator.go` (`PromptCoordinatorDiagnostics`)
- `service/fileaccess/mount_linux.go` (`MountDiagnostics`)
- `service/fileaccess/config.go` (registered config options)
- `service/fileaccess/prompt_notifications.go` (prompt payload + actions)
- `service/fileaccess/profile_handler.go` / `rule.go` (rule string formats)

UI reviewed under `desktop/angular/src/app/`.

---

## A. Changes required by recent backend features

### A1. Exec is now a real, promptable operation — ✅ verified working (optional polish)
**Verified live 2026-07-20:** injecting a real-PID `op:exec` event produces a normal
prompt (not a hard-deny). The `/prompt` card resolves the profile ("Sleep",
/usr/bin/sleep) and renders `Op: exec (pid …)` with Allow/Block actions. The template
does **not** hardcode open/read verbs — it shows `EventData.Subject.Op` dynamically
(`prompt.html:44`, falling back to `open` only when Op is absent), and exec-scoped
learned rules route to the Execute list (A3). No functional gap remains.
**Optional cosmetic polish only:** the card shows the raw wire token `exec` rather than
the natural verb `execute` (the backend `Message` already says "wants to execute" via
`opVerb`, but the custom card builds its own field table and ignores that message). A
one-line op→verb map in the template would make it read `execute`. Original analysis
kept below for reference.


- **Backend commit:** `eee4db60` (decide exec like read/write instead of hard-deny).
- **What changed:** `OpExec` (`FAN_OPEN_EXEC_PERM`) previously returned an
  unconditional deny before any policy. It now flows through normal rule /
  default-action / prompt evaluation, governed by the launching process's
  profile (`profile_handler.go:445`, `:557`). Verdict, prompt, permanent-rule,
  and post-allow reevaluation paths all now fire for exec.
- **Current UI:** the monitor filter and `opVerb` already know "exec"/"execute",
  so activity rows render. But exec now produces **prompts and learned rules**,
  which the rule editor and prompt copy don't distinguish from open/read/write.
- **UI change needed:**
  - Ensure the prompt card phrasing reads naturally for exec ("… wants to
    **execute** …") — the backend message already uses "execute", verify the
    Angular prompt template doesn't hardcode open/read verbs.
  - Rule editor must be able to show/produce an exec-scoped rule (see A3).
- **Files:** `prompt-entrypoint/prompt.html`, `shared/prompt-list/*`,
  `shared/config/rule-list/*`.

### A2. ~~Diagnostics interface is stale~~ — ✅ DONE (panel removed)
**Resolved differently than proposed:** the "File Access Enforcement" panel was a
raw metrics grid that didn't match Portmaster's UI, so it was **removed** rather than
extended. The backend telemetry (and `GET /api/v1/fileaccess/diagnostics`) stays; the
removed fields + the plan to re-surface them as a Dashboard health tile are tracked in
`docs/dashboard-enforcement-telemetry-todo.md`. Original analysis kept below for
reference.


- **Backend commits:** `76f8402f` (observation drops + missing counters),
  plus the phase-8 diagnostics commits `caf4f7fc`, `1ed7a4ae`, `5de7498b`.
- **What changed:** `FileAccessDiagnostics` grew several fields that the Angular
  `FileAccessDiagnostics` interface in
  `services/fileaccess-diagnostics.service.ts:13` does **not** declare or render:

  | Backend field | Where | Purpose | In Angular type? |
  |---|---|---|---|
  | `Settings{WatchPaths, InterceptReads, RequestedRootAsk, EffectivePipelineConfig}` | diagnostics_linux.go:32 | active vs requested settings | ❌ missing entirely |
  | `Observation{QueueDepth, QueueCapacity, Dropped}` | filequery_bridge.go:22 | dropped activity records (§12.5/§15.21) | ❌ missing |
  | `Reader.LastDecisionLatencyNanos`, `LastResponseLatencyNanos`, `DecisionResponseCount` | fanotify_linux.go | decision/response latency (§15.18/19) | ❌ missing |
  | `Decision.PendingAskByProfile` | decision_pipeline.go:65 | pending Ask per profile (§15.13) | ❌ missing (only aggregate `PendingAsk`) |
  | `Decision.ActiveDecisions`, `QueueSaturationDenies`, `OutstandingBudgetDenies`, `ProfileAskBudgetDenies`, `Closing` | decision_pipeline.go:55 | overload/saturation counters | ❌ missing |
  | `Prompt.Timeouts` | prompt_coordinator.go:310 | prompt-timeout count (§15.16) | ❌ missing |
  | `Mount.DynamicMountCoverageBreach`, `DynamicMountIDs`, `DynamicMountCoverageGaps`, `ScopeActivationPending`, `PendingScopes`, `CoverageKnown` | mount_linux.go:54 | **silent-allow-window / partial-coverage detail** | ❌ missing |

- **Severity note:** most *critical* signals are also emitted through the
  `Warnings[]` array, which the diagnostics panel already renders — so the
  system is not silently broken. But the specific metrics above (dropped
  activity, latency, timeouts, per-profile Ask pressure, and especially the
  **dynamic mount coverage breach**) are not visible as data.
- **UI change needed:** extend the Angular `FileAccessDiagnostics` interface and
  the `fileaccess-diagnostics.component` to surface the new fields — at minimum
  Observation.Dropped, Prompt.Timeouts, the Decision overload counters, and the
  Mount dynamic-coverage-breach block (this last one is a real "protection may
  have been bypassed" indicator and should be prominent).
- **Files:** `services/fileaccess-diagnostics.service.ts`,
  `pages/settings/fileaccess-diagnostics.component.ts` / `.html`.

### A3. ~~Rule editor doesn't understand the new tagged rule syntax~~ — ✅ DONE
**Resolved by restructuring, not by teaching the editor tags:** rules are now split
into three per-operation config lists (`fileaccess/readRules` / `writeRules` /
`execRules`), so the list carries the operation and stored patterns are plain paths/
globs — no `@op:` tags in the UI. The existing Portmaster rule-list editor renders all
three (Read/Write/Execute Rules) at both global and per-app scope with zero custom UI.
Original analysis kept below for reference.


- **Backend commits:** the permanent-rules series (`648851f0` … `3c6e3dd1`),
  formats in `profile_handler.go:680` (`FormatExactRule`) and `:688`
  (`FormatExactOperationRule`), model in `rule.go` (`PathRule.Exact`,
  `Operation`, `OperationScoped`, `DirectoryOnly`).
- **What changed:** learned "Always" rules are now persisted as tagged strings,
  not plain `+ /path` patterns:
  - exact path: `+ @"/home/u/f"`
  - operation-scoped: `+ @exec:"…"`, `- @read:"…"`, `+ @open:"…"`
  - directory-scoped: `+ @dir-open:"…"`, `- @dir-read:"…"`
- **Current UI:** `shared/config/rule-list/rule-list.ts:43` only knows
  `'+' → Allow`, `'-' → Block`. It treats everything after the sign as an opaque
  pattern. The `@…:"…"` payload renders as raw text and is trivially corrupted
  by hand-editing; no operation/exact/directory affordance exists. No Angular
  component references `fileaccess/rules`, `@exec`, `@read`, or `OperationScoped`.
- **UI change needed:** a file-access-aware rule editor (or an extension of
  `rule-list`) that parses/renders exact vs pattern, the operation (open / read /
  exec), and directory-only flags as structured chips, and emits the tagged
  format on save. Wire it into the per-app **Settings** tab for the
  `fileaccess/rules` key (`service/profile/config.go:30`).
- **Files:** `shared/config/rule-list/*`, `pages/app-view/app-view.html`
  (Settings tab), the generic `settings-view` for scoped config.

### A4. New backend config options need curated settings UI — mostly already covered
**Verified 2026-07-20 (answers "isn't there already a path-list editor?"):** yes.
`watchPaths` is a plain `StringArray`, so the generic config renderer already shows it
as an add/remove **path-list editor** via `<app-ordered-list>`
(`shared/config/generic-setting/generic-setting.html:135`) — no custom code. The
restart-required tuning knobs (`decisionWorkers` etc., all `RequiresRestart:true`)
**already get a "Saved – Restart required" cue** with a click-to-restart affordance
(`generic-setting.html:20-32`). `interceptReads` renders as a normal bool toggle. So the
functional part of A4 is **already done by generic rendering**; only *cosmetic curation*
remains and is optional: a real directory **picker** (vs typing paths) and a prominent
in-place warning when `/` is entered (whole-system monitoring — the backend Description
already warns of this). Low priority. Original analysis kept below for reference.


- **Backend commit:** `caf4f7fc` (phase-8 diagnostics and rollout controls),
  registered in `config.go:26-31`, `:97-188`.
- **What changed:** new options — `fileaccess/watchPaths`,
  `fileaccess/interceptReads`, and the restart-required tuning knobs
  `decisionWorkers`, `decisionQueueCapacity`, `outstandingEventLimit`,
  `perProfileAskLimit`, plus `rootAskRequested`.
- **Current UI:** settings renders generically from registered options
  (`pages/settings/settings.ts`), so these appear as raw int/bool inputs with
  no grouping or guidance. `watchPaths` (the core "what is protected" control)
  gets no special treatment; the restart-required knobs give no restart cue in
  place.
- **UI change needed:** curate the "File Access" settings category — a proper
  path-list editor for `watchPaths`, a clear on/off for `interceptReads`, and
  a "requires restart" affordance on the tuning knobs. Low priority for the
  tuning knobs; **higher** for `watchPaths` since it defines protection scope.
- **Files:** `pages/settings/*`, `shared/config/*`.

### A5. Root-Ask rollout gate — ✅ DONE (verified live)
**Verified live 2026-07-20:** the removed diagnostics panel used to render
`RootAskGate.Reasons`, but the user-facing gate signal does **not** depend on it.
`diagnostics_linux.go:156` emits a `root-ask-gate` warning whenever
`RootAskGate.Requested && !Open`, and `refreshWarningStates()` (module.go:217, 1 s
ticker) pushes it into module state as `mgr.State{ID:"fileaccess/root-ask-gate",
Name:"File Access Enforcement", …}`. Toggling `fileaccess/rootAskRequested` on made the
security-lock shield flip to **Warning** with a **"File Access Enforcement"**
notification carrying the message "Root scope Ask mode remains blocked until all rollout
evidence is current." (screenshot `tmp/a5-rootask-dashboard.png`); toggling it back off
cleared the state. So "requested but blocked" reaches the user via the shield +
notifications list, independent of the removed panel.
**Note:** the detailed `Reasons[]` list (e.g. `environment_evidence_stale`) is no longer
surfaced anywhere in the UI — only the single generic warning is. That is acceptable
(the reasons are internal rollout-evidence tokens, not user-actionable) and can be
re-added later alongside the Dashboard enforcement-health tile
(`docs/dashboard-enforcement-telemetry-todo.md`) if desired.

Original note kept below for reference.

- **Backend commits:** `84be0cb0`, `caf4f7fc` (rollout evidence + gate).
- **State:** the diagnostics panel already renders `RootAskGate{Requested, Open,
  Reasons}` and there's a `root-ask-gate` warning. This appears **aligned**;
  only verify the "requested but blocked" messaging matches the backend reasons
  list. No new work expected beyond A2's interface extension if any RootAskGate
  sub-field changed.


---

## B. Already aligned — do NOT redo

- **Prompt rendering:** `prompt-entrypoint/*` and `shared/prompt-list/*` filter
  on `EventID` `fileaccess:` and parse `EventData.Profile` / `EventData.Subject`
  (PID, Exe, Path, Op). No network/Entity/scope fields remain in the prompt.
- **Monitor page:** `pages/monitor/*` + `shared/filequery-viewer/*` show the
  file-access activity table (time, app, op, verdict, path, profile, exe) with
  op/verdict/path/app filters, backed by `filequery/query`.
- **Per-app events:** `pages/app-view` "File Events" tab embeds the
  filequery-viewer filtered by profile.
- **Degraded state:** `mgr.State` warnings flow to `shared/security-lock` (shield
  color) and to the diagnostics panel's warnings list; navigation shows a
  new-prompt badge.
- **Diagnostics panel skeleton:** `pages/settings/fileaccess-diagnostics.*`
  already exists — A2 is an extension of it, not a rewrite.

---

## C. Leftover network UI surfaced by the rewrite (remove or repurpose)

These are from the earlier network→file transition, not the recent commits, but
a reviewer aligning UI to the backend will hit them:

- **Dashboard mini-stats** (`pages/dashboard/dashboard.component.html:80-93`):
  still labeled "Connections Blocked / Active Connections" and query the monitor
  with **network** params (`verdict:3 verdict:4`, `groupBy: ['country']`). The
  filequery backend has no such verdicts or country grouping, so these tiles are
  broken/empty. Relabel to file-access counts (allowed/blocked/apps) and fix the
  queries, or remove.
- **Sidebar `network-scout`** (`shared/network-scout/*`, used in
  `layout/side-dash/side-dash.html`): sorts apps by connection counts /
  bandwidth / SPN identity — none of which exist for file access. Repurpose to
  file-access activity per app, or remove.
- **`netquery` module reuse** (`shared/netquery/*`): the line chart
  (`sfng-netquery-line-chart`) is reused by the filequery viewer. Functional but
  misnamed; optional cleanup/rename, not urgent.
- **SPN pages** (`pages/spn/*`, `shared/spn-*`, `country-flag`): standalone
  feature, unrelated to file-access core — leave as-is.

---

## Suggested priority

1. **A3** (tagged rule editor) and **C dashboard** — user-facing correctness:
   learned rules are otherwise unreadable/corruptible, and the dashboard shows
   broken network stats.
2. **A2** (diagnostics fields, esp. dynamic-mount-coverage-breach + dropped
   activity) — surfaces real enforcement-gap signals.
3. **A4** `watchPaths` editor — defines protection scope.
4. **A1** verb copy, **A5** verify, **C sidebar** repurpose.
5. **A6** one-time actions and **A4** tuning knobs — only on product decision.
