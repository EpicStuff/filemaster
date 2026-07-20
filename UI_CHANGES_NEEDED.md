# UI changes needed to reflect the backend rewrite

Status: **A2, A3 and A5 are done** and have been removed from this list
(A5 became moot — the root-scope Ask rollout gate was ripped out entirely; see
`FORK_NOTES.md`). **What remains:** the section C network-UI cleanup (the real
work), optional polish on A1 and A4, and a product decision on A6.

## How this list was derived

This is a *delta* analysis, not a from-scratch UI audit — the set of things that
later backend feature commits changed the UI-facing contract for, checked against
what the current Angular app (`desktop/angular/src/app/`) actually consumes.

Backend UI-facing surfaces worth re-checking when touching this area:
- `service/fileaccess/diagnostics_linux.go` (`FileAccessDiagnostics`)
- `service/fileaccess/filequery_bridge.go` (`ObservationDiagnostics`)
- `service/fileaccess/decision_pipeline.go` (`DecisionPipelineDiagnostics`)
- `service/fileaccess/prompt_coordinator.go` (`PromptCoordinatorDiagnostics`)
- `service/fileaccess/mount_linux.go` (`MountDiagnostics`)
- `service/fileaccess/config.go` (registered config options)
- `service/fileaccess/prompt_notifications.go` (prompt payload + actions)
- `service/fileaccess/profile_handler.go` / `rule.go` (rule string formats)

---

## A. Remaining feature-driven items

### A1. Exec prompt verb — optional polish only
Exec is fully working (verified live 2026-07-20: a real-PID `op:exec` event
produces a normal prompt showing `Op: exec (pid …)` with Allow/Block, no
hardcoded verb; exec-scoped learned rules route to the Execute list). The only
thing left is cosmetic: the prompt card (`prompt-entrypoint/prompt.html:44`)
prints the raw wire token `exec` rather than the natural `execute`. The backend
`Message` already says "wants to execute" via `opVerb`
(`prompt_notifications.go`), but the custom card builds its own field table and
ignores that message. A one-line op→verb map in the template would make it read
"execute". Low priority.

### A4. `watchPaths` / tuning-knob settings — optional curation only
The functional part is already handled by generic config rendering:
- `watchPaths` (a `StringArray`) gets the add/remove path editor
  `<app-ordered-list>` (`shared/config/generic-setting/generic-setting.html:135`).
- the restart-required tuning knobs (`decisionWorkers`, `decisionQueueCapacity`,
  `outstandingEventLimit`, `perProfileAskLimit`, all `RequiresRestart:true`)
  already show a "Saved – Restart required" cue with click-to-restart
  (`generic-setting.html:20-32`).
- `interceptReads` renders as a normal bool toggle.

Only optional curation remains: a real directory **picker** (vs typing paths) and
a prominent in-place warning when `/` is entered (whole-system monitoring — the
backend option Description already warns of this). Low priority.
- **Files:** `pages/settings/*`, `shared/config/*`.

### A6. One-time prompt actions — needs product decision
The prompt only offers Allow/Block, both of which persist as learned "Always"
rules (backend sends `ActionAllowAlways` / `ActionDenyAlways`,
`prompt_notifications.go:85-88`). There is no "allow once / block once"
non-persisting verdict. Adding one needs a new backend action + a matching button
in the prompt card; gated on a product decision about whether filemaster wants
one-time verdicts.
- **Files:** `service/fileaccess/prompt_notifications.go`,
  `prompt-entrypoint/prompt.html`, `shared/prompt-list/*`.

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
- **Rule editor:** the per-operation Read/Write/Execute rule lists render for
  free with the reused Portmaster rule-list editor at both global and per-app
  scope (this is what closed A3).
- **Degraded state:** `mgr.State` warnings flow to `shared/security-lock` (shield
  color) and surface in the notifications list; navigation shows a new-prompt
  badge.

> Note: the "File Access Enforcement" diagnostics panel was **removed** (that was
> A2). The backend telemetry and `GET /api/v1/fileaccess/diagnostics` stay; the
> removed fields and the plan to re-surface them as a Dashboard health tile are
> tracked in `docs/dashboard-enforcement-telemetry-todo.md`.

---

## C. Leftover network UI surfaced by the rewrite (remove or repurpose) — MAIN REMAINING WORK

These are from the earlier network→file transition, not the recent commits, but
a reviewer aligning UI to the backend will hit them:

- **Dashboard mini-stats** (`pages/dashboard/dashboard.component.html:80-93`):
  still labeled "Connections Blocked / Active Connections" and query the monitor
  with **network** params (`verdict:3 verdict:4`, `groupBy: ['country']`). The
  filequery backend has no such verdicts or country grouping, so these tiles are
  broken/empty. Also the "Data Received/Sent", "SPN Identities", "Active/Blocked
  Connections" chart and "Recent Connections per Country" world map are network
  concepts with no file-access equivalent. Relabel to file-access counts
  (allowed/blocked/apps) and fix the queries, or remove.
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

## Suggested priority (remaining)

1. **C dashboard mini-stats** — user-facing broken network tiles / world map.
2. **C sidebar `network-scout`** — repurpose to file-access per-app activity, or remove.
3. **A4 `watchPaths` curation** and **A1 verb polish** — optional cosmetic.
4. **A6 one-time actions** — only on a product decision.
5. **C `netquery` rename** — low priority; **SPN pages** — leave as-is.
