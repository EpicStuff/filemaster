# UI alignment plan

## Purpose

✅ Completed: every dashboard surface that relied on the removed network backend
now presents truthful file-access information. The empty Features card is
deleted, the News widget remains for future Filemaster news, and the dashboard
uses the current fanotify backend and presents
only Open and Execute. It deliberately excludes operations the current backend
cannot enforce: Read and Write are not dashboard metrics.

## Current backend contract

- The backend emits only Open (`FAN_OPEN_PERM`) and Execute
  (`FAN_OPEN_EXEC_PERM`) decisions. Its rewrite removes `FAN_ACCESS_PERM`, the
  `InterceptReads` setting, and runtime `OpWrite` events.
- `echo test > somefile` is an Open decision. It may open for writing, but
  fanotify does not reveal that mode, so the same Open rule covers opens for
  reading, writing, or both.
- Read and Write are not dashboard metrics in this release. Write remains
  hidden from the user-facing rule model until a selected backend can enforce it.
- The service does not retain a live table of open file descriptors. It can report recent open attempts, but not which applications currently hold files open.
- Every Access and Execute record includes its mount ID and mount path when
  mount attribution is available.

## Dashboard card mapping — ✅ Completed


| Dashboard order and existing card            | Replacement                       | Data and behaviour                                                                                                                           |
| -------------------------------------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `features` / Features (currently empty)      | **Deleted**                       | This SPN package-feature container is removed.                                                                                                |
| `stats` / Recent Activity                    | **Recent File Activity**          | The six mini-stat positions are retained. Each available count links to the matching Monitor filter.                                         |
| `news` / News                                | **News**                          | Leave unchanged for future Filemaster news.                                                                                                  |
| `charts` / connection charts                 | **Open and Execute Decisions over Time** | One combined four-series chart: Opens allowed/blocked and Executes allowed/blocked.                                                     |
| `blocked` / Recently Blocked Applications    | **Recently Blocked Applications** | Denied file-access records grouped by application; each row opens the corresponding Monitor profile filter.                                  |
| `countries` / Recent Connections per Country | **Recently Protected Mounts**     | Reuses Portmaster's protection shield: green protected, yellow pending, red degraded; then mount path and literal `-1` placeholder. Degraded/pending mounts sort first, then most recently active protected mounts. Each row links to its Monitor mount filter. Empty state is an empty list. |
| `connmap` / Recent Connection Countries map  | **Protected Mounts**              | The large slot now contains the complete per-mount coverage and recent-activity table below.                                                  |
| `bwvis-bar` / Recent Top Consumers           | **Most Active Applications**      | Applications ranked by recent file-access operations.                                                                                         |
| `bwvis-line` / Recent Bandwidth Usage        | **Opens and Executes**            | Open and Execute decision summary.                                                                                                            |
| new cards                                    | **Enforcement health**            | Three compact enforcement cards: Enforcement State, Decision Pipeline, and Event Delivery.                                                   |

### Protected Mounts display — ✅ Completed

The large **Protected Mounts** card is the detailed view for both protection
coverage and recent per-mount activity. Its header shows a single coverage
badge: **Protected**, **Partial**, or **Unknown**, followed by active and
missing mount counts. Its table contains:


| Mount path | Coverage  | Opens allowed | Opens blocked | Executes allowed | Executes blocked |
| ---------- | --------- | ------------ | ------------ | --------------- | --------------- |
| `/home`    | Protected | 128          | 3            | 4               | 0               |

Below the table, show pending scopes and dynamic mount coverage gaps with their
affected paths. A missing, pending, or dynamically breached mount makes the
coverage badge warning/red even if its recent activity counts are zero.

### Recent File Activity mini-stat mapping — ✅ Completed


| Existing mini-stat  | Replacement              | Notes                                                                          |
| ------------------- | ------------------------ | ------------------------------------------------------------------------------ |
| Connections Blocked | **File Opens Blocked**   | Denied file Open decisions only.                                               |
| Active Connections  | **Folder Opens Blocked** | Denied folder Open decisions only.                                             |
| Active Apps         | **Recent Applications**  | Distinct applications with file-access activity in the selected recent window. |
| Data Received       | **Opens Allowed**        | Allowed Open decisions.                                                        |
| Data Sent           | **Write Allowed**        | TODO placeholder; no metric until Write is enforceable.                        |
| SPN Identities      | **Executes Allowed**     | Allowed File Execute decisions.                                                |

## Bottom enforcement cards — ✅ Completed

The old settings diagnostics table is not restored. Append three compact, independently meaningful cards:

```text
┌ Enforcement State ──────────┐ ┌ Decision Pipeline ─────────┐ ┌ Event Delivery ────────────┐
│ ● Running                   │ │ ● Healthy                  │ │ ● Healthy                  │
│ 0 warnings                  │ │ 0 prompts · 4 / 4 workers  │ │ 0 dropped · queue 2 / 128  │
│ Open + Execute active       │ │ 0 overload denies          │ │ response latency: 4 ms      │
└─────────────────────────────┘ └────────────────────────────┘ └────────────────────────────┘
```

Each status uses green for healthy, yellow for a recoverable warning, and red for degraded protection or data loss. The individual cards show:

1. **Enforcement State** — lifecycle/degraded state and warnings. It identifies the active current-release enforcement as Open and Execute. Mount coverage is intentionally shown only in **Protected Mounts**, not duplicated here.
2. **Decision Pipeline** — prompts, queue pressure, worker availability, and overload denials.
3. **Event Delivery** — dropped observations, failed responses, descriptor pressure, and latency. It warns when activity cannot be fully observed or answered.

The existing security-lock state remains the primary immediate alert mechanism; these cards explain its health signals without duplicating a diagnostics table.

## Confirmed layout decisions — ✅ Completed

1. ✅ Deleted the empty Features card without replacing it in its existing slot.
2. ✅ Kept News for future Filemaster news.
3. ✅ Use **Protected Mounts** as the only detailed mount-coverage surface.
4. ✅ Implemented after the fanotify backend rewrite; exposes only current Open
   and Execute semantics.

## Potential backend extensions

These are deliberately not UI substitutions. They require a separately scoped backend change before the corresponding dashboard values can be real.

1. **Live open-file applications:** retain allowed opens by process and file identity, consume close notifications, clean entries on process exit and queue overflow, and expose a bounded API. An on-demand `/proc/<pid>/fd` scan is an alternative snapshot mechanism, but is too expensive and permission-sensitive for a continuously refreshed dashboard.
2. **Write activity:** defer this until the selected backend can enforce it.
   The current UI must not add a fanotify write metric or show a Write card
   before that enforcement exists.

## Follow-on UI cleanup

After the dashboard is complete, remove or repurpose the remaining network-era surfaces: the network scout side-dash; residual SPN profile subscription and netquery callers with no file-access replacement; per-app Insights and Internet/History quick settings; network-history and active-connection header details; and stale Portmaster-era side-dash, feature-scout, intro, support, and Tauri-shell claims. Retain standalone SPN pages unless their separate scope is changed. Extend E2E coverage so missing backend data cannot leave empty or broken widgets behind.
