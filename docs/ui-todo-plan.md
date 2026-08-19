# UI alignment plan

## Purpose

Replace every dashboard surface that relies on the removed network backend with truthful file-access information. Existing cards retain their current order, relative grid location, and size. The empty Features card is deleted. New enforcement cards are added to the bottom. The News widget remains unchanged for future Filemaster news.

The current CSS grid reserves a two-row `feature` area. Delete it and make sure to keep the size/shape/relative positions of the existing cards that are being replaced.

Implemented: the dashboard now uses the current fanotify backend and presents
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

## Dashboard card mapping


| Dashboard order and existing card            | Replacement                       | Data and behaviour                                                                                                                           |
| -------------------------------------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `features` / Features (currently empty)      | **Delete**                        | This is an SPN package-feature container.                                                                                                    |
| `stats` / Recent Activity                    | **Recent File Activity**          | Keep the six existing mini-stat positions. The exact old-to-new mapping is below. Each available count links to the matching Monitor filter. |
| `news` / News                                | **News**                          | Leave unchanged for future Filemaster news.                                                                                                  |
| `charts` / Active/Blocked Connections        | **Open Decisions over Time**      | Replace the first existing chart panel with allowed and blocked Open decisions over time.                                                    |
| `charts` / Connections Tunneled through SPN  | **Execute Decisions over Time**  | The current panel is hidden unless SPN is enabled. Replace it with an always-rendered Execute chart in the same second panel position.       |
| `blocked` / Recently Blocked Applications    | **Recently Blocked Applications** | Preserve the card, group denied file-access records by application, and link each row to that application's app page, matching Portmaster.    |
| `countries` / Recent Connections per Country | **Recently Protected Mounts**     | Render every returned mount in Portmaster's responsive list style: coverage badge, mount path, and literal `-1` placeholder number. Order degraded/pending mounts first, then the most recently active protected mounts. Each row links to Monitor with that mount filter. Empty state is an empty list. |
| `connmap` / Recent Connection Countries map  | **Protected Mounts**              | Reuse the large map-sized slot for the full per-mount coverage and recent-activity table described below.                                    |
| `bwvis-bar` / Recent Top Consumers           | **Most Active Applications**      | rank applications by recent file-access operations instead of transferred bytes.                                                             |
| `bwvis-line` / Recent Bandwidth Usage        | **Opens and Executes**            | operation-focused time chart: Open and Execute only.                                                                                         |
| new cards                                    | **Open Enforcement**              | Append the three compact enforcement cards described below. They are new cards; no existing card is moved to make space for them.            |

### Protected Mounts display

The large **Protected Mounts** card is the detailed view for both protection
coverage and recent per-mount activity. Its header shows a single coverage
badge: **Protected**, **Partial**, or **Unknown**, followed by active and
missing mount counts. Its table contains:


| Mount path | Coverage  | Open allowed | Open blocked | Execute allowed | Execute blocked |
| ---------- | --------- | ------------ | ------------ | --------------- | --------------- |
| `/home`    | Protected | 128          | 3            | 4               | 0               |

Below the table, show pending scopes and dynamic mount coverage gaps with their
affected paths. A missing, pending, or dynamically breached mount makes the
coverage badge warning/red even if its recent activity counts are zero.

### Recent File Activity mini-stat mapping


| Existing mini-stat  | Replacement              | Notes                                                                          |
| ------------------- | ------------------------ | ------------------------------------------------------------------------------ |
| Connections Blocked | **File Blocked**         | Denied file open/execute decisions.                                            |
| Active Connections  | **Folder Blocked**       | Denied folder open                                                             |
| Active Apps         | **Recent Applications**  | Distinct applications with file-access activity in the selected recent window. |
| Data Received       | **Open Allowed**         | Allowed Open decisions.                                                        |
| Data Sent           | **future write allowed** | Leave blank or show TODO text; no metric until Write is enforceable.           |
| SPN Identities      | **Executes Allowed**     | Allowed File Execute decisions.                                                |

## Bottom enforcement cards

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

## Confirmed layout decisions

1. Delete the empty Features card; do not replace it in its existing slot.
2. Keep News for future Filemaster news.
3. Use **Protected Mounts** as the only detailed mount-coverage surface.
4. Implemented after the fanotify backend rewrite; exposes only current Open
   and Execute semantics.

## Potential backend extensions

These are deliberately not UI substitutions. They require a separately scoped backend change before the corresponding dashboard values can be real.

1. **Live open-file applications:** retain allowed opens by process and file identity, consume close notifications, clean entries on process exit and queue overflow, and expose a bounded API. An on-demand `/proc/<pid>/fd` scan is an alternative snapshot mechanism, but is too expensive and permission-sensitive for a continuously refreshed dashboard.
2. **Write activity:** defer this until the selected backend can enforce it.
   The current UI must not add a fanotify write metric or show a Write card
   before that enforcement exists.

## Follow-on UI cleanup

After the dashboard is complete, remove or repurpose the remaining network-era surfaces: the network scout side-dash; residual SPN profile subscription and netquery callers with no file-access replacement; per-app Insights and Internet/History quick settings; network-history and active-connection header details; and stale Portmaster-era side-dash, feature-scout, intro, support, and Tauri-shell claims. Retain standalone SPN pages unless their separate scope is changed. Extend E2E coverage so missing backend data cannot leave empty or broken widgets behind.
