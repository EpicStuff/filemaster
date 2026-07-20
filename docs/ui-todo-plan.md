# UI alignment plan

## Purpose

Replace every dashboard surface that relies on the removed network backend with
truthful file-access information. Existing cards retain their current order,
grid location, and size, except that the empty Features card is deleted. New
enforcement cards are appended after News. The News widget remains unchanged
for future Filemaster news.

The current CSS grid reserves a two-row `feature` area. Delete it and make sure to
keep the relative positions/size/shape of the existing cards that are being replaced.

## Current collector limits

- The fanotify source currently emits open permission events, optional read
  permission events, and execute permission events. `echo test > somefile`
  first produces a file-open permission request; the event does not disclose
  that the application used a write-only open mode. Reads are disabled by
  default because they occur per read syscall. The source does not emit a write
  permission event, so the dashboard must not report a write count or an
  allowed/blocked write verdict.
- The service does not retain a live table of open file descriptors. It can
  report recent open attempts, but not which applications currently hold files
  open.

## Dashboard card mapping

| Dashboard order and existing card | Replacement | Data and behaviour |
| --- | --- | --- |
| `features` / Features (currently empty) | **Delete** | This is an SPN package-feature container. |
| `stats` / Recent Activity | **Recent File Activity** | Keep the six existing mini-stat positions. The exact old-to-new mapping is below. Each available count links to the matching Monitor filter. |
| `news` / News | **News** | Leave unchanged for future Filemaster news. |
| `charts` / Active/Blocked Connections | **Access Decisions over Time** | Replace the first existing chart panel with allowed and blocked file-access decisions over time. |
| `charts` / Connections Tunneled through SPN | **File Operations over Time** | Replace the second existing chart panel with opens, optional reads, and executes over time. It remains the second panel inside the existing `charts` widget. |
| `blocked` / Recently Blocked Applications | **Recently Blocked Applications** | Preserve the card, but group denied file-access records by application and link each row to the app/Monitor view. |
| `countries` / Recent Connections per Country | **Recent Mount Protection** | Use diagnostics data rather than a fabricated historical group-by: configured scopes, active mount count, missing mount count, and named dynamic coverage gaps. |
| `connmap` / Recent Connection Countries map | **Protected Mounts** | Reuse the large map-sized slot for the sole detailed mount-coverage view: protected/partial/unknown state, active and missing mount IDs, pending scopes, and named coverage gaps. |
| `bwvis-bar` / Recent Top Consumers | **Most Active Applications** | Keep the large slot, but rank applications by recent file-access operations instead of transferred bytes. |
| `bwvis-line` / Recent Bandwidth Usage | **File Operations by Type** | Keep the large slot for an operation-focused time chart: opens, optional reads, and executes. |
| new cards | **File Access Enforcement** | Append the three compact enforcement cards described below. They are new cards; no existing card is moved to make space for them. |

### Recent File Activity mini-stat mapping

| Existing mini-stat | Replacement | Notes |
| --- | --- | --- |
| Connections Blocked | **Access Blocked** | Denied file-access decisions. |
| Active Connections | **File Opens** | Recent open permission requests; this is an event count, not a live-open-file count. |
| Active Apps | **Recent Applications** | Distinct applications with file-access activity in the selected recent window. |
| Data Received | **Reads** | Available only while read interception is enabled; otherwise state that it is not monitored. |
| Data Sent | **Writes** | State “not collected” until a backend write-observation feature exists; never show a misleading zero. |
| SPN Identities | **Executes** | Recent execute permission requests. |

## Bottom enforcement cards

The old settings diagnostics table is not restored. Append three compact,
independently meaningful cards after News:

```text
┌ Enforcement State ──────────┐ ┌ Decision Pipeline ─────────┐ ┌ Event Delivery ────────────┐
│ ● Running                   │ │ ● Healthy                  │ │ ● Healthy                  │
│ 0 warnings                  │ │ 0 prompts · 4 / 4 workers  │ │ 0 dropped · queue 2 / 128  │
│ read monitoring: off        │ │ 0 overload denies          │ │ response latency: 4 ms      │
└─────────────────────────────┘ └────────────────────────────┘ └────────────────────────────┘
```

Each status uses green for healthy, yellow for a recoverable warning, and red
for degraded protection or data loss. The individual cards show:

1. **Enforcement State** — lifecycle/degraded state, warnings, and whether
   read interception is enabled. Mount coverage is intentionally shown only in
   **Protected Mounts**, not duplicated here.
2. **Decision Pipeline** — prompts, queue
   pressure, worker availability, and overload denials.
3. **Event Delivery** — dropped observations, failed responses, descriptor
   pressure, and latency. It warns when activity cannot be fully observed or
   answered.

The existing security-lock state remains the primary immediate alert mechanism;
these cards explain its health signals without duplicating a diagnostics table.

## Confirmed layout decisions

1. Delete the empty Features card; do not replace it in its existing slot.
2. Keep News for future Filemaster news.
3. Keep existing cards in their current locations and sizes. Deleting Features
   leaves its reserved grid area blank unless a later layout decision permits
   the cards below it to move.
4. Split the two existing chart panels into separate table rows and keep them
   as separate chart panels in the same widget.
5. Use **Protected Mounts** as the only detailed mount-coverage surface.
6. Append the new File Access Enforcement cards after News.

## Potential backend extensions

These are deliberately not UI substitutions. They require a separately scoped
backend change before the corresponding dashboard values can be real.

1. **Live open-file applications:** retain allowed opens by process and file
   identity, consume close notifications, clean entries on process exit and
   queue overflow, and expose a bounded API. An on-demand `/proc/<pid>/fd`
   scan is an alternative snapshot mechanism, but is too expensive and
   permission-sensitive for a continuously refreshed dashboard.
2. **Write activity:** consume `FAN_CLOSE_WRITE` notifications to observe that
   data was written after the fact. Linux fanotify has no separate write
   permission event, so this cannot become a pre-write allow/deny decision
   without a different enforcement design.
3. **TODO — historical activity by mount:** this is the separate backend task
   for “recent protected mounts.” Enable and parse fanotify's `FAN_REPORT_MNT`
   mount-ID information record, then persist the mount ID and display path with
   each file-access record. Update the storage schema, query API,
   retention/migration path, and tests. Until then, mount cards use real-time
   coverage telemetry only.

## Follow-on UI cleanup

After the dashboard is complete, remove or repurpose the remaining network-era
surfaces: the network scout side-dash; residual SPN profile subscription and
netquery callers with no file-access replacement; per-app Insights and
Internet/History quick settings; network-history and active-connection header
details; and stale Portmaster-era side-dash, feature-scout, intro, support, and
Tauri-shell claims. Retain standalone SPN pages unless their separate scope is
changed. Extend E2E coverage so missing backend data cannot leave empty or
broken widgets behind.
