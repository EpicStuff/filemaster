# UI alignment plan

## Purpose

✅ Completed: every dashboard surface that relied on the removed network backend
now presents truthful file-access information. The empty Features card is
deleted, the News widget remains for future Filemaster news, and the dashboard
uses fanotify for Open and Execute and the BPF LSM backend for structural
Delete, Create, Rename, and Link decisions. Read and Write are not dashboard
metrics; the Write rule list controls structural operations when BPF LSM is active.

## Current backend contract

- Fanotify emits Open (`FAN_OPEN_PERM`) and Execute (`FAN_OPEN_EXEC_PERM`)
  decisions. The BPF LSM backend emits Delete, Create, Rename, and Link decisions
  when structural protection is active. `FAN_ACCESS_PERM`, the `InterceptReads`
  setting, and byte-write events remain unsupported.
- `echo test > somefile` is an Open decision. It may open for writing, but
  fanotify does not reveal that mode, so the same Open rule covers opens for
  reading, writing, or both.
- Read and Write are not dashboard metrics in this release. The user-facing
  Write rule list is active for BPF LSM structural operations and is visible in
  each app's file-access settings. In audit mode it explains would-deny decisions.
- The service does not retain a live table of open file descriptors. It can report recent open attempts, but not which applications currently hold files open.
- Open, Execute, and structural records include mount ID and mount path when
  mount attribution is available.

## Dashboard card mapping — ✅ Completed


| Dashboard order and existing card            | Replacement                       | Data and behaviour                                                                                                                           |
| -------------------------------------------- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `features` / Features (currently empty)      | **Deleted**                       | This SPN package-feature container is removed.                                                                                                |
| `stats` / Recent Activity                    | **Recent File Activity**          | The six mini-stat positions are retained. Each available count links to the matching Monitor filter.                                         |
| `news` / News                                | **News**                          | Leave unchanged for future Filemaster news.                                                                                                  |
| `charts` / connection charts                 | **Open and Execute Decisions over Time** | Two Portmaster-style graph panels: Open and Execute. Each shows allowed (green) and blocked (red) decisions.                             |
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

Below the table, show dynamic mount coverage gaps with their affected paths.
Pending mounts are already represented by their own table row. A missing,
pending, or dynamically breached mount makes the coverage badge warning/red
even if its recent activity counts are zero.

### Recent File Activity mini-stat mapping — ✅ Completed


| Existing mini-stat  | Replacement              | Notes                                                                          |
| ------------------- | ------------------------ | ------------------------------------------------------------------------------ |
| Connections Blocked | **File Opens Blocked**   | Denied file Open decisions only.                                               |
| Active Connections  | **Folder Opens Blocked** | Denied folder Open decisions only.                                             |
| Active Apps         | **Recent Applications**  | Distinct applications with file-access activity in the selected recent window. |
| Data Received       | **Opens Allowed**        | Allowed Open decisions.                                                        |
| Data Sent           | **Write Allowed**        | TODO placeholder; no dashboard metric while byte writes lack a separate decision. |
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

1. **Enforcement State** — lifecycle/degraded state and warnings. The dashboard card identifies fanotify Open and Execute coverage; structural decisions appear in Monitor. Mount coverage is shown only in **Protected Mounts**.
2. **Decision Pipeline** — prompts, queue pressure, worker availability, and overload denials.
3. **Event Delivery** — dropped observations, failed responses, descriptor pressure, and latency. It warns when activity cannot be fully observed or answered.

The existing security-lock state remains the primary immediate alert mechanism; these cards explain its health signals without duplicating a diagnostics table.

## Confirmed layout decisions — ✅ Completed

1. ✅ Deleted the empty Features card without replacing it in its existing slot.
2. ✅ Kept News for future Filemaster news.
3. ✅ Use **Protected Mounts** as the only detailed mount-coverage surface.
4. ✅ Dashboard metrics retain Open and Execute semantics; structural operations
   appear in Monitor and app Write rules.

## Potential backend extensions

These are deliberately not UI substitutions. They require a separately scoped backend change before the corresponding dashboard values can be real.

1. **Live open-file applications:** retain allowed opens by process and file identity, consume close notifications, clean entries on process exit and queue overflow, and expose a bounded API. An on-demand `/proc/<pid>/fd` scan is an alternative snapshot mechanism, but is too expensive and permission-sensitive for a continuously refreshed dashboard.
2. **Write activity:** structural BPF LSM operations are enforced and visible in
   Monitor, but byte writes and writable opens still have no independent Write
   decision. Add a dashboard Write metric only when its scope and source are
   defined so the card does not imply byte-write coverage.

## Follow-on UI cleanup

After the dashboard is complete, remove or repurpose the remaining network-era surfaces: the network scout side-dash; residual SPN profile subscription and netquery callers with no file-access replacement; per-app Insights and Internet/History quick settings; network-history and active-connection header details; and stale Portmaster-era side-dash, feature-scout, intro, support, and Tauri-shell claims. Replace or remove the tracker-blocking and DNS onboarding steps: they make network-product claims and write network settings. Retain standalone SPN pages unless their separate scope is changed. Extend E2E coverage so missing backend data cannot leave empty or broken widgets behind.




- the last 4 cards still need work
