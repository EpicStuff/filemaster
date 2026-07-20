# TODO: re-add file-access enforcement telemetry to the Dashboard

## Why this exists

The global Settings page used to host a **"File Access Enforcement"** panel — a grid
of read-only runtime telemetry (no settings). It was removed because a raw metrics grid
does not match Portmaster's UI idiom (see the read/write/execute rules rework). The
**backend telemetry was not removed**: it is still computed and still served at

```
GET /api/v1/fileaccess/diagnostics   ->  service/fileaccess/diagnostics_api_linux.go
                                          (module.Diagnostics(), FileAccessDiagnostics)
```

The plan is to re-surface the important signals later on the **Dashboard** as a compact
enforcement-health tile / indicator (Portmaster-idiomatic), rather than a metrics table.

The Angular component + service that rendered the grid were deleted:
- `desktop/angular/src/app/pages/settings/fileaccess-diagnostics.component.*`
- `desktop/angular/src/app/services/fileaccess-diagnostics.service.*`

Any re-add should read the same still-present API.

## What the removed grid displayed (all read-only)

| Group | Fields (from `FileAccessDiagnostics`) |
|---|---|
| Lifecycle badge | `lifecycleState` (Running / degraded / closing) |
| Decision pipeline | `Decision.ActiveWorkers`, `Decision.ExpectedWorkers`/`Workers`, `Decision.QueueDepth`, `Decision.Outstanding` |
| Prompts | `Prompt.Groups`, `Prompt.Events`, `Decision.PendingAsk` |
| Descriptors | `Reader.DescriptorPressure`, `Reader.OutstandingDescriptors` / `Reader.DescriptorLimit`, `FailedResponseCount` |
| Mount coverage | `Mount.ActiveMountIDs`, `Mount.MissingMountIDs`, `Mount.PartialCoverage` |
| Permanent rules | dirty-rule count, persistence failure |
| Shutdown | `Shutdown.Marks.Pending`/`Complete`, `Shutdown.Unresolved` |
| ~~Root-scope Ask rollout~~ | ~~`RootAskGate.Open`, `RootAskGate.Reasons`~~ — **gone:** the root-Ask rollout gate was removed entirely (see `FORK_NOTES.md`); these fields no longer exist. |
| Warnings | `Warnings[]` (with `Severity`) |

## Backend fields that exist but were never surfaced (also worth a tile)

These were added by later backend commits and are the highest-signal for a health
indicator (see the original delta review):

- `Observation.Dropped` / `QueueDepth` / `QueueCapacity` — dropped activity records.
- `Prompt.Timeouts` — prompt-timeout count.
- `Decision.PendingAskByProfile`, `ActiveDecisions`, `QueueSaturationDenies`,
  `OutstandingBudgetDenies`, `ProfileAskBudgetDenies`, `Closing` — overload/saturation.
- `Reader.LastDecisionLatencyNanos`, `LastResponseLatencyNanos`, `DecisionResponseCount`.
- `Mount.DynamicMountCoverageBreach`, `DynamicMountIDs`, `DynamicMountCoverageGaps`,
  `ScopeActivationPending`, `PendingScopes`, `CoverageKnown` — **partial-coverage / silent
  allow-window detail; the most important "protection may have been bypassed" signal.**

## Note

The critical safety signals (degraded / coverage breach / warnings) already reach the
user independently of this panel via `mgr.State` → the security-lock shield color, so
removing the panel did not silence alerting. A Dashboard tile is an enhancement, not a
gap fix.
