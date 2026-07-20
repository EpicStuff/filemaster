# Fanotify Phase 8 Verification Matrix

This matrix records the ordinary Phase 8 implementation state at commit time.
Host-dependent verification is deliberately not inferred from unit tests.

| Area | Production implementation | Automated coverage | Host command / current result | Blocker |
| --- | --- | --- | --- | --- |
| Mount identity, nested and bind mounts, staged scopes | `service/fileaccess/mount_linux.go`, `fanotify_linux.go` | `mount_linux_test.go` | `go test ./service/fileaccess -run 'Test.*Mount\|Test.*Scope'` | None for unit coverage; real namespace test remains opt-in. |
| Owned events and response writes | `pending_event.go`, `response_writer_linux.go` | `pending_event_test.go`, `response_writer_linux_test.go` | `go test ./service/fileaccess -run 'Test.*Pending\|Test.*Response'` | Kernel response writes need fanotify capability for host confirmation. |
| Descriptor accounting and reader structural failures | `fanotify_linux.go` | `fanotify_reader_linux_test.go` | `go test ./service/fileaccess -run 'Test.*Reader\|Test.*Malformed\|Test.*Metadata'` | None for deterministic coverage. |
| Worker queue and budgets | `decision_pipeline.go` | `decision_pipeline_test.go` | `go test ./service/fileaccess -run 'Test.*Pipeline\|Test.*Queue\|Test.*Budget'` | None. |
| Immutable profile snapshots | `profile_handler.go`, `profile_lookup.go` | `profile_handler_test.go`, `profile_snapshot_test.go` | `go test ./service/fileaccess -run 'Test.*Snapshot'` | None. |
| Prompt grouping and revision reevaluation | `prompt_coordinator.go` | `prompt_coordinator_test.go`, `prompt_coordinator_phase5_test.go` | `go test ./service/fileaccess -run 'Test.*Prompt'` | None. |
| Permanent rule durability | `permanent_rules.go`, profile record transactions | `permanent_rules_test.go`, profile tests | `go test -race ./service/fileaccess -run TestPermanentRules` | None for deterministic persistence cases. |
| Controlled shutdown | `lifecycle.go`, `shutdown.go` | `shutdown_test.go`, `fanotify_shutdown_linux_test.go` | `go test -race ./service/fileaccess -run TestShutdown` | None for deterministic shutdown paths. |
| Settings and effective limits | `config.go`, `module.go` | `phase8_test.go` | `go test ./service/fileaccess -run 'TestConfiguredDecision\|TestPipelineSettings'` | Restart is required for queue/worker/budget changes by design. |
| Diagnostics and degraded warnings | `diagnostics_linux.go` | `phase8_test.go` | `go test -race ./service/fileaccess -run TestDiagnostics` | UI presentation is config/status driven; detailed descriptor IDs remain privileged-only. |
| Matching settings UI | Existing dynamic settings renderer, `fileaccess` subsystem registration, and the settings diagnostics panel | component and HTTP endpoint service specs | Focused Karma specs and `npx playwright test playwright/file-access.spec.ts --project=chromium --workers=1 --reporter=line` — **passed** | Dev server compiled successfully; inspected `tmp/fileaccess-settings-live.png` shows live running diagnostics. |
| Fake-source ownership parity | `socket_source.go` uses `PendingEvent`/`deliverPendingEvent` | socket and pipeline tests | `go test -tags filemaster_test ./service/fileaccess -count=1` | Socket transport lacks kernel-only mount/FD behavior; confined source covers that. |
| Confined fanotify integration | `fanotify_confined_integration_linux_test.go` | `TestConfinedFanotifyIntegration` | `FM_FANOTIFY_INTEGRATION=1 go test ./service/fileaccess -run '^TestConfinedFanotifyIntegration$' -count=1 -v -timeout=45s` — **passed** | Private mount namespace and temporary bind mount only; `/` is never marked. |

> **Removed after Phase 8:** the root-scope Ask rollout gate and its host
> verification apparatus (`rollout_gate_linux.go`, `rollout_gate_other.go`,
> `cmds/fanotify-confined-pipeline`, `docs/fanotify-systemd-host-verification.md`,
> the `fileaccess/rootAskRequested` option, and the `root-ask-gate` warning)
> were deleted. The gate only ever suppressed interactive prompting under
> whole-system (`/`) watch; prompts now flow through the normal
> rule/default-action/prompt path regardless of scope. The three former matrix
> rows for the confined-pipeline harness and the Ask gate are dropped
> accordingly. See `FORK_NOTES.md`.

## Independent architecture review follow-up

The final independent review verdict was **ACCEPT WITH NONBLOCKING FINDINGS**.
There were no Blocker or High findings and no root-gate bypass. Every confirmed
correctness finding was resolved before Phase 8 completion:

| Finding | Resolution | Focused coverage |
| --- | --- | --- |
| R1/R2: malformed fanotify batch ownership and untrusted frame advancement | `fanotify_linux.go` now accounts only safely framed fixed-prefix descriptors, never advances through an untrusted length, explicitly records an unparseable tail, denies/closes safely identified ownership, and closes the source after fatal framing loss. | `fanotify_reader_linux_test.go`: malformed A/B/C tail and suspicious metadata-version length cases. |
| P1: coordinator-less Always persistence | `ProfileHandler` routes accepted coordinator-less Always actions through `RulePersistence`, so the immutable dirty overlay, serialized write, retry, and diagnostics apply identically. | `TestProfileHandlerCoordinatorlessAlwaysUsesDurableOverlayAndRetry`. |
| S1: mark-removal failures after Closed | `diagnostics_linux.go` publishes `shutdown-mark-removal-failed` until final mark removal is genuinely complete, including after `LifecycleClosed`. | `TestShutdownMarkRemovalFailureWarningSurvivesClosed`. |
| P2: equal-revision divergent merge | `RulePersistence.Merge` compares policy content as well as revision. A successful durable write records its canonical exact base rule, so an equal-revision external removal/change cannot be mistaken for an identical reload. | `TestPermanentRulesEqualRevisionDivergenceDoesNotRestoreCleanRule`. |
| P3: per-profile persistence worker lifetime | Idle writers retire after a bounded idle interval. Shutdown performs one reporting-bounded flush, then seals admission and joins every writer without a reporting-deadline escape. | `TestPermanentRulesRetireIdleWorkersAndStopWithoutDiscardingDirtyState`, `TestPermanentRulesStopWaitsForBlockedWorkerAfterFlushDeadline`, `TestShutdownWaitsForBlockedPermanentRuleWorkerAfterReport`. |
| R3: redundant accounting | `handleEvent` now routes only pre-accounted descriptors; accounting remains visibly before path resolution and policy. | `TestShutdownResponseFailureRemainsExplicitlyOwned` and reader batch tests. |
| S2: fake reader lifecycle parity | The fake source reports running/exited state, group closure unblocks the reader, and reader-exit/accounting behavior is covered. | `TestFakeSourceReportsReaderLifecycleAndGroupClosure`. |

The exact file-access Playwright command,
`cd desktop/angular && npx playwright test playwright/file-access.spec.ts --project=chromium --workers=1 --reporter=line`,
now passes. The prior startup deadlock was corrected by restoring the
documented caller-owned record lock contract for runtime push functions.

The exact `go test ./... -count=1` command was also run. All relevant Phase 8
packages passed; the overall suite remains blocked only by
`service/core/base`, whose `TestDefaultAPIPortMatchesUIConstants` cannot find
its expected UI `DEFAULT_PORT` constant. That path is not modified by this
Phase 8 work.
