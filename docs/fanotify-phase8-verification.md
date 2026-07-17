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
| Real PID 1 systemd safety | `docs/fanotify-systemd-host-verification.md` | Manual host runbook and systemd-managed helper probe | Temporary-scope `systemd-run` probe — partial **passed** | Startup, real helper fanotify receipt, accounting, and shutdown passed; interactive prompt approval, audit, and profile UI evidence remain incomplete. |
| Root pipeline benchmark | Existing `cmds/fanotify-root-bench` measures transport only | Harness emits JSON transport measurements | `go build -o /tmp/fanotify-root-bench-bin ./cmds/fanotify-root-bench` followed by the commands in its README | **Incomplete:** the existing harness does not exercise the complete Filemaster profile, prompt, persistence, and observation pipeline. Root Ask evidence cannot be recorded from it. |
| Root scope Ask gate | `rollout_gate_linux.go`, `profile_handler.go` | `phase8_test.go` | `go test ./service/fileaccess -run TestRootAskGate` | Closed: systemd host and root benchmark evidence are absent. Evidence is a private 0600 data-dir record, never a browser setting. |

The exact file-access Playwright command,
`cd desktop/angular && npx playwright test playwright/file-access.spec.ts --project=chromium --workers=1 --reporter=line`,
now passes. The prior startup deadlock was corrected by restoring the
documented caller-owned record lock contract for runtime push functions.

The exact `go test ./... -count=1` command was also run. All relevant Phase 8
packages passed; the overall suite remains blocked only by
`service/core/base`, whose `TestDefaultAPIPortMatchesUIConstants` cannot find
its expected UI `DEFAULT_PORT` constant. That path is not modified by this
Phase 8 work.

The Phase 8 root Ask gate defaults closed. Its browser-visible request switch
does not supply verification evidence. A trusted backend host-verification
recorder calls `FileAccess.RecordRootAskRolloutEvidence`, which atomically
writes `<data-dir>/fileaccess-root-ask-rollout-evidence.json` with mode 0600;
there is deliberately no API endpoint or configuration option that can write
this record. The recorder derives the implementation version, effective worker
and descriptor settings, and current Linux kernel environment itself. A missing
record, write/read error, implementation change, settings change, or kernel
environment change closes the gate again. Trusted verification must provide
confined integration, systemd PID 1, benchmark, shutdown, persistence, and
prompt grouping evidence.
