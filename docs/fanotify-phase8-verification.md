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
| Matching settings UI | Existing dynamic settings renderer and `fileaccess` subsystem registration | Angular config component suite | `cd desktop/angular && npx ng test --watch=false` | Requires installed ChromeHeadless environment. |
| Fake-source ownership parity | `socket_source.go` uses `PendingEvent`/`deliverPendingEvent` | socket and pipeline tests | `go test -tags filemaster_test ./service/fileaccess -count=1` | Socket transport lacks kernel-only mount/FD behavior; confined source covers that. |
| Confined fanotify integration | Linux-only opt-in harness below | Unit tests plus host harness | `FM_FANOTIFY_INTEGRATION=1 go test -tags fanotify_integration ./service/fileaccess -run TestConfinedFanotifyIntegration -count=1 -timeout=90s` | Must have Linux fanotify, mount namespace and `CAP_SYS_ADMIN`; never marks host `/`. |
| Real PID 1 systemd safety | `docs/fanotify-systemd-host-verification.md` | Manual host runbook | `sudo ./scripts/verify-fanotify-systemd-host.sh` | Current PID 1 is `fish`, not systemd; result is incomplete. |
| Root pipeline benchmark | Existing `cmds/fanotify-root-bench` measures transport only | Harness emits JSON transport measurements | `go build -o /tmp/fanotify-root-bench-bin ./cmds/fanotify-root-bench` followed by the commands in its README | **Incomplete:** the existing harness does not exercise the complete Filemaster profile, prompt, persistence, and observation pipeline. Root Ask evidence cannot be recorded from it. |
| Root scope Ask gate | `rollout_gate_linux.go`, `profile_handler.go` | `phase8_test.go` | `go test ./service/fileaccess -run TestRootAskGate` | Closed: systemd host and root benchmark evidence are absent. |

The Phase 8 root Ask gate defaults closed. Its browser-visible request switch
does not supply verification evidence; trusted host verification must provide
current implementation and settings fingerprints, confined integration,
systemd PID 1, benchmark, shutdown, persistence, and prompt grouping evidence.
