# Fanotify systemd PID 1 host verification

This procedure is intentionally manual. Run it only on a disposable or
maintained Linux host where `ps -p 1 -o comm=` reports `systemd`, with the
required fanotify and mount-namespace capabilities. Do not use a container
whose PID 1 is a shell.

1. Confirm the target and capability preconditions.

   ```bash
   test "$(ps -p 1 -o comm=)" = systemd
   capsh --print | grep -q cap_sys_admin
   test -r /proc/self/mountinfo
   ```

2. Start Filemaster with a temporary data directory and a confined, nonroot
   watched directory. Confirm that the seeded systemd profile and its editable
   helper allow rules are present in the profile UI before enabling restrictive
   policy.

3. Exercise a helper process and a systemd-managed helper against the confined
   directory. Confirm that the correct special profile is selected, prompts
   resolve exactly once, responses precede activity/audit records, and neither
   PID 1 nor the helper becomes blocked.

4. Trigger a profile edit while a matching prompt is open. Confirm revision
   reevaluation closes the prompt when the new policy is decisive.

5. Force one temporary mark-removal failure, then begin controlled shutdown.
   Confirm that late permission events are denied until marks are removed or
   the group closes, and inspect `GET /api/v1/fileaccess/diagnostics` for
   unresolved ownership and final cleanup state.

6. Stop the service, verify all fanotify marks and temporary mounts are gone,
   then restore the original configuration and remove the temporary data
   directory.

Record the host kernel, Filemaster build commit, descriptor limit, worker and
queue settings, exact observed prompts, and shutdown diagnostics. A successful
trusted backend verifier must then call
`FileAccess.RecordRootAskRolloutEvidence`; it persists the evidence atomically
in the Filemaster data directory with mode 0600. The browser request switch and
the diagnostics API cannot write this record. The recorder refreshes the
implementation, effective-settings, and kernel-environment fingerprints, so
changing any of them closes root Ask mode until the host is verified again.
The recreated verification host has PID 1 `systemd`, a private mount namespace,
and effective `CAP_SYS_ADMIN`. Its confined run used a distinct temporary bind
target, reported complete coverage, and observed exactly one real permission
event from a `systemd-run` helper; peak descriptor accounting was one and
controlled shutdown completed in about 660 ms. It intentionally did not record
trusted evidence because there was no interactive approved prompt, audit, or
profile-UI confirmation. Complete those remaining runbook steps before calling
`RecordRootAskRolloutEvidence`.

The backend-only verifier now performs the interactive notification exchange
without a browser. It uses one stable temporary helper executable and one
reusable transient helper unit. The first temporary-scope access receives an
approved `Allow always` response and produces a matching filequery observation;
a daemon restart then reuses the same durable profile identity and exact rule
without another prompt. Root scope verification is explicitly deferred from
Phase 8: do not record root-scope evidence or open root Ask from this confined
verification alone.
