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
result must be supplied to the trusted rollout-evidence recorder before root
scope Ask mode can open. This repository checkout has **not** completed this
verification: its PID 1 is `fish`, not `systemd`.
