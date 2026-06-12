# filemaster — implementation steps

Tracking the path from "compiling fork with no file logic" to "working
file-access prompt loop." See `FORK_NOTES.md` for what was deleted to get
here.

## Phase 1 — minimal fanotify daemon (no UI, no rules) [DONE]

Goal: a single Go package that opens an fanotify group, marks one
hard-coded path, and blocks/allows opens via stdin or a hard-coded
verdict. Proves the kernel plumbing works before we wire anything else.

- [x] `service/fileaccess/` new package skeleton (module manifest, mgr.Module).
- [x] `fanotify_linux.go` — `unix.FanotifyInit` with `FAN_CLASS_CONTENT |
      FAN_CLOEXEC`, mark a hard-coded dir with `FAN_OPEN_PERM`.
- [x] Event loop: read `fanotify_event_metadata`, resolve PID → exe path
      via `/proc/<pid>/exe`, log `{pid, exe, path}`.
- [x] Verdict writer: respond with `FAN_ALLOW`. (Auto-allow only; deny
      logic deferred to phase 3 with the prompt loop.)
- [x] Wire the package into `service/instance.go` service group (after
      `process`, before `ui`).
- [x] Smoke test: `cat /tmp/filemaster-test/<file>` triggers an event,
      daemon logs `{pid, exe, path}`, syscall proceeds. Verified
      2026-06-12 with bash + cat events. Smoke binary at
      `cmds/fanotify-smoke/`.
- [x] Configurable watch paths via `FM_WATCH_PATHS` env var
      (colon-separated). Defaults to `/tmp/filemaster-test` so the
      existing demo/smoke binaries still work unchanged. Verified
      multi-path: marks land on each path independently, and opens
      outside any watched path correctly bypass the daemon.

Lessons / footguns:
- `FAN_MARK_MOUNT` marks the *entire mount*, not the path. On a root-
  filesystem path this routes every open on the system to the daemon and
  freezes the host when verdicts can't keep up. Use plain inode mark
  (default) + `FAN_EVENT_ON_CHILD` for a single-directory watch.
- Self-PID filter is mandatory: an open from inside the daemon's own
  handler would block waiting for the daemon to respond to itself.
- Env requirements: init user namespace + `CAP_SYS_ADMIN` + no seccomp
  filter blocking `fanotify_init`. In Docker terms:
  `--userns=host --cap-add=SYS_ADMIN --security-opt seccomp=unconfined`
  (or a custom seccomp profile that allows fanotify syscalls).

Open questions deferred to phase 2/3:
- `FAN_REPORT_FID` for cross-mount support — punt until the rule shape
  forces the decision.

## Phase 2 — file rule matching [DONE; profile-storage integration deferred]

Standalone PathRule + PathRules live in `service/fileaccess/rule.go`.
Pattern syntax: exact, single-segment glob, `/**` recursive. Used by
PromptHandler directly. Per-exe lookup keying landed in phase 2.5.

The endpoints-package integration (originally the plan) is deferred:
that path requires retrofitting the `Endpoint.Matches(*intel.Entity)`
signature, which is a bigger refactor than the file-rule logic itself.
For now phase-3 storage is the in-memory PromptHandler map, which is
enough to demo and to design phase-5 against.

Still to do (post-phase-3):
- [ ] Decide whether file rules ride on the existing
      `service/profile/endpoints/` infrastructure or get their own
      storage layer in `service/fileaccess/`.
- [ ] On that decision: either add `EndpointPath` alongside the
      existing endpoints (intel.Entity gets a Path field), or build a
      parallel rule storage hierarchy.
- [ ] Delete the IP/domain/country/ASN/scope endpoint files +
      `service/intel/entity.go` + `netutils` + `reference` stubs once
      the path is decided and the scaffolding is no longer load-bearing.

## Phase 2.5 — per-app rules [DONE]

PromptHandler keys its rule list by `FileEvent.Exe`, so a rule
established by `/usr/bin/vim` for `/home/alice/notes.txt` doesn't
auto-allow that path for `/usr/bin/cat`. Verified end-to-end:
- Unit test `TestPromptHandlerPerExeIsolation`.
- Live demo 2026-06-12: bash and cat each had to prompt once for the
  same file, then both got silent rule-hits on second access.

Still pending:
- [x] **Profile-fingerprint identity:** rules now key off the
      portmaster `LocalProfile.ScopedID()` (content-addressed from the
      fingerprint set) instead of the exe path, so reinstalls and
      upgrades that keep the cmdline stable keep the rules. Implemented
      as `ProfileHandler` over a `ProfileLookup` interface; the
      production binding wraps `process.GetProcessWithProfile`. Falls
      back to the exe-keyed `PromptHandler` when no profile resolves
      (e.g. process gone, detection disabled). Rules live in the
      profile's config map under `fileaccess/rules` and ride the
      existing profile-DB + sync paths -- no parallel storage layer.
- [x] **Persistence:** per-exe rule lists survive daemon restart via a
      JSON file at `<dataDir>/fileaccess-fallback-rules.json` for the
      fallback handler. Profile-resolved events persist through the
      profile package's own storage (config option
      `fileaccess/rules`). Save on every appendRule (atomic
      temp+rename), load on Start (missing file is not an error).
      Wired into `instance.go`; demo cmd supports `FM_RULES_PATH` env
      var. Schema is versioned so future migrations surface as load
      errors rather than silent corruption. Verified 2026-06-12.

## Phase 3 — prompt loop end-to-end [logic done, live test pending]

Goal: an unknown path access fires a notification, user responds via API,
rule persists, next access of the same path is auto-decided.

- [ ] In the fanotify event handler, look up the process's profile (reuse
      `process.GetProcessWithProfile`). **Deferred** -- phase-3 minimum
      uses a single global rule list, not per-app. Profile lookup lands
      with phase 2.5 (storage integration).
- [x] Match the access against rules. If no match → prompt. (`PromptHandler`
      in `prompt.go`.)
- [x] Prompt actions: Allow once / Deny once / Allow always / Deny always.
      "Always" appends a `PathRule` to the in-memory rule list.
- [x] Verdict write happens only after user responds (or timeout fires --
      default-deny on expire, 30s default).
- [x] Wired into `service/instance.go`: `NotificationsPrompter` is the
      production Prompter backing `PromptHandler`.
- [x] **Live demo:** `cmds/fileaccess-demo/` wires fanotify + Prompt-
      Handler + a scripted prompter (deny anything with "blocked" in
      the path). Verified 2026-06-12: real bash + cat open syscalls
      succeed for allowed paths and fail with EPERM for denied paths.
      Second access of an "allow-always" / "deny-always" path skips
      the prompter (persisted rule hit).
- [ ] **Pending:** live websocket-against-real-notifications test --
      drive a real NotificationsPrompter prompt via ws on
      `/api/database/v1`. The Prompter abstraction means this only
      exercises the upstream notifications path; PromptHandler itself
      is already verified.

Verified 2026-06-12:
- Daemon boots cleanly with the wired PromptHandler.
- Six unit tests cover rule-hit-skips-prompt, allow-once, allow-always
  persists rule, deny-always persists rule, no-reply defaults to deny,
  unknown action defaults to deny.
- Live demo: real syscalls allowed/denied/persisted as expected.

Footgun captured during live test:
- Multiple FAN_CLASS_CONTENT listeners on the same inode are ANDed by
  the kernel -- any denying listener denies the syscall. Don't leave
  stale daemons running during a focused-test run; they'll either deny
  events out from under the test or stall waiting on prompts the test
  isn't responding to.

## Phase 4 — UI

Goal: existing Angular/Tauri shell renders file prompts instead of
network prompts. Defer until phase 3 settles the field shape.

- [ ] Map `FileEntity` fields into whatever the prompt component expects
      (probably rename `Entity` → `Subject` in the API payload).
- [ ] Replace network-specific labels in the prompt component
      (`Connection from ...` → `Access to ...`).
- [ ] App-list view: per-app rules render `path:` lines instead of
      `domain:`/`ip:`.
- [ ] Strip out tabs/panels that no longer make sense (network monitor,
      DNS settings, SPN).

## Phase 5 — per-app sandboxing (Storage-Scopes-style)

Stretch goal from the original ChatGPT discussion. Only after phase 4.

**Landlock vs mount namespaces:** Landlock LSM (Linux 5.13+, syscalls
`landlock_create_ruleset` / `landlock_add_rule` / `landlock_restrict_self`)
is probably the right primitive here, not mount namespaces. It's
self-imposed by the sandboxed process, inherits across `clone()`, doesn't
need root-per-app, and stacks cleanly with the fanotify prompt layer
(fanotify intercepts the *first* access for the prompt; Landlock enforces
the resulting rule cheaply in-kernel). Mount-namespace + OverlayFS still
wins if we need transparent path *rewriting* (Storage-Scopes-style) rather
than just deny — Landlock can only allow/deny, not redirect.

- [ ] Decide: pure Landlock (deny-only) vs Landlock + ns-redirect hybrid.
- [ ] If hybrid: per-app mount namespace + bind/OverlayFS for the redirect
      cases, Landlock for everything else.
- [ ] Trigger: endpoint actions `sandbox:~/Documents=allow` (Landlock) and
      `redirect:~/Documents=/var/lib/filemaster/<app>/Documents` (ns).
- [ ] Launcher shim that applies the ruleset before `execve` (Landlock
      must be set up by the parent).

## Cross-cutting cleanup (do whenever)

- [ ] Rename the binary and module path from `portmaster` to `filemaster`.
      Defer until phase 3 — module-path rename touches every Go file.
- [ ] Drop the `safing.io` / Portmaster branding from `info/info.go`.
- [ ] Trim the README to describe the fork.
