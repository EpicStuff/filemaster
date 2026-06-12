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
- [x] **Live websocket prompt round-trip verified.** Drove a real
      NotificationsPrompter prompt via ws on `/api/database/v1`. Wire
      format: `<msgid>|qsub|query notifications:` to subscribe;
      received `<msgid>|new|notifications:all/fileaccess:open:N|J<json>`;
      replied `<msgid>|update|<key>|J<json-with-SelectedActionID>`; got
      `<msgid>|success`. NotificationsPrompter's Response() channel
      fired, the verdict reached fanotify, and `cat
      /tmp/filemaster-test/nested/secret.txt` returned the file
      content with rc=0 (allow) or EPERM (deny). End-to-end run
      script captured at /tmp/responder.py.
- [x] **Angular UI confirmed end-to-end.** Stood up the full stack
      under headless chromium (ng serve on :4200 proxying API to
      pm-core on :817 with `core/devMode=true`). Loaded the dashboard,
      triggered a cat, snapshotted before/after. The sidebar's
      prompt-tray div (gated by
      `*ngIf="hasNewPrompts || globalPromptingEnabled"`) appears with
      the yellow indicator dot only when a fileaccess prompt is live
      -- visible diff in the screenshots. PortapiService completes
      the WS handshake, the prompt-list filter
      (notif.EventID.startsWith("fileaccess:")) matches, and the
      action button click maps to the same `update` wire message that
      the standalone responder uses.

      Run-it-yourself recipe:
      1. `cat > <dataDir>/config.json <<EOF
         {"core":{"devMode":true},
          "fileaccess":{"watchPaths":["/tmp/filemaster-test"]}}
         EOF`
      2. `setsid pm-core --data-dir <dataDir> --bin-dir <binDir> \
                       --log-dir <logDir> > /tmp/pm.log 2>&1 &`
      3. `cd desktop/angular && ng serve --host 0.0.0.0 \
              --port 4200 --proxy-config ./proxy.json`
      4. Open `http://<host>:4200/` in a browser. Trigger a file
         access in a watched dir; the prompt-tray icon turns yellow.
         Click it, then click an action button.

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

## Phase 3.5 — recursive watch + auto-profiles [DONE]

Goal: subdir recursion on watched paths, and confirm portmaster's
existing GetLocalProfile auto-creation actually fires for previously-
unseen exes.

- [x] **Subdirectory recursion.** fanotifySource walks each watch root
      and adds a fanotify mark per directory in the tree (symlinks not
      followed). The kernel's FAN_MARK_ADD is idempotent, so the live-
      reload hook re-walks every requested root on each config commit
      -- subdirs created since the last walk get marked, deleted ones
      get their stale marks dropped (ENOENT on remove is treated as
      success since the kernel implicitly drops marks for vanished
      inodes). `roots map[string]map[string]struct{}` tracks per-root
      mark sets so removing a root unmarks every subdir under it.
      Verified live 2026-06-12 with `cat
      /tmp/filemaster-test/nested/deeper/secret.txt` -- the daemon
      logs the deep path and the kernel routes the open to the
      verdict path.
- [x] **Auto-profile-creation via portmaster.** Verified live
      2026-06-12: with no profile in the DB for `/usr/bin/cat`,
      accessing a watched file with cat caused portmaster's
      GetLocalProfile to create a fresh local profile named "Cat"
      with `Fingerprints=[{path, equals, /usr/bin/cat}]` and the
      content-addressed ScopedID. The fileaccess package does NOT
      have its own auto-create path -- our processProfileLookup
      consumes whatever process.GetProcessWithProfile returns, and
      that function already invokes portmaster's existing
      auto-creation chain (see doc-comment on
      NewProcessProfileLookup). A test
      (TestProcessProfileLookupGoesThroughPortmasterHook) locks down
      the indirection so a future change can't accidentally bypass
      the portmaster path.

## Phase 4 — UI [DONE]

Goal: existing Angular/Tauri shell renders file prompts instead of
network prompts.

- [x] **EventData payload.** `NotificationsPrompter` now sets
      `EventData = FilePromptData{Profile{ID,Source,Name,LinkedPath},
      Subject{PID,Exe,Path,Op}}` (see
      `service/fileaccess/prompt_notifications.go`). The TS mirror
      lives at `services/notifications.types.ts` (`FilePromptData`
      replaces `ConnectionPromptData`; `FileAccessPrompt` replaces
      `ConnectionPrompt`). `LookupResult` carries the profile metadata
      so `ProfileHandler.Decide` stamps Profile fields onto the
      `FileEvent` before calling the prompter.
- [x] **Prompt-entrypoint window.** `prompt-entrypoint.ts` filters
      on `fileaccess:open` EventID prefix, groups by Profile when one
      resolved and by exe path when not. `prompt.html` renders
      `Path:` + `Op:` (with pid) rows instead of `Domain:` + `IP:`.
      Unknown-process events fall through to a "Unknown program" group.
- [x] **In-app prompt list.** `shared/prompt-list/` rewired to the
      same EventID prefix and FileAccessPrompt shape. `allow/block`
      buttons map to the `allow`/`deny` (+/-always) action IDs the
      backend emits; the domain-parsing path is gone.
- [x] **App-list view: per-app rules render path entries.** Set
      `DisplayHintAnnotation: "endpoint list"` on
      `CfgOptionFileAccessRulesKey` so the existing `app-rule-list`
      component draws `+ <pattern>` / `- <pattern>` entries with the
      default Allow/Block symbol map. No frontend change required.
- [x] **Sidebar strip.** Removed SPN nav button, "Re-Initialize SPN",
      "Logout Completely", "Clear DNS Cache", "Cleanup Network
      History" menu items, and all "Pause SPN for ..." pause-menu
      items. Removed `SPNService`/`BoolSetting` imports +
      `spnEnabled`/`pauseSPN`/`reinitSPN`/`logoutCompletely`/
      `clearDNSCache`/`cleanupHistory` methods. `/spn` route gone.
      `/monitor` route, "Network Activity" nav button, "Connections"
      and "Insights" tabs, `app-qs-internet` and `app-qs-history`
      tiles kept as scaffolding for future file-access activity views.
- [x] **EventID prefix flipped everywhere.** `filter:prompt` →
      `fileaccess:open` in navigation tray badge and notification list
      filter so prompts aren't double-rendered in the notification
      panel.
- [x] **Stats block removed.** The per-app header tiles (Active
      Connections / Blocked % / Received / Sent) only made sense
      against netquery and are gone. The "Active Connections" and
      "Network History" detail lines stay (they're inside the
      header-detail block and tied to the kept scaffolding).
- [x] Compiles: `npm run build-libs:dev && ng build --configuration
      development` is green; 26 Go tests still pass.

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

## Portmaster reuse audit (kept current as we sweep)

- [x] **Profile.DefaultAction** read by `ProfileHandler` on no-rule-match.
      Honors the existing per-profile `permit` / `ask` / `block` knob, so
      users coming from the network filter UX get the same mental model.
- [x] **Single lookup per event.** `ProfileLookup.Lookup` is the only
      place that calls `process.GetProcessWithProfile`; the result
      bundles Path + Store + ParsedRules + DefaultAction so both the
      main and fallback handlers consume one resolve.
- [x] **Drop fanotify's `/proc/<pid>/exe` readlink.** Exe resolution
      now rides on the process module's richer lookup (cmdline, env,
      tags) instead of a parallel readlink in the source. Source logs
      `pid + path` only; ProfileHandler populates `e.Exe` from
      `Process.Path` before delegating to the fallback or logging.
- [x] **Cached parsed rules.** `processProfileLookup` caches a
      `PathRules` per profile ID, invalidated only when the raw rule
      count changes (the only mutation we currently do is prepend via
      `AddFileAccessRule`). Avoids re-parsing the StringArray on every
      Decide without restructuring the type graph.

Still on the list:
- [x] **Watch paths as a `base/config` `StringArrayOption`** under
      `fileaccess/watchPaths`. Registered from `fileaccess.New()` so it
      lands before `config.Start` writes `cfgInitialized`. Priority
      chain in `resolveWatchPaths()`: config option (when non-empty),
      then `FM_WATCH_PATHS` env var, then the hardcoded default.
      Verified 2026-06-12 by writing
      `{"fileaccess":{"watchPaths":["/tmp/fm-conf-target"]}}` to
      `<dataDir>/config.json` and observing the daemon mark that path
      (and not the default).
- [x] **Live reload.** `Source.SetWatchPaths(paths)` is now part of
      the interface (fanotify_linux maintains a path-set and diffs;
      non-linux nopSource no-ops). `fileaccess.Start()` subscribes to
      `EventConfigChange` and calls `SetWatchPaths(resolveWatchPaths())`
      on every config commit, so edits to `fileaccess/watchPaths`
      (and the new `fileaccess/interceptReads` toggle) take effect
      without a daemon restart. Mask changes (toggle-reads) also
      trigger a re-mark with the new mask.
- [x] **Read/write/exec op distinction.** FileOp gains OpRead +
      OpExec alongside OpOpen; fanotify_linux's mask now includes
      FAN_OPEN_PERM + FAN_OPEN_EXEC_PERM by default, with
      FAN_ACCESS_PERM gated behind the new
      `fileaccess/interceptReads` BoolOption (off by default --
      FAN_ACCESS_PERM fires per read() syscall and would storm the
      prompt path on a chatty consumer). `opFromMask` decodes events
      most-specific-first; the prompt message uses an op-appropriate
      verb ("execute" / "read" / "open") and the EventID prefix
      becomes `fileaccess:<op>:N` so the UI filter is now
      `fileaccess:` (anything). A "write" op is intentionally absent:
      fanotify perm events are fired before the open completes, so
      the open-flag distinction can't be made without inspecting
      userspace state racily.
- [x] **Endpoints scaffolding deleted.** `service/profile/endpoints/`
      package gone. `service/intel/`, `service/network/` stubs gone.
      `service/profile/profile-layered.go` lost its MatchEndpoint /
      MatchServiceEndpoint / MatchSplitTunUsagePolicy /
      MatchSPNUsagePolicy / MatchFilterLists / StackedTransitHub /
      StackedExitHub methods plus 17 wrap*Option fields. `Profile`
      lost its endpoints / serviceEndpoints / splitTun* / spn* fields
      and matching accessors. `Profile.AddFileAccessRule` now calls
      the renamed-and-generalised `addStringArrayEntry`. Special
      profiles keep only DefaultAction in their bootstrap config.
      Total: ~2700 LOC removed for ~70 added. Daemon boots cleanly;
      26 fileaccess tests still green.
