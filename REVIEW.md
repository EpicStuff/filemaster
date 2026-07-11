# filemaster — code review (2026-06-14)

Goal: be a Portmaster-flavoured per-app **file-access** prompt tool.
Reuse upstream code where possible; replace nfqueue/WFP with fanotify;
replace IP/domain rules with path rules.

This pass walked the source rather than the in-tree docs. Every claim
below is tagged with the file(s) I read to ground it. Anything I
couldn't ground in code is called out under §9 as "still unverified."

Snapshot: branch `claude/strip-network-stack` at commit `f8fe209b`.

---

## 1. Build / test state, observed

- `go build ./...` — clean (just ran).
- `go test ./service/fileaccess/... -count=1 -v` — 28 test functions,
  all pass. (See §5 for the matrix.)
- `go test ./...` — one failure, unrelated:
  `service/profile/binmeta.TestFindIcon` errors with
  `no icon found for evolution / nextcloud`. That test walks
  `/usr/share` for installed-app icons, so it's environment-dependent
  (those apps aren't installed in this dev sandbox), not a code
  regression.
- The live fanotify tests (`TestSetWatchPathsLiveAddRemoveSubtree`,
  `TestSetWatchPathsLiveReloadAddsNewSubdirsOnReload`) **did not
  skip** on this machine — they ran a real `FanotifyInit` + walked
  + reconciled. So at least the SetWatchPaths reconciler is verified
  against the real kernel API here, not just against a stub.

---

## 2. Backend — verified to actually exist and wire up

### 2a. The decider chain

`service/instance.go:173-201` constructs the chain at startup:

```
fanotifySource ── handler:ProfileHandler
                      │
                      ├─ lookup: NewProcessProfileLookup()      // profile_binding.go:44
                      │      └─ getProcessWithProfile (var)     // profile_binding.go:17
                      │             defaults to process.GetProcessWithProfile
                      │             → process.GetOrFindProcess → process.GetProfile
                      │             → profile.GetLocalProfile → findProfile / New(...)
                      │
                      ├─ prompter: &NotificationsPrompter{}     // prompt_notifications.go:43
                      │      pushes a base/notifications.Notify with EventID
                      │      "fileaccess:<op>:<n>" and EventData = FilePromptData
                      │
                      ├─ fallback: PromptHandler                // prompt.go:44
                      │      exe-keyed, JSON-persisted
                      │
                      └─ timeout: 30s
```

I read every file in that chain (`event.go`, `rule.go`,
`profile_handler.go`, `profile_binding.go`, `prompt.go`,
`prompt_notifications.go`, `persistence.go`, `fanotify_linux.go`,
`module.go`, `config.go`). It's coherent.

### 2b. Profile API the chain depends on

The binding (`profile_binding.go:91-105`) reads four things off the
local profile and writes one. I verified each of those exists with
the expected signature:

| Call site | Method | Defined at |
| --- | --- | --- |
| `local.ScopedID()` | `func (*Profile) ScopedID() string` | `service/profile/profile.go:215` |
| `local.GetFileAccessRules()` | `func (*Profile) GetFileAccessRules() []string` | `service/profile/profile.go:278` |
| `local.DefaultAction()` | `func (*Profile) DefaultAction() uint8` | `service/profile/profile.go:292` |
| `local.Source`, `local.Name`, `local.LinkedPath` | struct fields | `service/profile/profile.go:46,49,76` |
| `local.AddFileAccessRule(entry)` | `func (*Profile) AddFileAccessRule(newEntry string)` | `service/profile/profile.go:299` |

`DefaultAction` returns the field `defaultAction uint8` which is set
by `Profile.parseConfig()` (`profile.go:152-166`) from the string
config option `filter/defaultAction` (`profile/config.go:17,73`).
That option's possible values (`permit` / `block` / `ask`) are also
registered there.

`AddFileAccessRule` calls `addStringArrayEntry(CfgOptionFileAccessRulesKey, …)`
(`profile.go:307-356`) which:

1. takes `profile.Lock()`,
2. fetches the current `[]string` for `fileaccess/rules`,
3. checks for duplicates within the leading same-prefix run,
4. prepends the new entry,
5. writes the new value back via
   `config.PutValueIntoHierarchicalConfig(profile.Config, cfgKey, list)`,
6. marks `dataParsed = false` and re-runs `parseConfig`,
7. on defer, calls `profile.Save()` which goes through
   `profileDB.Put(profile)` (`profile.go:225-234`).

So a positive prompt response *does* end up in the profile database
via the unmodified portmaster persistence path. This is a real
load-bearing reuse of Portmaster, not a stub.

### 2c. Profile auto-creation

`process.GetProcessWithProfile` (`service/process/find.go:14-41`)
calls `process.GetOrFindProcess` then `(*Process).GetProfile`
(`service/process/profile.go:18-42`), which calls
`profile.GetLocalProfile(specialProfileID, p.MatchingData(), p.CreateProfileCallback)`.

`profile.GetLocalProfile` (`service/profile/get.go:24-178`) walks
this chain on a previously-unseen exe:

1. No active profile by ID, no special profile match → call
   `findProfile(SourceLocal, md)` (line 89) which iterates every
   profile in the DB and scores fingerprints (line 222 — `MatchFingerprints`).
2. No fingerprint match → call `createProfileCallback()` (line 101);
   if that returns nil, fall through to a default `New(&Profile{...
   Fingerprints: [{Type: FingerprintTypePathID, Operation:
   FingerprintOperationEqualsID, Value: fpPath}]})` at line 111-123.
3. `profile.Save()` (line 142) is called on `created || changed`.
4. A `LayeredProfile` is created (line 171) if none exists.

So when an unknown PID hits the fanotify source, the portmaster code
path *does* create a fresh `LocalProfile` keyed by `path-equals`
fingerprint, save it to the DB, and the binding then reads
rules/default action from the *just-saved* `LocalProfile()`.

I did NOT drive a real PID through this in this session (the package
test exercises only the indirection — see §5). So "auto-creation
fires for an unknown exe" is structurally grounded in code but not
witnessed live in this session.

### 2d. Fanotify source (Linux)

`service/fileaccess/fanotify_linux.go`, 511 lines, read fully.

- `FanotifyInit(FAN_CLASS_CONTENT|FAN_CLOEXEC, O_RDONLY|O_LARGEFILE|O_CLOEXEC)`
  at line 136-139. EPERM is wrapped with a CAP_SYS_ADMIN hint.
- Mask is built by `resolveMarkMask()` (line 59-65):
  `FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_EVENT_ON_CHILD`, plus
  `FAN_ACCESS_PERM` iff the `fileaccess/interceptReads` BoolOption
  is true. Defended against nil `cfgOptionInterceptReads`. Verified
  by `TestResolveMarkMaskDefault` and `TestResolveMarkMaskWithReads`.
- Marks are inode-scoped, *not* `FAN_MARK_MOUNT` (line 354-362).
  Comment specifically calls out that mount marks would route every
  system open to the daemon.
- `walkAndMark` (line 306-346) uses `filepath.WalkDir`, marks every
  directory, joins per-path errors, doesn't follow symlinks.
  Verified by `TestWalkAndMarkVisitsSubdirs` with a tree containing
  a symlink to `/etc`.
- `SetWatchPaths` (line 202-299) reconciles current marks with the
  requested set: walks new roots, drops vanished ones, also re-marks
  the whole subtree when `resolveMarkMask()` returns something
  different (the InterceptReads toggle). Locked behind `marksMu`.
- `Run` (line 376-416) does `Poll` with a 500ms timeout for
  responsive shutdown, then `Read` events, handles `EAGAIN/EINTR`
  cleanly, treats `EBADF` as graceful shutdown (matches the `Close`
  contract).
- `handleEvent` (line 438-493):
  - version check against `FANOTIFY_METADATA_VERSION`,
  - skips overflow events (`Fd < 0`),
  - drops self-PID events (avoids self-deadlock) but still writes an
    allow response if it's a perm event,
  - resolves path via `readlink(/proc/self/fd/N)`,
  - calls handler.Decide,
  - writes verdict via `respond` (line 495-506) which does the
    `unsafe.Slice` over the `FanotifyResponse` struct.

The `Run`/`Close` race is handled by the fd-close-causes-EBADF
pattern, which matches the comment on `Source.Close`.

Footgun *not* fully captured in code: `markRemove` on line 364 uses
`s.markMask`, not the per-root's *original* mark mask. If the mask
toggles while a root is partially marked, the remove can target the
wrong mask. In practice the SetWatchPaths flow handles this by
remasking under `oldMask` before the add pass switches `s.markMask`
(line 218-228), so the live-flow is fine. Just a maintenance hazard.

### 2e. Fanotify "source" on non-Linux

`fanotify_other.go` (`!linux` build tag, 23 lines):

```go
func (s *nopSource) Run(ctx context.Context, h Handler) error {
    s.log.Warn("file-access interception not implemented on this platform")
    <-ctx.Done()
    return nil
}
```

Just a warn + park. macOS and Windows builds run the rest of the
daemon and the UI with **zero enforcement**, no further warning
beyond that single log line. There's no UI banner that the user
would see.

### 2f. Rule shape

`rule.go` defines:

- exact match (string equality through `filepath.Match`),
- single-segment glob via `filepath.Match`,
- `/foo/**` recursive match handled by the custom prefix check at
  line 60-66.

Wire format `+ <pattern>` / `- <pattern>` is the same as upstream
endpoint rules. `FormatRule` / `ParseRule` round-trip is tested in
`profile_handler_test.go:94-126`.

---

## 3. UI — what's actually wired, what's actually dead

This is where my previous review was too generous. The Angular
shell is "kept largely intact" the way `FORK_NOTES.md` claims, but
*intact* means **most of the Portmaster-themed pages, services, and
copy still ship**, not just structurally — they're still the
default landing experience.

### 3a. File-access prompt path through the UI: real

These three files all filter on `fileaccess:` and consume
`FileAccessPrompt`/`FilePromptData`:

- `notifications.types.ts:128-142,222` — `FilePromptData` interface
  and `FileAccessPrompt = Notification<FilePromptData>` type alias.
- `prompt-entrypoint.ts:5,10,30,39,45,87` — the separate prompt
  window filters `n.EventID.startsWith('fileaccess:')` (line 39) and
  groups by `EventData.Profile.ID`.
- `prompt-list.component.ts:5,12-13,55,60-66,101,149-161,194` — the
  in-app sidebar prompt list, same filter, same shape; `allow()`
  resolves the `allow` or `allow-always` action ID, `block()`
  resolves `deny` or `deny-always` — both match the constants the Go
  backend emits (`prompt.go:14-18`).
- `navigation.ts:126,140` — tray-badge gating filters on
  `fileaccess:` too, so the yellow dot lights up only for file
  prompts.

So when the backend posts a `fileaccess:open:N` notification, the
flow into the UI is real. Verified by reading the TS, not by
running it.

### 3b. UI surfaces that still render but have no backend

Read `app-routing.module.ts` and `app.module.ts`:

- `MonitorPageComponent` is declared at `app.module.ts:137` and
  routed at `app-routing.module.ts:34-37` (with the comment "kept
  for future file-access activity view"). It imports `Netquery` and
  `SPNService` at `pages/monitor/monitor.ts:3`, calls
  `this.netquery.cleanProfileHistory([])` at `monitor.ts:72`. Both
  Go endpoints are deleted (per `UI_GAPS.md` and verified — there
  is no `service/netquery` directory).
- `SPNModule` is imported at `app.module.ts:35,205`. It is *not*
  routed (`app-routing.module.ts` has no `/spn`), but the module's
  declarations get bundled regardless.
- `NetqueryModule` imported at `app.module.ts:54,202`. Used by
  dashboard, monitor, and app-view.
- `SPNStatusComponent`, `SPNLoginComponent`,
  `SPNAccountDetailsComponent` all declared at lines 56-58, 145,
  147-148.

### 3c. The dashboard is still a Portmaster dashboard

`pages/dashboard/dashboard.component.html` is untouched. It renders:

- "Your current plan is **Portmaster Free**" / "Account Details" /
  "Login / Subscribe" buttons (line 30, 53-65).
- "Active Connections", "Connections Blocked", "Data Received",
  "Data Sent", "SPN Identities" (lines 80-125) with the
  "Available in Portmaster Plus" / "Pro" fallback labels (lines 99-123).
- A `<spn-map-renderer>` for "Recent Connection Countries" (line 207).
- `<sfng-netquery-line-chart>` for bandwidth and active vs blocked.
- `<sfng-netquery-circular-bar-chart>` for "Recent Top Consumers".
- A "Recent Connections per Country" tile linked to `/monitor` with
  netquery query strings.

`dashboard.component.ts:3-11` imports `Netquery, SPNService,
SfngNetqueryLineChartComponent, SPNAccountDetailsComponent,
MAP_HANDLER` — all alive and referenced. `featureSPN`, `featureBw`
are computed from `this.spn.watchEnabledFeatures()` on line 156. A
"logged out of SPN" toast lives on line 480.

**Net effect for a user**: open the app, land on a dashboard that
is overtly a Portmaster Plus/Pro upsell page with empty data
panels. That's a strictly worse first-run experience than just a
plain "no data yet" splash.

### 3d. App-view tab still says Portmaster Plus / SPN

`pages/app-view/app-view.html`:

- Line 47-48: "Active Connections: 0" (always 0; netquery is gone).
- Line 51-60: "Network History … None | sfng-tooltip='Network
  History feature is available in **Portmaster Plus**'".
- Line 67-72: scaffolding QS buttons (`<app-qs-internet>`,
  `<app-qs-history>`) "kept; will be repurposed to file-access
  allow/block" — currently still wired to upstream config keys.
- Line 106-112: a `Connections` tab that renders
  `<sfng-netquery-viewer>`. Tab is shown unconditionally.
- Line 366-370: an `Insights` tab → `<app-app-insights>`.
- Line 120: "Get Help" link → `docs.safing.io/portmaster/settings`.
- Line 341: "Delete Profile" copy still says "as soon as the
  application starts to use the **network**."

The App Settings tab itself (line 113-183) is the part that
actually works: it renders the registered config options including
the new `fileaccess/rules` via the generic `<app-settings-view>`.

### 3e. Side-dash conditionally hides SPN login, doesn't strip it

`layout/side-dash/side-dash.html:9-10`:

```html
<app-spn-login *ngIf="spnLoginRequired"></app-spn-login>
<app-network-scout *ngIf="!spnLoginRequired" ...></app-network-scout>
```

with `side-dash.ts:11` hardcoding `spnLoginRequired = false`. So
the SPN-login pane never renders, but the network-scout pane
*always* does. Haven't read network-scout in this pass.

### 3f. safing.io URLs are still pervasive in the UI

`grep -rn "safing\.io" desktop/angular/src/` returns 21 hits across:

- `dashboard/feature-card/feature-card.component.ts:71` — opens
  `safing.io/pricing?source=Portmaster` from a button.
- `monitor/monitor.html:31` — "Available in Portmaster Plus" link.
- `settings/settings.html:4` — settings help link.
- `support/pages.ts:43-85` — wiki, docs, blog, discord,
  `mailto:support@safing.io`.
- `shared/spn-login/spn-login.html:32,42,64` — multiple deep links.
- `environments/environment*.ts:5,9` — `supportHub: "https://support.safing.io"`.
- `i18n/helptexts.yaml:17,371` — tooltip URLs.

(There are also four occurrences of `safing.io` in Go code that
are intentional — `service/config.go:137-197` four `AutoCheck=false`
comments documenting the local-only stance. That's a deliberate
self-document, not a phone-home.)

### 3g. Intro / welcome modal

`pages/intro/step-1-welcome/step-1-welcome.html:1` —
`<h1>Portmaster Protects Your Privacy</h1>`. That's the *first thing*
a new user sees.

---

## 4. Branding still says Portmaster

Beyond the UI strings:

- `go.mod:1` — `module github.com/safing/portmaster`.
- `cmds/portmaster-core/main.go:21,71,75-76` — binary name in
  `Use:`, `info.Set("Portmaster", "", "GPLv3")`, metric namespace
  `"portmaster"`, `User-Agent: "Portmaster Core ..."`.
- `cmds/portmaster-core/main_linux.go:1-11` — package name in
  `runPlatformSpecifics`. Module path uses `safing/portmaster`.
- `service/status/notifications.go:45` — `Payload: "https://safing.io/support/"`.
- `cmds/updatemgr/scan.go:16` and `service/configure/updates.go:12-25`
  — `https://updates.safing.io/...` as the default update index
  URLs. They're not contacted at runtime because
  `service/config.go:137-197` sets `AutoCheck=false` on every
  updater config, but they're still the configured indices.
- `base/api/router.go:152` — CSP includes `connect-src https://*.safing.io 'self'`.
- `README.md` — unchanged upstream Portmaster marketing.

The Go module-path rename is the biggest single chunk: every Go
file imports `github.com/safing/portmaster/...`. Until that's done,
"filemaster" only really shows up in three places I noticed:
`navigation.ts` ("filemaster is paused", "Resuming filemaster ..."),
`FORK_NOTES.md`, `TODO.md`, and this file.

---

## 5. Test coverage — actually enumerated

Ran `go test ./service/fileaccess/... -v -count=1`. Every test
listed below ran and passed in this session:

| Test | Asserts |
| --- | --- |
| `TestHandlerRouting` | fakeSource drives 3 events through a HandlerFunc; verdicts come back in order |
| `TestAllowAll` | the phase-1 default handler returns allow |
| `TestOpFromMask` (6 sub-cases) | OPEN_PERM→OpOpen, ACCESS_PERM→OpRead, OPEN_EXEC_PERM→OpExec, exec+open→exec wins, EVENT_ON_CHILD doesn't shift op, zero mask→OpOpen |
| `TestResolveMarkMaskDefault` | mask includes OPEN+OPEN_EXEC, excludes ACCESS when interceptReads option is nil |
| `TestResolveMarkMaskWithReads` | mask includes ACCESS when interceptReads is on |
| `TestFileOpString` | String() round-trip for the three op constants |
| `TestSaveLoadRoundTrip` | per-exe JSON persistence: persist via SetPersistPath, load in a fresh handler, rules apply without re-prompting; per-exe scope preserved across reload |
| `TestLoadMissingFileIsNotError` | missing rules file is not an error |
| `TestLoadWrongVersionRejected` | wrong schema version is rejected (not silently dropped) |
| `TestProcessProfileLookupGoesThroughPortmasterHook` | the indirection exists: setting `getProcessWithProfile = stub` actually intercepts. **Does not** drive a real PID through the live chain. |
| `TestProcessProfileLookupNilProcessIsErrNoProfile` | upstream returning `(nil, nil)` surfaces as `ErrNoProfile`, not a nil deref |
| `TestParseAndFormatRuleRoundTrip` | "+ /foo" / "- /foo" / "+ /a/**" round-trip |
| `TestParseRuleRejectsMalformed` | 6 malformed inputs all rejected |
| `TestProfileHandlerRuleHit` | rule present in parsed view bypasses prompter |
| `TestProfileHandlerAllowAlwaysPersistsInProfile` | first call prompts + writes a `+ pattern` to fakeRuleStore; second call hits the rule, tripwire prompter not called |
| `TestProfileHandlerPerProfileIsolation` | vim's allow-always for /home/alice/notes.txt does NOT auto-allow it for cat |
| `TestProfileHandlerDefaultActionPermit` | DefaultActionPermit short-circuits to allow, prompter not called |
| `TestProfileHandlerDefaultActionBlock` | DefaultActionBlock short-circuits to deny, prompter not called |
| `TestProfileHandlerDefaultActionAskFiresPrompter` (2 sub-cases) | `Ask` and `NotSet` both fall through to the prompter |
| `TestProfileHandlerFallbackPopulatesExe` | on lookup error, no resolved exe is forwarded (because the err path returns an empty Path) |
| `TestProfileHandlerNoProfilePopulatesExeAndFallback` | unknown PID → fallback fires with the original event's Path |
| `TestPromptHandlerRuleHitPreseeded` | bootstrap rules in `initial` apply to a seeded exe after first appendRule |
| `TestPromptHandlerAllowOnce` | allow-once doesn't grow the rule list |
| `TestPromptHandlerAllowAlwaysPersists` | allow-always writes a rule, second access hits it |
| `TestPromptHandlerPerExeIsolation` | vim's persisted rule doesn't carry to cat |
| `TestPromptHandlerDenyAlwaysPersists` | deny-always writes a deny rule |
| `TestPromptHandlerNoResponseDefaultsDeny` | prompter returning ok=false → deny, no rule grown |
| `TestPromptHandlerUnknownActionDefaultsDeny` | unknown action ID → deny |
| `TestWalkAndMarkVisitsSubdirs` | recursive walk records exactly the expected dirs, symlink to /etc not followed |
| `TestSetWatchPathsLiveAddRemoveSubtree` | **live**: real FanotifyInit, add root → 5 marks, clear → 0 |
| `TestSetWatchPathsLiveReloadAddsNewSubdirsOnReload` | **live**: subdir created post-walk isn't auto-tracked; next SetWatchPaths picks it up; removed subdir is unmarked on next reload |

What's *not* covered by these tests:

- The fanotify `Run` event loop end-to-end (poll → read → handle →
  respond). No test opens a marked dir and triggers a real `open()`.
- `NotificationsPrompter.Prompt` (the wire format and Response() round-trip).
- The `ProcessProfileLookup` cache invalidation (`parsedRulesFor`,
  `profile_binding.go:111-123`).
- The module-level `Start` / `Stop` lifecycle + `EventConfigChange`
  callback for live-reload (`module.go:31-61`).
- Anything fileaccess-related on Windows / macOS (no-op source).

So phase 3's "live demo verified" claim in `TODO.md` is not a
unit-test fact — it's a manual log entry. The unit-test coverage
is real for the verdict logic and rule machinery; the kernel/
notification/UI integration ends at the seam between
`fanotifySource.handleEvent` and `Handler.Decide`.

---

## 6. Concrete latent issues spotted while reading

1. **`PromptHandler.Save` errors are silently dropped.** `prompt.go:138-145`
   does `_ = h.Save(persistPath)` with a comment acknowledging it.
   A disk-full or perms issue silently loses an "always allow" on
   restart. No logger plumbed through.
2. **`ProfileHandler.promptID atomic.Uint64`** at
   `profile_handler.go:91`. Never read or incremented anywhere in
   the file. Dead field.
3. **Race in `addStringArrayEntry` defer order.** `profile.go:307-356`
   does `defer profile.Save()` *outside* the lock and
   `defer profile.Unlock()` *inside* it. Save reads the same data
   the Unlock just released. Two near-simultaneous AddFileAccessRule
   calls on the same profile could see a save sequence
   `setA → setB → saveA → saveB` where saveA writes stale state.
   `profileDB.Put` probably last-writer-wins so the steady state
   is fine, but the in-between DB record can be inconsistent.
4. **`markRemove` uses the *current* `markMask`** (line 364) rather
   than the mask the inode was marked with. SetWatchPaths protects
   against this on toggle (it remasks with the old mask before
   switching), but anyone else calling `markRemove` while the mask
   is mid-flight would target the wrong mask. Just narrow today.
5. **`/proc/self/fd/N` readlink is racy.** `fanotify_linux.go:473`
   resolves the perm-event path through the symlink to the
   underlying inode, *after* the kernel handed us the event fd.
   A concurrent rename would surface the new name. Acceptable for
   a user prompt; bad for an audit log. Comment doesn't call it out.
6. **No prompt coalescing / rate limit.** A chatty consumer (cat,
   grep, find) will spawn one prompt per fanotify event. The
   fallback handler default-denies on the 30s timeout, but in the
   meantime the user gets stormed. Worth a per-(profile,path) debounce.
7. **Profile auto-creation NotificationsPrompter EventID format.**
   `prompt_notifications.go:51` uses `fmt.Sprintf("fileaccess:%s:%d", e.Op, ...)`
   with `e.Op.String()` (line 26-37). Op for the unknown case is
   "unknown", so a future op the kernel surfaces but our switch
   doesn't decode would produce `fileaccess:unknown:N`. The UI
   filter `startsWith('fileaccess:')` would still match, so this is
   benign but worth pinning the constant.
8. **The Go binary panics on `Set()` not being called** because
   `info.CheckVersion()` requires it (`base/info/version.go:178-191`),
   and `main.go:71` does set "Portmaster". Renaming requires
   coordinating with whatever else asserts on `info.Name == "Portmaster"`
   (none that I found in this pass).

---

## 7. Reuse audit, with code receipts

These are the pieces of upstream Portmaster the file-access path
relies on. All of them I read or grep-confirmed.

| Subsystem | Where filemaster touches it | Evidence it's load-bearing |
| --- | --- | --- |
| `base/notifications` | `prompt_notifications.go:70` calls `notifications.Notify` with `Type: notifications.Prompt` and an EventData payload. Action set is custom (file-flavoured). | Wire format isn't changed; the same protocol the upstream UI uses. |
| `base/config` registry + annotations | `fileaccess/config.go:31-67` registers two options. `profile/config.go:77-100` registers the per-app rule option with `DisplayHintAnnotation: "endpoint list"` so the upstream `app-rule-list` editor draws the +/- entries. | Without the existing annotation handling none of this would render in the Angular Settings page. |
| `base/database` runtime DB | Profile DB and notification subscriptions ride on it. `profile.Save` → `profileDB.Put`. | Not touched in this fork at all. |
| `base/api` | UI websocket; CSP at `base/api/router.go:152`. | Unchanged; the UI talks to it. |
| `service/profile` | `Profile` struct, `LayeredProfile`, `parseConfig`, `GetLocalProfile`, fingerprint matching, profile DB, special profiles. | `profile_binding.go` and `instance.go` consume all of this. |
| `service/process` | `process.GetProcessWithProfile`, `GetOrFindProcess`, `IsPortmasterUi`. | Single entry point in `profile_binding.go:17` via the indirection var. |
| `service/sync` | Module wired in `instance.go:169`. Profile sync rides on the profile DB. | Not touched in the fork. |
| `service/ui` + `base/runtime` | UI server, the runtime DB the notifications get pushed through. | Unchanged. |
| `service/updates` | Local-only (`AutoCheck=false`) per `service/config.go:137-197`. | Mechanism preserved; phone-home disabled. |
| `service/profile/binmeta` | Icons + app names. The icon-test failure in §1 is here. | App-overview consumes it; prompt header doesn't yet. |
| Angular shell — routing, prompt-tray, prompt-entrypoint, app-overview, app-rule-list, settings page, support page, edit-profile-dialog | Re-skinned via TypeScript type swaps in `notifications.types.ts:128-142,222`. | See §3a. |

Surgical edits I saw evidence of (not just claims from FORK_NOTES):

- `service/profile/profile-layered.go` is 245 lines, no MatchEndpoint
  / MatchServiceEndpoint / etc. methods. Comments at line 22-32
  explain the strip.
- `service/profile/config.go` is 104 lines, two options
  (`filter/defaultAction` + `fileaccess/rules`).
- `service/profile/profile.go` no longer has SPN / endpoints /
  splitTun fields. Has `GetFileAccessRules` / `DefaultAction` /
  `AddFileAccessRule`.
- `service/process/find.go` is 48 lines and matches the description
  in FORK_NOTES (`GetProcessByRequestOrigin` is a stub returning
  "not implemented in this fork").
- `service/firewall`, `service/network`, `service/intel`,
  `service/netquery`, `service/resolver`, `service/nameserver`,
  `service/splittun`, `service/compat`, `service/detection`, etc.
  — none of these directories exist (confirmed by listing
  `service/`: 14 entries, none of them network-themed).

---

## 8. What still needs to land

Prioritized by user-visible impact (no more "looks like a finished
product" handwaving):

1. **Dashboard rewrite.** The current dashboard is a Portmaster
   Plus / Pro upsell page with empty data panels. Until this is
   gone, "filemaster" looks broken on first run. This is the single
   biggest gap between the stated goal and what ships.
2. **Strip / hide the dead surfaces.** `/monitor`, app-view
   Connections + Insights tabs, SPN Module, SPN
   account/login/status components, qs-internet / qs-history /
   qs-use-spn / qs-use-splittun / qs-select-exit. Either delete or
   gate behind a feature flag. The "kept as scaffolding" framing
   trades known-empty pages for *visibly portmaster-themed* empty
   pages.
3. **Rebrand.** Go module path rename, `info.Set("Filemaster", …)`,
   metric namespace, README, intro modal, support page URLs, CSP,
   all 21 `safing.io` UI URLs, "Network History … Portmaster Plus"
   tooltips, "Portmaster Free / Plus / Pro" labels.
4. **macOS / Windows surface.** Either ship-as-Linux-only with a
   clear UI banner on non-Linux, or stand up the Windows kernel
   driver / macOS Endpoint Security path. Today these platforms
   build cleanly and silently do nothing.
5. **Live-tested end-to-end harness.** No test exercises the
   fanotify→handler→notification→UI loop. The unit tests are good
   for the decider; the integration is verified only by hand. A CI
   matrix that boots pm-core in a privileged Linux container, opens
   a file under a watched dir, and asserts the notification appears
   would catch a lot.
6. **Activity log.** Once #1-#2 land, the empty `/monitor` slot is
   the obvious place for a file-access history view (SQLite-backed,
   write-only on the daemon side, queryable from the UI).
7. **Phase 5 (Landlock).** Already well-scoped in TODO.md.

---

## 9. Still unverified (honest list)

Things I did not check in this pass, that I'd want before calling
the fork "done":

- The fanotify `Run` loop driving a real `open()` and the kernel
  honouring the verdict. Live in this session: only the
  walk/mark reconciler.
- The end-to-end UI: pm-core → notification → websocket → Angular
  prompt-tray → click → backend Response(). Structurally wired in
  the TS, never run in this session.
- `NotificationsPrompter`'s Notify+Response semantics against a
  real notifications module. Code looks right (`Response()` channel
  pattern matches what the upstream firewall path used), not exercised.
- That `profile.GetLocalProfile` actually creates a profile when
  driven from a real fanotify event (chains via process module).
  Verified the static path; never run a live PID through it here.
- Whether `service/sync` actually transports per-profile
  `fileaccess/rules` arrays through profile export/import. Module
  is wired but I didn't read the sync transport code.
- `app-network-scout` (always rendered in the side-dash) and
  `app-feature-scout` (always rendered) — never opened. Could be
  surfacing portmaster-themed content too.
- `service/integration` (Etw on Windows, OS integration glue). Not
  read. Likely fine on Linux.
- Tauri shell window titles, icons, file metadata. Not read.

---

## 10. TL;DR (re-verified)

Backend: real. The decider chain is genuinely portmaster-reuse:
fanotify event → ProfileHandler (per-profile rules + default action
out of the *unchanged* profile DB) → NotificationsPrompter
(unchanged notification + websocket plumbing) → user action →
`AddFileAccessRule` → profile DB persists → next event hits the
rule with no prompt. Unit tests cover the verdict logic and the
walk/mark reconciler against a live fanotify fd.

Frontend: the file-prompt path through prompt-tray and
prompt-entrypoint is wired (filter, types, action mapping). Almost
everything else is *still Portmaster*: the dashboard, the app-view
Connections + Insights tabs, the monitor page, the SPN modules in
the bundle, the safing.io URLs, the "Portmaster Free / Plus / Pro"
labels, the intro "Portmaster Protects Your Privacy" headline. A
first-time user sees a Portmaster Plus upsell page that happens to
also raise file-access prompts. That's the headline gap.

Cross-platform: Linux-only enforcement, no UI warning on macOS /
Windows.

What's left is mostly cleanup and rebrand. The hard plumbing
question — "can we reuse Portmaster's profile + notification +
config + UI machinery without forking it" — the answer is yes,
and the code commits it.
