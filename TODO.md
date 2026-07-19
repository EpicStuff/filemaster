# filemaster — implementation steps

Completed task checklists have been removed after confirmation in implementation
history and runtime tests. Their goals and durable operational lessons remain
here for context. See `FORK_NOTES.md` for the deletion history.

## Completed milestones — goals and lessons

### Phase 1 — minimal fanotify daemon

Goal: prove the kernel plumbing with one Go package that opens a fanotify
group, marks a path, and returns allow/block verdicts.

Lessons / footguns:

- `FAN_MARK_MOUNT` marks the entire mount rather than one path. On a root
	filesystem this can route every open through the daemon and freeze the host
	when verdicts cannot keep up. Use an inode mark with `FAN_EVENT_ON_CHILD` for
	a single-directory watch.
- Exclude the daemon's own PID: an open from its handler would otherwise block
	waiting for a verdict from itself.
- Fanotify needs an initial user namespace, `CAP_SYS_ADMIN`, and a seccomp
	profile that permits `fanotify_init`. Typical Docker requirements are
	`--userns=host --cap-add=SYS_ADMIN --security-opt seccomp=unconfined` (or an
	equivalent custom profile).

### Phase 2 — file rule matching

Goal: match exact paths, single-segment globs, and recursive `/**` patterns
	against file-access events, with rules stored per resolved app profile.

### Phase 2.5 — per-app rules

Goal: ensure a rule granted to one executable/profile does not auto-decide the
	same path for a different app.

### Phase 3 — prompt loop end-to-end

Goal: an unknown path access creates a prompt; the selected action persists as
	a rule when appropriate, and the next access is auto-decided.

Lesson: multiple `FAN_CLASS_CONTENT` listeners on the same inode are combined
	by the kernel, so any denying listener denies the syscall. Stop stale daemons
	before a focused fanotify test.

### Phase 3.5 — recursive watches and auto-profiles

Goal: cover watched subdirectories and use Portmaster's existing local-profile
	auto-creation for previously unseen executables.

### Phase 4 — UI

Goal: render file prompts and file-access activity in the existing Angular /
Tauri shell rather than network prompts and activity.

## Phase 4.5 — legacy UI cleanup

Goal: replace or remove every remaining network-era surface whose backend was
removed with the network stack.

- [ ] Decide whether the dashboard should gain file-access equivalents for
	recent activity, allowed/blocked activity, and affected applications, or
	whether those widgets should be removed.
- [ ] Remove or replace the dashboard's country, bandwidth, and other
	connection-oriented widgets, their Plus-feature gates, and the News widget,
	which currently show empty data or a 404 result.
- [ ] Remove the residual SPN profile subscription and any remaining netquery
	callers/services with no file-access replacement.
- [ ] Remove or convert the per-app Insights view, Internet/History quick
	settings, and remaining network-history / active-connections header details.
- [ ] Audit the surviving Portmaster-era side-dash, feature-scout, intro,
	support, and Tauri shell surfaces; remove or convert anything that still
	presents network, SPN, or Portmaster functionality.
- [ ] Extend the relevant E2E coverage when those surfaces are finalized so a
	deleted backend cannot silently leave an empty widget in the UI.

## Reliability and platform support

- [ ] Decide and document the support contract for non-Linux builds: either
	show a prominent UI warning that file-access enforcement is unavailable on
	macOS and Windows, or implement an equivalent platform source.
- [ ] Add a privileged Linux integration test that drives a real fanotify
	permission event through the daemon, prompt response, and recorded activity.
	The existing fake-socket E2E test remains valuable but cannot verify the
	kernel event loop or fanotify verdict.
- [ ] Triage the remaining file-access hardening findings: report rule-save
	failures instead of dropping them, remove dead prompt state, make profile
	rule persistence safe under concurrent writes, consider per-profile/path
	prompt coalescing, and document the rename race in audit paths.

## Phase 5 — per-app sandboxing (Storage-Scopes-style)

Optional per-app sandboxing goal.

**Landlock vs mount namespaces:** Landlock LSM (Linux 5.13+, syscalls
`landlock_create_ruleset` / `landlock_add_rule` / `landlock_restrict_self`)
is probably the right primitive here, not mount namespaces. It's self-imposed
by the sandboxed process, inherits across `clone()`, doesn't need root-per-app,
and stacks cleanly with the fanotify prompt layer (fanotify intercepts the
first access for the prompt; Landlock enforces the resulting rule cheaply
in-kernel). Mount-namespace + OverlayFS still wins if we need transparent path
*rewriting* (Storage-Scopes-style) rather than just deny — Landlock can only
allow/deny, not redirect.

- [ ] Decide: pure Landlock (deny-only) vs. Landlock + namespace-redirect
	hybrid.
- [ ] If hybrid: per-app mount namespace + bind/OverlayFS for redirect cases,
	Landlock for everything else.
- [ ] Define endpoint actions: `sandbox:~/Documents=allow` (Landlock) and
	`redirect:~/Documents=/var/lib/filemaster/<app>/Documents` (namespace).
- [ ] Build a launcher shim that applies the ruleset before `execve` (Landlock
	must be set up by the parent).

## other stuff
- make sure user is notified of failed fan mark

## Potential Future Features
- comptemplate clamav integration feasability
- comptemplate app groups feasablilty
	- so python file1.py and python file2.py show under the same group but different rules/profile without needing to manually configure it

## Cross-cutting cleanup

- [ ] Rename the binary and module path from `portmaster` to `filemaster`.
	The module-path rename touches every Go file.
- [ ] Drop the `safing.io` / Portmaster branding from `info/info.go`.
- [ ] Trim the README to describe the fork.
- [ ] Replace remaining Portmaster/Safing strings, URLs, updater defaults,
	and CSP allowances across the UI, prompt text, support surfaces, and Tauri
	metadata.
