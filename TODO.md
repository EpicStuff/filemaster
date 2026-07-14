# filemaster — remaining implementation work

This tracker intentionally contains only work that is still open. Completed
fanotify, rule-storage, prompt-loop, UI, testing, and Portmaster-reuse work
has been removed after confirmation in implementation history and runtime
tests. See `FORK_NOTES.md` for the deletion history and `UI_GAPS.md` for
remaining legacy UI surfaces.

## Phase 5 — per-app sandboxing (Storage-Scopes-style)

Stretch goal from the original ChatGPT discussion.

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

## Cross-cutting cleanup

- [ ] Rename the binary and module path from `portmaster` to `filemaster`.
	The module-path rename touches every Go file.
- [ ] Drop the `safing.io` / Portmaster branding from `info/info.go`.
- [ ] Trim the README to describe the fork.
