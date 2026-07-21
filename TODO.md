# todo

## per-app sandboxing (like Grapheneos Storage Scopes)

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

## known bugs

## other stuff

- make sure user is notified of failed fan mark
- the README
- maybe add warning popup when you enter / to watch path
- maybe add file picker for watch path and rules
- maybe add warning when add rule for path outside watch
- try to make is so a root virus cant stop filemaster without user noticing
- look into "the curent intended design is that the user facing rules do not differentiate between folders and files, but i guess some way to tag the rule as for only folders or only files could be nice, like how i think portmaster has a upd/tcp tag"
	```Normal user facing rules intentionally apply to both files and folders, so the absence of a file only distinction is not currently a correctness problem.

The rule language could optionally support qualifiers such as:

@file:
@folder:

This would allow advanced users to restrict a rule to only files or only folders, similar to how Portmaster supports qualifiers such as TCP and UDP. Unqualified rules would continue to apply to both.```

## Potential Future Features

- comptemplate clamav integration feasability
- comptemplate app groups feasablilty
	- so python file1.py and python file2.py show under the same group but different rules/profile without needing to manually configure it

## Cross-cutting cleanup

- [ ] Rename the binary and module path from `portmaster` to `filemaster`.
	The module-path rename touches every Go file.
- [ ] Drop the `safing.io` / Portmaster branding from `info/info.go`.
- [ ] Replace remaining Portmaster/Safing strings, URLs, updater defaults,
	and CSP allowances across the UI, prompt text, support surfaces, and Tauri
	metadata.
