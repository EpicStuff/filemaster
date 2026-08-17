# Second fanotify group exploration

> Shared and second-group-specific evaluation checks are in
> [Backend Test Requirements](backend-test-requirements.md).

Explore a second fanotify notification group for Filemaster to make path-based
permissions more robust against renames and other namespace changes, while
keeping the existing permission-event pipeline intact.

Goal:
- Prevent an untrusted process from bypassing path rules by moving a protected file to an unprotected path, waiting, then accessing it.
- Fix the race where a file is renamed by another process while an Open
  permission event is blocked, causing Filemaster to resolve/evaluate only the
  new path.
- Allow applications that are permitted the move to legitimately move/reclassify files so the destination path's rules become authoritative.

The settled choices are in [Decided design](#decided-design); the requirements
below remain the constraints an implementation has to satisfy.

Design requirements:
- Use a separate FAN_CLASS_NOTIF group with FID/name reporting and filesystem marks where supported. Track at least FAN_RENAME; include other namespace events only where they are necessary for correctness.
- Correlate namespace notifications with permission events using stable file identity/FID, not pathname strings or PID alone.
- Identify the process responsible for namespace changes reliably (prefer pidfd/process identity integration with existing Filemaster profile handling).
- Do NOT keep permanent history for every file. Maintain sparse persistent protection overrides only when an untrusted namespace change would otherwise weaken the object's effective permissions.
- An untrusted move from a more-restricted path to a less-restricted path must retain the old protection indefinitely; there must be no timeout that malware can wait out.
- A mover that is permitted the move may cause the new pathname rules to take effect and clear any existing override. Permission comes from the existing rule lists; there is no separate trusted-renamer capability.
- Before answering a permission event, process relevant pending namespace notifications so sequential `rename(); wait(); open()` cannot bypass protection.
- Pending permission events must also be correlated with rename notifications so a concurrent rename does not silently change which path rule is evaluated.
- Treat notification loss/overflow, unsupported FID/filesystem behavior, failed correlation, or otherwise uncertain state conservatively. Never let tracking failure weaken protection.
- Be aware that fanotify cannot make rename atomic: the namespace may change just before FAN_RENAME is generated. Do not claim this closes that kernel-level race; structure the code so this limitation is explicit and fail-safe where possible.
- Consider hard links as another potential path-laundering mechanism. Do not introduce a design that handles rename while trivially allowing the same bypass through link().
- For namespace operations fanotify cannot prevent, optional rollback is acceptable only when it is provably safe (e.g. verify FID before undoing a simple rename/link). Do not rely on rollback for security, and do not attempt unsafe restoration of destructive/overwrite operations.

Reuse existing Filemaster/Portmaster abstractions and event/profile/rule machinery rather than creating a parallel policy system. Keep the change focused and review the current latest Filemaster commit before implementing. Do not add or depend on fanotify read/write interception or classification; this option only addresses namespace tracking around existing Open decisions.

For namespace tracking also cover hard-link creation. Linux reports hard links as FAN_CREATE and FAN_REPORT_TARGET_FID can identify the linked inode/FID and new parent/name. Use this to preserve any existing protection override on new aliases. Note that FAN_CREATE does not report the source pathname of link(), so a previously-untracked protected inode may still be hard-linked into an unprotected path; explicitly investigate/test this limitation rather than assuming hardlinks are fully solved.

## Decided design

None of this is implemented. It records the choices that are settled so an
implementation does not have to relitigate them.

### Override semantics

When an untrusted move is observed, record the object's **origin path** against
its stable file identity — not a frozen verdict. Later decisions evaluate the
existing rule lists against the origin path as well as the current path, and the
more restrictive result wins.

Recording a verdict instead was rejected: verdicts are per-profile, so a frozen
Deny would also block a profile that is legitimately allowed the origin path,
and it would not follow later rule edits. Recording the origin path keeps a
single policy system, as required by the reuse constraint above.

On repeated moves, **keep the first recorded origin**. A later untrusted move
never overwrites it.

### Move permission

A move is permitted when the mover is allowed to **Open** both the source and
the destination. This is an interim model, adopted because Open
(`FAN_OPEN_PERM`) is the only runtime-observable operation the current backend
has; see [Backend Plan §12](backend-todo-plan.md#12-rename-and-move-behaviour)
for the target semantics under LSM support (Source Delete AND Destination Create
or Write) and why they cannot be used yet.

The source is evaluated at its **effective path**: the recorded origin if one
exists, otherwise the literal source path. Without this, laundering would only
take two steps — one untrusted move to record the override, then a second move
by an application that is allowed at the now-unprotected literal path, which
would clear it.

Outcomes:

| Move permitted | Existing origin | Result |
|---|---|---|
| No | none | Record origin = literal source path |
| No | present | Keep the existing origin unchanged |
| Yes | none | Nothing recorded; destination rules are authoritative |
| Yes | present | Clear the origin; destination rules become authoritative |

There is no trusted-renamer flag, capability, or setting. An application that
the rules already permit to open both ends of the move is what "trusted" means
here.

### Folder moves

An override is recorded against the moved object's own identity. A moved folder
therefore carries an override that its descendants do not: the file later opened
is a different object that was never itself moved.

Descendants are resolved at decision time by walking the opened path's ancestors
for the nearest override and rewriting that prefix back to the origin. Stamping
every descendant at move time was rejected — it requires an unbounded subtree
walk while the namespace is still changing under it.

This adds an ancestor lookup to the blocking open path. Cost has to be measured,
not assumed.

### Unsupported kernels and filesystems

Probe at startup: create the notification group with FID reporting and add a
filesystem mark for every watched filesystem. If any of it fails, the module
**fails to start** with an error naming the filesystem or mount responsible.

There is no degraded mode and no fallback. An unusual filesystem inside a watch
scope (overlayfs, some network mounts) is a hard startup failure, which is the
intended behaviour: running with namespace tracking silently absent is the
bypass this option exists to close.
