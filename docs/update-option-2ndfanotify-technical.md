# Second fanotify group — technical design

> Technical companion to [Second fanotify group](update-option-2ndfanotify.md).
> Shared acceptance checks are in [Backend Test Requirements](backend-test-requirements.md).

## Scope and terms

The existing content group remains responsible for blocking Open and File
Execute decisions. The second group reports namespace changes only. It never
responds to, prompts for, or rolls back a namespace syscall.

An **origin override** maps stable object identity to the first effective source
path. An **unknown-origin override** maps stable object identity to a
fail-closed state. An **effective path** is the virtual path after applying any
ancestor origin override.

The option evaluates existing Open policy only. It does not use the future
Delete/Create/Write rename evaluator, and it does not introduce fanotify
read/write interception or classification.

## Notification group and capability probe

Create a separate `FAN_CLASS_NOTIF` group with FID, parent/name, target-FID,
and process-identity reporting where the running kernel supports them. Mark each
filesystem containing a watch scope, rather than only the individual watched
path. Track at least `FAN_RENAME` and `FAN_CREATE`.

At startup, probe group creation and every required filesystem mark. If any
required FID reporting, process-identity reporting, or filesystem mark is not
available, fail module startup and name the responsible filesystem or mount.
There is no degraded mode. An unusual filesystem inside a watch scope
(overlayfs, some network mounts) is therefore a hard startup failure, which is
intended: running with namespace tracking silently absent is the bypass this
option exists to close.

The event parser must validate every variable-length information record by its
type and length; information-record ordering is not an API contract. The stable
object key includes filesystem identity and file handle, not pathname or PID.

## Rename classification

For each rename notification:

1. Resolve its stable object identity, source and destination paths, and mover
   identity.
2. Apply any existing ancestor override to obtain the effective source path.
3. Resolve the mover's profile using stable process identity.
4. Evaluate the existing Open policy at the effective source and destination.
   Only two already-final Allow results authorize reclassification; an absent
   rule, promptable outcome, missing mover identity, or failed correlation is
   untrusted.
5. For an untrusted rename, preserve the first effective source path as the
   object's origin. For an authorized rename, clear the object's existing
   origin.

The rename itself has already completed. "Untrusted" and "authorized" describe
the resulting origin state; they do not attempt to deny or allow the syscall.

## Origin resolution

Before responding to an Open or File Execute event, obtain the event object's
stable identity and look up an exact override. If none exists, walk the current
path's ancestors for a folder override. Rewrite the matching prefix to that
origin and continue resolving until the path has no applicable ancestor
override.

Resolution happens at decision time rather than by stamping every descendant
when the folder moves: stamping requires an unbounded subtree walk while the
namespace is still changing underneath it.

When an origin is found, route the decision pipeline with that origin path only.
Do not also evaluate the current path. This gives an untrusted namespace change
the same policy effect as if it had never happened.

An origin path is recorded rather than a frozen verdict. Verdicts are
per-profile, so a stored Deny would also block a profile that is legitimately
allowed at the origin, and it would not follow later rule edits. Recording the
path keeps a single policy system.

The override store is persistent and keyed by stable object identity. A source
object renamed over a destination keeps its own origin. A replaced destination
record is removed only once its separate object is verified gone; removing one
hard-link name is not enough.

The ancestor walk sits on the blocking open path. Its cost has to be measured,
not assumed.

## Hard links

`FAN_CREATE` reports the new directory entry and, with target-FID reporting,
the target object's identity. It does not report the pathname passed as the
source of `link()`.

If the target already has an origin or unknown-origin override, preserve it.
Otherwise create an unknown-origin override and deny all later Open and File
Execute decisions for that identity until the object is gone.

Scanning for other names that resolve to the same object may be useful for
diagnostics, but it is not an authorization mechanism: it cannot establish a
complete, race-free set of names across a filesystem and mount namespaces. A
partial scan must never turn an unknown origin into an Allow result.

## Ordering, loss, and failure

The notification reader runs continuously. Before the content group answers an
Open or File Execute event, it requests a drain acknowledgement from the
notification worker. The acknowledgement is issued only after the worker has
processed its readable kernel records and earlier local buffers. This prevents a
completed sequential `rename(); open()` from being answered before its known
rename notification is applied.

Notification loss, queue overflow, malformed records, unsupported behavior,
failed correlation, a missing acknowledgement, or uncertainty about object
identity must fail closed. Keep existing origin records; do not allow based on
missing state. A capacity failure likewise preserves existing records and
enters a fail-closed state rather than evicting them.

Fanotify does not make a rename atomic with the later Open decision. Concurrent
namespace races remain a kernel limitation and must be explicit in diagnostics,
tests, and user-facing claims.

## Implementation boundaries

Reuse Filemaster's existing fanotify lifecycle, process/profile resolution,
rule evaluation, prompt, diagnostics, and shutdown machinery. Add only the
namespace-notification reader, stable-identity handling, origin store, origin
rewrite, and the synchronization boundary needed to integrate it.

The current Filemaster source permits an event outside the active path scope.
Origin and unknown-origin checks must occur before that fast-path Allow so a
laundered object cannot escape through its current pathname.

## Required verification

In addition to the shared acceptance checklist, verify:

1. A child moved out of an overridden folder receives the folder-derived
   effective source as its first origin.
2. An authorized move clears an existing origin only when both existing Open
   evaluations already allow.
3. A hard link preserves a known origin, while a first hard link of an object
   without an origin becomes unknown-origin and denies later Open and File
   Execute decisions through every alias.
4. Deleting one hard-link name retains the record; deleting the underlying
   object removes it.
5. Queue overflow, parser failure, unavailable capacity, and failed drain
   acknowledgement all remain fail-closed.
