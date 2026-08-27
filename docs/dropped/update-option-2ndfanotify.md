# Second fanotify group

Dropped since provides less capability than bpf without less work or risk.

## Goals

- Prevent a process from accessing a protected file by moving it first to unprotected folder.
	- Do this by saving original path to base all future open/execute decisions on
- Let a move that is allowed by the existing Open rules reclassify a file at its destination (drop saved original path).

## Decided behavior

### Namespace changes are classified after they happen

For a rename, Filemaster evaluates the mover with the existing Open rules at the source and destination paths. If both are already allowed, the
move is policy-authorized. Otherwise it is untrusted. A warning is shown for an untrusted change, but the warning does not decide or undo that change.

### Origin overrides

For an untrusted move, Filemaster records the object's first effective source path as its origin. Future Open and File Execute decisions use that origin path only, as if the untrusted move had never happened.

An object's first origin is never overwritten by a later untrusted move. The case that a child leaves a folder with an origin override must be considered carefully.

If a move is policy-authorized, any existing origin override for the moved object is cleared and the destination pathname governs future decisions.

### Hard links

If a hard link is created, Filemaster records **unknown origin**. The user is warned and future Open and File Execute decisions for that object are denied.
This is deliberately fail-closed since the option cannot reliably discover which pre-existing pathname was used as the hard-link source.

### Retention and capacity

Origin records are sparse and persistent. Existing records are never evicted or timed out. A record is removed only when its underlying object no longer exists, not when one of several hard-link names disappears.

If storage capacity prevents Filemaster from recording required namespace state, it warns the user and fails closed. It must never delete an older record or permit a decision because required origin state was unavailable.

## Scope

This option preserves the existing Open and File Execute model. It does not add fanotify read/write interception or split an Open decision into Read and Write permissions.
