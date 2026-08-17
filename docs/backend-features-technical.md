# Backend Features Technical

> **Status: unreviewed research note.** This document records the kernel-level
> mechanisms behind the product behaviour in
> [backend-features.md](backend-features.md). It does not change that behaviour
> and does not select a backend architecture. Constant names are provisional.

Source material: the fanotify permission-event extension feature list
(`~/fanotify/Readme.md`) and its accompanying patch notes, which describe
extending fanotify with blocking pre-operation permission events — promoting
notification-only events into freezing permission events, splitting open into
independent read and write grants, and covering operations that have none today.

## Hook placement and re-validation

1. The freeze point must not hold any directory lock, inode lock, rename lock,
   or any other lock that unrelated processes can block on.
2. Where the current notification hook sits inside a locked region, the
   permission hook is placed earlier: after the parent directory and name are
   resolved, before the lock is taken.
3. Because no lock is held across the freeze, an approval is re-checked once the
   lock is taken — object, parent directory, and name must still match what was
   approved when the operation commits.
4. On mismatch the operation fails with a distinct errno rather than proceeding
   or silently re-prompting.

## Event context and reporting

1. Every permission event carries at minimum: operation type, process identity,
   object identity as a file descriptor where one exists, the path as resolved
   by the kernel at hook time, mount context, and the second object's identity
   and path where the operation involves two.
2. The kernel renders the path at hook time, so it cannot be raced between the
   event and the response. The file descriptor remains the authoritative
   identity.
3. Higher-level distinctions such as create-versus-replace are derived by
   userspace from the reported state, not from distinct kernel event types.

## Reuse of existing machinery

1. Marks, event queues, blocking and waiting, Allow/Deny responses, ignore
   masks, overflow handling, and group lifecycle are reused rather than
   duplicated.
2. New context is delivered as new variable-length info records. The
   fixed-layout event metadata struct is not extended.
3. Existing event types, response semantics, and the existing execute permission
   event continue to work unchanged.
4. Several pieces this design needs already exist in mainline and should be
   reused rather than reinvented: `FAN_DENY_ERRNO` for returning a chosen errno
   from a permission response, `FAN_EVENT_INFO_TYPE_RANGE` for byte-range
   reporting, `FAN_EVENT_INFO_TYPE_MNT` for mount context, and the
   `FAN_RENAME` two-object reporting (`OLD_DFID_NAME` / `NEW_DFID_NAME`, plus
   `FAN_REPORT_TARGET_FID` for an existing destination). The gap for rename is
   that this reporting exists for notifications, not for a freezing
   pre-operation event.

## Open

1. The event reports the requested access mode as supplied by the application.
2. The response is three-valued: Allow, Deny, or Allow-read-only.
3. Allow-read-only on an `O_RDWR` open succeeds with write access removed, so
   the descriptor the application receives is an ordinary read-only descriptor.
4. Allow-read-only on a write-only open is a deny; there is no read grant to
   fall back to. The errno is defined and documented.
5. Allow-read-only cancels `O_TRUNC`.
6. A writable memory mapping requires a writable descriptor, so denying write at
   open also prevents modification through mappings. No separate mapping
   permission event is required.

## Directory listing

The decision is scoped to the open file description, not to the individual
syscall, so enumerating a large directory produces one event rather than one per
buffer-fill.

## Directory-modifying operations

Each freezes before the directory lock is taken and re-validates after, per the
hook-placement rules above.

1. **Pre-create** reports parent directory, name, and path before the object
   exists. The object has no identity yet, so it is identified by parent and
   name.
2. **Pre-rename/move** reports source and destination. Where the destination
   already exists, its identity is reported in the same event, because the
   rename and the destruction of the destination are one atomic operation.
3. **Pre-link** reports source and destination context for hard links and
   symlink creation.

## Other operations

1. **Pre-truncate** covers explicit truncate and ftruncate; `O_TRUNC` is handled
   by the open path instead.
2. **fallocate and hole punching** report the affected byte range and the
   requested mode.
3. **Clone / reflink** covers `FICLONE` and `FICLONERANGE`, reusing the
   two-object reporting built for rename. Both objects are already-open file
   descriptors, so no path resolution or re-validation is required.

## Group behaviour

1. Fail-open versus fail-closed is selectable at group creation, defaulting to
   fail-open to match existing behaviour. It governs what happens when the
   listener dies or closes its descriptor with events outstanding, and when the
   event queue is full.
2. Behaviour is defined for interrupted waits, cancellation, and malformed
   responses.
3. Capability discovery lets userspace determine which features the running
   kernel supports, so it can never silently assume enforcement that is not
   present.

## Metadata-read events

1. **No file descriptor is delivered.** The existing file-identity reporting
   mode (`FAN_REPORT_FID` and friends) is the obvious basis, but it is not free
   reuse: fid reporting has historically been restricted to `FAN_CLASS_NOTIF`,
   so combining it with a permission class needs verifying against the target
   kernel before this is assumed to work. The requirement either way is that the
   event never depends on descriptor delivery. Opening a file merely to describe
   it is expensive
   relative to the operation being decided and has side effects — opening a FIFO
   blocks until a writer appears, and opening some device nodes changes their
   state.
2. **Suppression must scale to a subtree.** Existing ignore masks are
   per-object, so silencing a directory tree would require one decision and one
   mark per file, reproducing the problem it is meant to solve.

## Low-priority mechanisms

1. **Write permission events.** There is no write-specific blocking hook today.
   `FAN_PRE_ACCESS` (`FAN_CLASS_PRE_CONTENT`) is a blocking pre-content hook,
   but it exists to populate content on demand rather than to decide writes, and
   is not split by access mode. Promoting the existing modify notification into
   a freezing event produces one freeze per write call, usable only in
   combination with ignore masks.
2. **Dedupe** (`FIDEDUPERANGE`). A single call takes one source and an array of
   destinations, processed individually with per-destination status, so it does
   not fit the two-object reporting used by rename and clone. The kernel also
   verifies the ranges are identical before sharing, so contents do not change.
3. **Directory traversal permission events.** Path lookup runs in a mode where
   blocking is not permitted, so this requires forcing a retry into the slower
   lookup path.
4. **Listener self-exemption in the kernel**, so a group does not receive events
   for its own activity. Until then the listener filters its own events by
   process identity.
5. **io_uring parity.** Operations issued through io_uring must reach the same
   hooks and be attributed to the issuing process rather than to a kernel worker
   thread.
