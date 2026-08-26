# Backend Feature Requirements

These are the product features a future Filemaster backend should aim to provide.
Kernel mechanisms, hook placement, event reporting formats, and constant names
live in [Backend Features Technical](backend-features-technical.md).
Candidate-specific constraints and tests belong in the corresponding backend
notes and [Backend Test Requirements](backend-test-requirements.md).

These are product requirements, not a claim that every candidate backend can
implement them. Each option document states the subset it can enforce.

## Terminology

* **Open** is the current permission operation. It is the operation represented
  by the current fanotify permission event.
* **Read** and **Write** are future permissions requested at Open time. They do
  not mean per-read or per-write fanotify events.
  A per-read permission event
  was considered and removed: `FAN_ACCESS_PERM` only fired on reads through an
  already-open descriptor, could not distinguish read from write, and added no
  enforcement that `FAN_OPEN_PERM` does not already provide.
* **Execute** is permission to launch a file as a program.
* **Access** is a legacy UI rule label for Open; it is not a separate
  operation and notify me on encounter.

## Rule model

* Read, Write, and Execute each use a separate ordered rule list. A list may
  contain both file and folder rules.
* The first applicable matching rule decides. A file rule does not inherently
  outrank a folder rule; configured order decides. The profile default applies
  only when no applicable rule matches.
* Modifying an existing file's contents or metadata uses the target file's
  Write rules. A nonrecursive rule for its parent folder does not apply merely
  because the file is inside it.
* Entry-changing operations use the applicable Write rules for their affected
  objects and parent folders. Delete evaluates the target and its containing
  folder. Create evaluates the future destination path and its parent folder.
* Rename, move, and replacement require both a source Delete decision and a
  destination decision: Create when the destination does not exist, or Write
  when it does.
* An unsupported operation fails closed; it must not fall back to Open/Read
  policy, a prompt that can Allow it, or a learned rule.
* Hard-link and symlink policy needs an option-specific design. Do not infer it
  from the generic rule model alone.

## Event records

* Every persisted Open and Execute record retains the protected mount's stable
  ID and display path when attribution is available.
* Attribution uses the active protected-mount state at decision time. The
  deepest applicable mount wins.
* No applicable mount or pending reconciliation is recorded as explicit
  unknown. The service must not guess an unrelated mount after a mount change.

## Rules

These apply to every permission event described below.

* **Freeze semantics.** A permission event freezes the triggering application
  before the operation takes effect. It resumes only after an Allow/Deny
  response. There is no timeout; a freeze may last indefinitely.
* **Freezes are killable.** A frozen application must remain killable, so an
  unanswered event can always be escaped without rebooting.
* **No locks held during a freeze.** Nothing that unrelated processes can block
  on stays held while an event waits for an answer. A freeze must never stall
  processes that are not part of it.
* **Re-validation.** An approval is re-checked before the operation commits: the
  object, parent directory, and name must still be what was approved. On
  mismatch the operation fails with a documented error rather than proceeding on
  a stale approval or silently re-prompting.
* **Event context.** Every permission event identifies at minimum the operation,
  the process, the object, the mount context, the path as resolved when the
  event was raised, and the second object where the operation involves two.
* **Path is context, not identity.** The path is rendered when the event is
  raised, so it cannot be raced between the event and the response. It is
  supplied for policy decisions and display; the object identity remains
  authoritative.
* **No separate event types for higher-level cases.** Distinctions such as
  create-versus-replace are derived by Filemaster from the state reported in the
  event.
* **Existing behaviour is preserved.** Existing event types, response semantics,
  and the existing execute permission event continue to work unchanged.

---

## Super High Priority

### Directory-modifying operations

Each is decided before the operation commits and re-validated before it takes
effect, per the rules above.

* **Pre-delete** for files and directories.
* **Pre-link** for hard links and symlink creation, reporting source and
  destination context.
* **Pre-create**, reporting the parent directory and the new name before the
  object exists. The object has no identity yet, so it is identified by parent
  and name.
* **Pre-rename/move**, reporting trustworthy source and destination. Where the
  destination already exists, its identity is reported in the same event, since
  approving the rename also approves destroying it — the two are one atomic
  operation and cannot be answered separately.

## High priority

### Open

* The open permission event reports the **requested access mode** — read, write,
  or both — as supplied by the application.
* The response is **three-valued**: Allow, Deny, or Allow-read-only.
* Allow-read-only on an `O_RDWR` open succeeds with write access removed. The
  application observes an ordinary read-only descriptor: the open succeeds, the
  descriptor reports read-only, and a later write fails as it would for any file
  opened read-only.
* Allow-read-only on a **write-only** open is a deny; there is no read grant to
  fall back to, and the resulting error is documented.
* Allow-read-only **cancels `O_TRUNC`**. A downgraded open must not truncate the
  file.
* Denying write at open also prevents modification through memory mappings, so
  there is no separate mapping event for the user to answer.

### Directory listing

* Listing a directory's contents is a permission event **distinct from opening
  the directory**. Opening a directory to reach a known file and enumerating
  everything inside it are separately decidable.
* **One decision covers a whole enumeration** by that application, not each read
  of directory entries, so listing a large directory does not produce a stream
  of events.

### Other operations

* **Pre-truncate**, covering explicit truncate and ftruncate. (`O_TRUNC` is
  covered by the open rules above.)
* **Metadata-write permission events**, covering at least permission changes,
  ownership changes, timestamp changes, and extended-attribute writes.
* **fallocate and hole punching**, reporting the affected byte range and the
  requested mode, so that allocation is distinguishable from operations that
  destroy content.
* **Clone / reflink**, which replace a file's contents with no read or write
  call. Both source and destination are identified in the same event.

### Group behaviour

* **Fail-open versus fail-closed is selectable** when the listener is
  established, defaulting to fail-open to match existing behaviour. This governs
  what happens when Filemaster dies with events outstanding, and what happens
  when the event queue is full. Behaviour in both situations is defined and
  documented for both settings.
* Behaviour is defined for **interrupted waits, cancellation, and malformed
  responses**.
* **Capability discovery**: userspace can determine which of these features the
  running kernel supports, and can never silently assume enforcement that is not
  present.

---

## Medium priority

* **Metadata-read permission events**, covering at least stat-family calls, and
  optionally extended-attribute reads, symlink reads, and access checks.

  Two requirements specific to this event, both of which are part of the feature
  rather than deployment notes:

  * **No file descriptor is delivered.** Unlike every other permission event,
    this one reports path and file identity only. Opening a file merely to
    describe it is expensive relative to the operation being decided, and has
    side effects — opening a FIFO blocks until a writer appears, and opening
    some device nodes changes their state. Listing a directory of device nodes
    must not cause any of that.
  * **Suppression must scale to a subtree.** Metadata reads are generated in
    very large numbers by ordinary activity — a status check on a source tree
    issues thousands. Silencing one object at a time reproduces the problem it
    is meant to solve. This event is not complete when it fires correctly; it is
    complete when there is a workable way to stop it firing for a whole subtree.

---

## Low priority

* **Write permission events**, promoting the existing modify notification into a
  freezing event. A per-write event produces one freeze per write call, so it is
  only usable in combination with suppression. Listed so that the promotion of
  notifications into permission events is complete, not because Filemaster
  intends to use it — Filemaster decides Read and Write at Open.
* **Dedupe.** Lower value than clone, since the kernel verifies the ranges are
  identical before sharing and contents therefore do not change. It also does
  not fit the two-object reporting used by rename and clone.
* **Directory traversal permission events.** Deciding path lookup itself, as
  opposed to opening or listing a directory. Expensive enough that it needs a
  design of its own.
* **Listener self-exemption in the kernel**, so a group does not receive events
  for its own activity. Until then the listener filters its own events by
  process identity.
* **io_uring parity.** Operations issued through io_uring must reach the same
  enforcement and be attributed to the issuing process, so prompts and rules
  name the real application. Treated as a correctness requirement to verify
  rather than a feature to build.
