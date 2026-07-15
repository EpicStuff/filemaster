# Fanotify Core Plan

## Goal

Replace recursive directory marking with mount marking.

Watch configured filesystem scopes, including `/`, without recursive startup
marking or serially delaying ordinary desktop activity. Filemaster must make
permission decisions in parallel, preserve enforcement for prompted accesses,
and keep audit, logging, persistence, and UI work off the decision critical
path.

## Confirmed decisions

* The first implementation uses mount marks only. Recursive directory marks are
  deferred.
* A configured path is a policy scope. Filemaster marks the mount containing
  that path and every separate nested mount beneath the scope.
* Paths on the same mount share one kernel mark. Events elsewhere on that mount
  are immediately allowed when they fall outside every configured policy scope.
* Filemaster core and UI processes use normal profile policy. They are not
  unconditionally allowed. Existing Portmaster core and UI profile identities
  remain in use.
* Filemaster core policy is maintained as an immutable in memory snapshot so
  deciding its own events does not require profile storage or process lookup.
  This is a different execution path, not a policy exemption.
* Identical requests from the same profile are grouped into one visible prompt.
* A full global decision queue or exhausted pending event budget causes an
  immediate deny for the new in scope request.
* Audit and activity recording occur only after the permission response.
* A separate privileged enforcement broker is deferred. The plan records the
  limitation that a forced termination of the fanotify owner is fail open.

## Kernel and resource constraints

* A fanotify permission event blocks only its requesting `open()` or `exec()`
  until Filemaster replies `FAN_ALLOW` or `FAN_DENY`.
* Many processes and threads can have events pending concurrently. A browser
  can therefore create many pending events even though each individual thread
  is blocked on one request.
* The fanotify kernel queue is bounded by the host configuration used when the
  group is created. Filemaster must not request an unlimited queue by default.
* `FAN_Q_OVERFLOW` has no usable event FD and must be detected from the event
  mask. It is a serious enforcement warning, not an event to ignore.
* Reading a normal event installs an event FD in Filemaster. That FD remains
  open until Filemaster responds and closes it. Pending events must therefore
  be limited independently of the kernel queue.
* Closing the fanotify group allows all permission events that are still queued
  or awaiting a response. Controlled shutdown can deny first, but `SIGKILL`, a
  crash, or killing the process that owns the group remains fail open.
* A mount mark covers one mount. It does not automatically cover a separate
  mount nested beneath it.

## Mount strategy

### Policy scopes and kernel marks

For every configured protected path:

1. Normalize the path and retain it as a policy scope.
2. Resolve the mount containing that path.
3. Discover separate mounts nested beneath that path.
4. Deduplicate all required marks by mount identity.
5. Apply one `FAN_MARK_MOUNT` mark per required mount.

Calling `fanotify_mark()` with `FAN_MARK_MOUNT` on `/path/to/dir` marks the
mount containing that directory. The directory does not need to be a mount
point.

A mount mark may observe much more than the configured protected path. The hot
path therefore classifies the resolved event path against an immutable policy
scope snapshot. Events outside all protected scopes are allowed immediately
without process or profile resolution.

Configuring `/` means all descendant paths are in scope, including paths on
separate nested mounts. Filemaster must therefore mark every current mount in
its mount namespace, not only the root mount.

### Mount topology changes

Filemaster must reconcile mount topology while running so a newly attached
mount beneath a protected scope is added and a detached mount is removed.
Implementation may use a mount topology watcher or bounded periodic
reconciliation, but the resulting behavior and any coverage delay must be
visible in diagnostics.

### Configuration changes

Do not walk directory trees on configuration changes. Reconcile immutable old
and new policy scope and mount identity sets:

* add marks required only by the new configuration;
* remove marks no longer required;
* retain unchanged marks;
* atomically replace the policy scope snapshot after mark reconciliation.

A mark mask change, such as toggling read access interception, may require
replacing existing marks with the new mask.

## Event ownership

Represent every permission event as an owned event lease rather than passing a
bare `FileEvent` through a synchronous handler.

```go
type PendingEvent interface {
	Event() *FileEvent
	Respond(Verdict) error
}
```

The implementation may use a concrete internal type, but it must guarantee:

* exactly one current owner;
* at most one response;
* the event FD closes after the response attempt;
* ownership can move from a decision worker to the prompt coordinator;
* panic, cancellation, overload, and shutdown paths still resolve ownership;
* concurrent response writes to the fanotify group are serialized safely.

## Parallel event pipeline

```text
fanotify kernel queue
        ↓
single reader
        ↓
metadata validation, overflow detection, path resolution, scope classification
        ↓
outside scope: allow immediately
inside scope with exhausted global budget: deny immediately
        ↓
bounded decision worker queue
        ↓
rule or profile default: respond immediately
ask: transfer ownership to prompt coordinator
        ↓
response written and event FD closed
        ↓
asynchronous audit, activity, persistence, logging, and metrics
```

### Reader responsibilities

The reader may perform only work required to safely route the event:

* validate metadata and event length;
* detect `FAN_Q_OVERFLOW`;
* construct the event lease;
* resolve the path from the event FD;
* classify the path against the immutable policy scope snapshot;
* enforce the global outstanding event budget;
* enqueue in scope events or send an immediate overload verdict.

The reader performs no general process lookup, profile lookup, prompt work,
rule parsing, persistence, activity recording, or verbose per event logging.

### Decision workers

* Start with four workers and expose the count as a backend setting.
* Use one bounded queue. Never create one goroutine per event.
* When the decision queue is full, immediately deny the new in scope event.
  Do not leave it waiting and do not discard it without a response.
* Rule hits and profile default permit or block decisions respond immediately.
* Workers transfer Ask events to the prompt coordinator and return to the
  worker pool.
* Filemaster core events use a dedicated in memory evaluation path that applies
  the same profile rules and default action. It must not invoke general process
  lookup or profile storage while deciding its own access.

The existing benchmark found four workers best for path classification and
eight best for a nearly empty allow path. This is only an initial default. The
final choice requires benchmarks using real process, profile, rule, prompt, and
observation handling.

## Outstanding event limits

Maintain both a per profile pending budget and a global outstanding event
budget.

The global count includes every in scope event FD currently held by Filemaster:

* waiting in the decision queue;
* being processed by a worker;
* owned by the prompt coordinator;
* waiting for its response write to finish.

The usable global limit must never exceed the process soft `RLIMIT_NOFILE`
minus reserved headroom for Filemaster databases, sockets, logs, configuration,
and ordinary operation.

When the global budget is exhausted, new in scope events are immediately
denied. When a profile reaches its pending budget, new Ask events for that
profile are immediately denied until its pending count falls below the limit.
Rule hits and profile default decisions do not join the prompt budget because
they are answered immediately.

Expose current and peak global pending counts, per profile pending counts,
queue saturation denies, profile overload denies, and event FD response
errors.

## Process and profile decision snapshots

### Process resolution

Reuse Portmaster's existing process store and process identity based on PID plus
process creation time. Do not add a second general PID cache.

This prevents PID reuse from returning the previous process profile. Process
resolution should continue through the existing Portmaster process and profile
flow so auto creation and special core or UI profiles remain consistent.

An allowed `FAN_OPEN_EXEC_PERM` can replace the executable while retaining the
same PID and creation time. After responding to an exec event, invalidate or
refresh the corresponding process mapping so later events resolve the new
executable and profile.

### Profile snapshots

Each loaded profile must expose an immutable file access decision snapshot
containing at least:

```go
type DecisionSnapshot struct {
	ProfileID	string
	Source		string
	DefaultAction	uint8
	Rules		PathRules
	Revision	uint64
}
```

Profile configuration changes parse rules once, create a new immutable
snapshot, and atomically replace the old snapshot. Decision workers only read
that snapshot.

The Filemaster core profile uses the same snapshot format and policy semantics.
It is loaded before fanotify marks are installed and refreshed through the
existing profile change events.

Remove the current rule cache behavior that considers a profile unchanged when
only the number of raw rules is unchanged. Editing a rule without changing the
count must replace the snapshot. Do not retain a profile owned raw rule slice
after releasing its lock. Copy the rules while locked or obtain an already
immutable snapshot.

The decision path must not synchronously:

* read the profile database;
* parse raw profile rules;
* persist audit records;
* write verbose logs;
* update UI activity;
* persist an Always rule before answering the current event.

## Prompt coordinator

Prompt presentation is asynchronous, but enforcing prompts retain their event
leases until the user answers, the request times out, overload policy denies
it, or controlled shutdown resolves it.

### Exact request grouping

The first implementation groups exact duplicate requests using:

```text
profile source and profile ID
operation
normalized exact path
```

One visible prompt owns a group of one or more pending event leases. A response
resolves every lease currently in that group with the same verdict.

Every grouped event still counts against the per profile and global event
budgets. Once either budget is exhausted, additional matching events are denied
rather than added to the existing group.

Requests without a resolved profile use an unidentified bucket that includes a
stable process identity so unrelated unidentified programs are not grouped
together.

### Prompt results

* Allow and Deny resolve the current group only.
* Allow Always and Deny Always update the in memory profile snapshot first,
  then resolve the current group and any other exact pending groups matched by
  the new rule.
* Rule persistence occurs asynchronously after the response.
* Persistence failure raises a visible warning. The in memory decision remains
  valid for the current run but may be lost after restart.
* Prompt timeout defaults to deny.
* Controlled shutdown defaults all pending prompt groups to deny.

Broader parent directory grouping remains a later design phase because it
requires choosing a safe rule boundary. Exact duplicate grouping does not wait
for that work.

## Shutdown and forced termination

### Controlled shutdown

1. Remove all fanotify marks so no new events are generated.
2. Stop admitting new work to the decision queue.
3. Deny queued events that have not started policy evaluation.
4. Deny every pending prompt group.
5. Wait for active decisions and response writes to finish within a bounded
   shutdown deadline.
6. Close the fanotify group only after outstanding event ownership reaches
   zero or the shutdown deadline expires.

### Forced termination limitation

The Linux fanotify API allows queued and pending permission events when the
fanotify group closes. A process cannot run cleanup after `SIGKILL`.
Consequently, one userspace process owning the fanotify group cannot guarantee
fail closed behavior after its own forced termination.

A later hardening phase may split enforcement into a small root owned broker
that owns the fanotify group and denies requests whenever the main Filemaster
service is unavailable. Killing the broker itself would still fail open. A
strong guarantee against a privileged attacker requires an in kernel policy
mechanism such as an LSM implementation.

The initial implementation should still harden the Filemaster service so an
unprivileged process cannot signal or modify it, and should restart it promptly
if it exits unexpectedly.

## Audit and activity recording

Separate permission decisions from observation.

After a successful response write, enqueue the `filequery` record, activity
update, detailed log event, and metrics update. The observation queue is
bounded and may drop records under overload, but it must never delay an allow
or deny response.

Track and expose observation drops separately from enforcement queue overflow
or overload denial.

## Configuration and UI

Backend options cover at least:

* protected path scopes;
* worker count;
* decision queue capacity;
* per profile pending event budget;
* global outstanding event budget and FD reserve;
* prompt timeout;
* overload verdict, initially deny;
* read access interception, disabled by default and unsuitable for root wide
  use without dedicated benchmarks;
* mount topology reconciliation status;
* metrics and diagnostics visibility.

There is no recursive or mount strategy selector in the first implementation
because only mount marks are supported.

Every backend option requires a matching Angular UI control, description, and
safe default. UI implementation remains deferred until the backend contract is
stable.

## Required metrics and warnings

At minimum expose:

* kernel queue overflow count;
* decision queue depth, peak depth, and saturation deny count;
* active and configured decision workers;
* decision and response latency;
* current and peak outstanding event FDs;
* per profile pending event count and overload deny count;
* current prompt group count and grouped event count;
* response write errors;
* observation queue depth and dropped record count;
* watched policy scopes and resolved mount identities;
* mount topology reconciliation errors or delayed coverage warnings.

A kernel queue overflow or response write error is a serious enforcement
warning and must be surfaced prominently.

## Tests and rollout

1. Unit test path normalization, mount identity resolution, nested mount
   discovery, deduplication, add and remove reconciliation, and topology
   changes.
2. Test path scope classification when a mount mark observes unrelated paths.
3. Test parallel completion, bounded queues, global and per profile budgets,
   exactly once responses, event FD closure, and response before observation.
4. Test Filemaster core events against the normal in memory core profile,
   including permit, block, Ask, and profile refresh behavior.
5. Test process identity reuse, exec refresh, immutable profile snapshot
   replacement, rule edits with unchanged counts, and default action fast
   paths.
6. Test exact prompt grouping, grouped FD accounting, timeout, overload denial,
   asynchronous Always persistence, and controlled shutdown.
7. Exercise the fake fanotify source through the same ownership and coordinator
   interfaces used by the real source.
8. Re run the root mount benchmark with real cached profile and rule handling,
   cold process resolution, exact prompt grouping, and observation enabled.
9. Enable mount watching through configuration first, inspect metrics and
   desktop behavior, then choose the final defaults.
10. Keep root scope Ask mode behind configuration until overload limits,
    grouping, shutdown handling, and diagnostics have passed end to end tests.
