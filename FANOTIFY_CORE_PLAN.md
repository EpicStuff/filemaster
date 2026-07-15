# Fanotify Core Plan

Status: approved redesign plan. The recovered root monitoring and profile driven daemon policy is already implemented. This document covers only the remaining mount mark, concurrency, overload, prompt coordination, cache, and shutdown redesign while preserving that behavior.

## Implemented baseline to preserve

The following behavior already exists and is not new implementation work:

* `fileaccess/watchPaths` defaults to `[/home]`.
* Users may explicitly configure `/` for whole system monitoring.
* The watch path validator accepts `/`.
* There are no global traversal exclusions for `/run`, `/dev`, `/proc`, `/sys`, or similar paths. With `/` configured, accesses there use normal profile, prompt, verdict, and audit behavior.
* Filemaster core uses the normal Filemaster special profile rules, rule precedence, default action, prompting, verdict, and recording semantics.
* Filemaster core policy is hydrated before fanotify starts and kept in a synchronized in memory snapshot. Deciding a Filemaster event does not perform normal process lookup or read profile storage.
* The Filemaster daemon profile is seeded with default allow and editable rules derived from its executable and runtime paths.
* User changes to seeded special profiles are preserved during reloads and upgrades.
* The Filemaster daemon profile is available through the existing profile system.
* The systemd special profile and helper matching are seeded with editable allow rules without changing the profile default action.
* Existing system resolver special profile behavior remains intact.
* Recursive traversal retains successfully installed marks when another subtree cannot be marked and emits compact partial coverage warnings.
* The real profile stack previously ran with `/` for ten seconds without a global allow or Filemaster self deadlock.

The systemd profile implementation exists, but host safety has not yet been exercised on a system where PID 1 is systemd. That remains required verification rather than implementation work.

## Redesign goals

* Replace recursive directory marking with mount marking.
* Avoid recursive startup traversal and repeated directory walks on configuration changes.
* Process independent permission events concurrently without creating one goroutine per event.
* Keep permission enforcement correct when prompts remain pending.
* Bound every queue and every held event file descriptor.
* Group exact duplicate requests from the same profile into one visible prompt.
* Send permission responses before audit, activity, detailed logging, and persistence work.
* Preserve every implemented baseline behavior listed above.

## Mount mark strategy

The first redesign supports mount marks only. Recursive directory marks are removed rather than retained as a second selectable strategy.

### Policy scopes and kernel marks

A configured path is a policy scope, while a mount mark is only the kernel interception scope.

For each configured path:

1. Normalize and retain the path in an immutable policy scope snapshot.
2. Resolve the mount containing the path.
3. Discover separate mounts nested beneath the configured scope.
4. Deduplicate required marks by mount identity.
5. Apply one `FAN_MARK_MOUNT` mark for every required mount.

Calling `fanotify_mark()` with `FAN_MARK_MOUNT` on `/path/to/dir` marks the mount containing that directory. The directory itself does not need to be a mount point.

A mount mark may observe paths outside the configured policy scope. Resolve the event path and compare it against the immutable scope snapshot before process or profile lookup. Immediately allow events outside every configured scope.

Configuring `/` places all descendant paths in scope, including paths on separate nested mounts. Filemaster must therefore mark every applicable current mount in its mount namespace rather than only the root mount.

### Mount topology changes

Reconcile the active mount set while Filemaster is running so that:

* a new mount beneath a protected scope receives a mark;
* a detached mount is removed from tracked state;
* a failed mark is retried;
* coverage delay and reconciliation errors are visible in diagnostics.

A bounded periodic reconciliation is acceptable for the first implementation. A topology event watcher may replace it later.

### Partial coverage

Failure to install one required mount mark must not remove marks that were installed successfully.

Filemaster must:

* retain successful marks;
* report one compact warning identifying failed mount scopes;
* expose missing marks and partial coverage through diagnostics;
* retry failed marks during reconciliation;
* never report complete coverage while a required mark is missing.

### Configuration changes

Do not walk directory trees after a configuration change. Reconcile the old and new immutable scope and mount sets:

* add newly required marks;
* remove obsolete marks;
* retain unchanged marks;
* replace the policy scope snapshot atomically after reconciliation.

Changing the event mask, such as enabling read interception, may require replacing existing marks.

## Event ownership

Replace the synchronous bare event handler contract with an owned pending event abstraction.

```go
type PendingEvent interface {
	Event() *FileEvent
	Respond(Verdict) error
}
```

The concrete implementation must guarantee:

* one current owner;
* no more than one response attempt;
* event file descriptor closure after the response attempt;
* explicit ownership transfer from the reader to a worker and then, when needed, to the prompt coordinator;
* resolution on panic, cancellation, overload, timeout, and shutdown paths;
* serialized writes to the fanotify group file descriptor.

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
bounded decision queue
	↓
decision worker pool
	↓
rule or profile default: respond immediately
Ask: transfer ownership to prompt coordinator
	↓
response written and event file descriptor closed
	↓
asynchronous observation and persistence
```

### Reader responsibilities

The reader performs only work required to route an event safely:

* validate metadata and event length;
* detect `FAN_Q_OVERFLOW` from the event mask before checking the event file descriptor;
* construct the owned event;
* resolve the event path;
* classify the path against the policy scope snapshot;
* enforce the global outstanding event budget;
* enqueue an in scope event or send an immediate overload verdict.

The reader does not perform general process lookup, profile lookup, rule parsing, prompting, persistence, activity recording, or verbose event logging.

### Path resolution recursion

Preserve the existing live result that Filemaster self policy works without a global self allow. Add a focused integration test confirming that resolving `/proc/self/fd/<event fd>` does not create a nested permission event.

If path resolution does recurse on a supported system, add only the smallest unconfigurable metadata resolution guard needed to obtain the path. It must not change Filemaster profile policy, suppress the final audit record, exempt unrelated Filemaster accesses, or create broad path exclusions.

### Decision workers

* Start with four workers and expose the count as a backend setting.
* Use one bounded queue.
* Never create one goroutine per event.
* Immediately deny a new in scope event when the decision queue is full.
* Reply immediately for rule hits and profile default allow or block decisions.
* Transfer Ask events to the prompt coordinator and return the worker to the pool.
* Route Filemaster core events through its existing in memory profile snapshot while applying the same policy semantics as any other profile.

Four workers is an initial value only. Rebenchmark using real process resolution, profile snapshots, rules, prompts, response writes, and observation work.

## Outstanding event limits

Maintain both a global outstanding event budget and a per profile pending Ask budget.

The global count includes every in scope event file descriptor held by Filemaster while it is:

* waiting in the decision queue;
* being processed by a worker;
* held by the prompt coordinator;
* waiting for its response write to finish.

The usable global limit must not exceed the process soft `RLIMIT_NOFILE` after reserving file descriptors for databases, sockets, logs, configuration, and normal daemon operation.

When the global budget is exhausted, immediately deny new in scope events. When a profile reaches its pending Ask budget, immediately deny additional Ask events for that profile until its count falls below the limit.

Immediate rule and profile default decisions do not consume the per profile Ask budget because they do not remain pending.

## Process and profile caches

### Process resolution

Reuse Portmaster's existing process store and PID plus process creation identity. Do not add a second general PID cache.

After an allowed `FAN_OPEN_EXEC_PERM`, invalidate or refresh the corresponding process mapping because `exec` can replace the executable while preserving the PID and process creation identity.

### Immutable profile snapshots

Extend the existing Filemaster self snapshot approach into immutable file access decision snapshots for loaded profiles. Each snapshot contains at least:

```go
type DecisionSnapshot struct {
	ProfileID	string
	Source		string
	DefaultAction	uint8
	Rules		PathRules
	Revision	uint64
}
```

A profile mutation parses rules once, creates a new snapshot, and atomically replaces the old snapshot. Decision workers only read snapshots.

Remove the current cache behavior that treats rules as unchanged when only their count is unchanged. Editing a rule without changing the number of rules must replace the parsed snapshot.

Do not retain a profile owned raw rule slice after releasing the profile lock. Copy it while locked or consume an already immutable representation.

The decision path must not synchronously:

* read the profile database;
* parse raw profile rules;
* persist audit records;
* write verbose logs;
* update UI activity;
* persist an Always rule before answering the current event.

## Prompt coordinator

Prompt presentation is asynchronous, but an enforcing prompt retains its owned events until the user answers, the request times out, overload policy denies it, or controlled shutdown resolves it.

### Exact duplicate grouping

The first implementation groups requests by:

```text
profile source and profile ID
operation
normalized exact path
```

One visible prompt owns one or more pending events. Its response resolves all events currently in that exact group.

Every grouped event still counts against the global and per profile budgets. When either budget is exhausted, deny additional matching events instead of adding them to the group.

Requests without a resolved profile use an unidentified bucket that includes stable process identity so unrelated unidentified programs are not grouped together.

Broader parent directory grouping remains a later design task.

### Prompt results

* Allow and Deny resolve the current exact group only.
* Allow Always and Deny Always update the in memory profile snapshot first.
* After the snapshot update, resolve the current group and other exact pending groups matched by the new rule.
* Persist the new rule asynchronously after responding.
* Surface persistence failure visibly. The current in memory decision remains valid until restart.
* Prompt timeout defaults to deny.
* Controlled shutdown denies every unresolved prompt group.

## Shutdown and forced termination

### Controlled shutdown

1. Remove fanotify marks so no new events are generated.
2. Stop admitting work to the decision queue.
3. Deny queued events that have not begun policy evaluation.
4. Deny every pending prompt group.
5. Wait for active decisions and response writes within a bounded shutdown deadline.
6. Close the fanotify group only after outstanding event ownership reaches zero or the deadline expires.

### Forced termination limitation

Closing the fanotify group allows queued and pending permission events. A process cannot perform cleanup after `SIGKILL`. One userspace process owning the group therefore cannot guarantee fail closed behavior after its own forced termination.

A later hardening phase may introduce a small root owned broker that owns the fanotify group and denies requests while the main service is unavailable. Killing that broker still fails open. Protection against a privileged attacker requires an in kernel policy mechanism such as an LSM.

The initial redesign should still harden the Filemaster service against signals and modification from unprivileged processes and restart it promptly after unexpected exit.

## Observation and persistence

Send the fanotify response first. After a successful response write, enqueue audit records, file activity, detailed logs, metrics, and deferred rule persistence.

The observation queue is bounded and may drop records during overload, but it must never delay an allow or deny response. Report observation drops separately from enforcement overload or kernel queue overflow.

## Configuration and UI

Add backend settings and matching UI controls for:

* decision worker count;
* decision queue capacity;
* global outstanding event budget and file descriptor reserve;
* per profile pending Ask budget;
* prompt timeout;
* overload verdict, initially deny;
* mount reconciliation interval and status;
* metrics and diagnostics.

Keep the existing protected path setting, `[/home]` default, explicit `/` support, read interception setting, and root risk documentation.

There is no mark strategy selector because the redesign supports mount marks only.

## Required metrics and warnings

Expose at least:

* kernel queue overflow count;
* decision queue depth and peak depth;
* decision queue saturation deny count;
* configured and active workers;
* decision and response latency;
* current and peak outstanding event file descriptors;
* per profile pending count and overload deny count;
* prompt group count and grouped event count;
* response write errors;
* observation queue depth and dropped record count;
* configured policy scopes and resolved mount identities;
* missing required marks and partial coverage state;
* mount reconciliation errors and delayed coverage warnings.

Kernel queue overflow, response write failure, and partial coverage are serious enforcement warnings and must be prominent.

## Tests and rollout

1. Preserve and run tests for the implemented `[/home]` default, explicit `/`, root validation, daemon profile seeding, systemd profile seeding, user edit preservation, no global traversal exclusions, and Filemaster self profile synchronization.
2. Exercise the systemd profile on a real systemd host where PID 1 is systemd.
3. Test mount identity resolution, nested mount discovery, deduplication, reconciliation, topology changes, and partial mark failures that retain successful marks.
4. Test path scope classification when a mount mark observes unrelated paths.
5. Test kernel overflow detection before event file descriptor validation.
6. Test parallel completion, bounded queues, global and per profile budgets, exactly once responses, event file descriptor closure, and response before observation.
7. Test Filemaster core allow, block, Ask, profile refresh, and recorded self events through the new pipeline.
8. Test process identity reuse, exec refresh, immutable snapshot replacement, and rule edits that preserve the same rule count.
9. Test exact prompt grouping, grouped event accounting, timeout, overload denial, asynchronous Always persistence, and controlled shutdown.
10. Exercise the fake source through the same ownership and coordinator interfaces as the real source.
11. Run the existing backend, Playwright, and Karma suites.
12. Run a confined fanotify integration test and a real host systemd safety test.
13. Re run the root benchmark with real profile handling, cold process resolution, exact prompt grouping, response writes, and observation enabled.
14. Keep root scope Ask mode behind configuration until queue limits, grouping, shutdown, diagnostics, and real host systemd safety have passed end to end testing.
