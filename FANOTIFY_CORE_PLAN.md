# Fanotify Core Plan

Status: approved redesign plan. The recovered root monitoring and profile driven daemon policy is already implemented. This document covers only the remaining mount mark, concurrency, overload, prompt coordination, cache, persistence, and shutdown redesign while preserving that behavior.

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
* Keep permission enforcement correct while prompts remain pending.
* Bound every queue and every held event file descriptor.
* Group exact duplicate requests from the same profile into one visible prompt.
* Send permission responses before audit, activity, detailed logging, and durable rule persistence work.
* Preserve every implemented baseline behavior listed above.

## Mount mark strategy

The first redesign supports mount marks only. Recursive directory marks are removed rather than retained as a second selectable strategy.

### Mount identity

Mount identity means the mount ID reported by `/proc/self/mountinfo`. Do not deduplicate by device number, filesystem ID, or resolved path alone.

Bind mounts have separate mount IDs. A mark on one bind mount observes accesses through that mount, not accesses through another alias of the same underlying files. Each required bind mount therefore needs its own mark.

### Policy scopes and kernel marks

A configured path is a policy scope, while a mount mark is only the kernel interception scope.

For each configured path:

1. Normalize and validate the configured path.
2. Resolve configured symlinks to a canonical existing directory.
3. Retain the original path for UI display and the canonical path for policy matching.
4. Resolve the containing mount ID from `/proc/self/mountinfo`.
5. Discover separate mounts nested beneath the configured scope.
6. Deduplicate required marks by mount ID.
7. Apply one `FAN_MARK_MOUNT` mark for every required mount.

Calling `fanotify_mark()` with `FAN_MARK_MOUNT` on `/path/to/dir` marks the mount containing that directory. The directory itself does not need to be a mount point.

A mount mark may observe paths outside the configured policy scope. Resolve the event path and compare it against the immutable scope snapshot before process or profile lookup. Immediately allow an event only when its path was resolved successfully and is conclusively outside every configured scope.

Configuring `/` places all descendant paths in scope, including paths on separate nested mounts. Filemaster must therefore mark every applicable current mount in its mount namespace rather than only the root mount.

### Path semantics

Use one normalization and containment implementation for configured scopes, rule matching, prompt keys, audit paths, and event classification.

* Paths must be absolute and cleaned consistently.
* Scope containment must be component aware. `/home/a` must not match `/home/abc`.
* Configured paths must already exist and be directories. Filemaster must not create missing watch paths.
* A configured symlink is resolved at activation. The resolved target is the enforced scope.
* Keep an `O_PATH` descriptor or equivalent stable reference for each active scope root so a rename can be detected and the current canonical path can be refreshed during reconciliation.
* A bind mount alias is covered only when its mount ID and namespace path fall under a configured scope.
* A deleted or unreachable event path is treated as unresolved, even if `/proc/self/fd/<fd>` returns a name ending in ` (deleted)`.
* An event from a marked mount whose path cannot be resolved or normalized defaults to deny and enters a visible degraded state. It must never be silently classified as outside scope.

### Event mask

The mount mark mask includes:

* `FAN_OPEN_PERM`;
* `FAN_OPEN_EXEC_PERM`;
* `FAN_ONDIR` so directory open events are reported;
* `FAN_ACCESS_PERM` only when Intercept Read Syscalls is enabled.

`FAN_EVENT_ON_CHILD` is not used for mount marks because it has no effect on mount marks.

With read interception enabled, `FAN_ACCESS_PERM | FAN_ONDIR` covers directory reads such as `readdir()`. This is required for blocking applications doing their equivalent of `ls`.

### Safe configuration transition

Configuration changes must not create a window where newly marked events are classified against the old scope snapshot.

Use this staged transition:

1. Stop concurrent reconciliation for the affected configuration generation.
2. Publish an immutable union of the old and new policy scopes.
3. Add and verify newly required mount marks.
4. Publish the final new policy scope snapshot.
5. Remove obsolete mount marks.
6. Resume reconciliation using the new generation.

If adding a required mark fails, retain the union snapshot for the affected scope until the failure is resolved or the configuration change is explicitly rolled back. Do not publish a snapshot that claims protection which is not marked, and do not classify a newly marked scope through the old snapshot.

Event mask changes should normally add and remove only the changed mask bits with `FAN_MARK_ADD` and `FAN_MARK_REMOVE`. Do not tear down every mark unless the kernel or a specific transition requires full replacement.

### Mount topology changes

Reconcile the active mount set while Filemaster is running so that:

* a new mount beneath a protected scope receives a mark;
* a detached mount is removed from tracked state;
* a failed mark is retried;
* renamed scope roots are refreshed;
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

## Event ownership and response writing

Replace the synchronous bare event handler contract with an owned pending event abstraction.

```go
type PendingEvent interface {
	Event() *FileEvent
	Respond(Verdict) error
}
```

The concrete implementation must guarantee:

* one current owner;
* exactly one logical verdict;
* explicit ownership transfer from the reader to a worker and then, when needed, to the prompt coordinator;
* resolution on panic, cancellation, overload, timeout, and shutdown paths;
* serialized writes to the fanotify group file descriptor.

The response writer must:

1. Serialize complete `fanotify_response` writes.
2. Retry a write interrupted by `EINTR` without changing the logical verdict.
3. Treat any successful write shorter than the complete response structure as an error rather than assuming the verdict was accepted.
4. Close the event file descriptor only after the complete response has been accepted.
5. Enter a fatal degraded state on an unrecoverable response error.

A fatal response state stops new policy work, surfaces a prominent enforcement warning, and begins controlled draining. The group must not be silently closed because closing it allows unresolved permission events.

## File descriptor accounting and event reads

Every valid event descriptor returned by `read()` consumes Filemaster's `RLIMIT_NOFILE` before path resolution or scope classification.

The global outstanding descriptor count therefore includes every valid event descriptor from the moment it is parsed until its response succeeds and the descriptor is closed, including descriptors for:

* events not yet classified;
* events later found outside policy scope;
* events waiting in the decision queue;
* events being processed by a worker;
* events held by the prompt coordinator;
* events waiting for a response write.

Before each `read()`:

1. Calculate available descriptor headroom from the configured global limit.
2. Do not read when no descriptor headroom remains.
3. Limit the read buffer or batch capacity so one read cannot intentionally request more descriptor carrying events than the available headroom.
4. Reserve enough daemon descriptor headroom for databases, sockets, logs, configuration, scope references, and normal operation.

After each successful `read()`, account for every valid event descriptor immediately before path resolution or any other work.

Handle `EMFILE` explicitly as a serious enforcement and capacity failure. Record diagnostics, stop further reads until headroom is restored, and continue servicing descriptors already received. A successful read may still contain several events, so the complete returned buffer must always be parsed and accounted for.

## Parallel event pipeline

```text
fanotify kernel queue
	↓
single reader with descriptor headroom control
	↓
metadata validation, overflow detection, immediate FD accounting
	↓
path resolution and scope classification
	↓
outside scope: allow immediately
unresolved path: deny and report degraded state
global budget exhausted: deny immediately
	↓
bounded decision queue
	↓
decision worker pool
	↓
rule or profile default: respond immediately
Ask: transfer ownership to prompt coordinator
	↓
complete response accepted and event FD closed
	↓
durable rule persistence when needed
	↓
droppable observation work
```

### Reader responsibilities

The reader performs only work required to route an event safely:

* validate metadata and event length;
* detect `FAN_Q_OVERFLOW` from the event mask before checking the event file descriptor;
* account for every valid event descriptor immediately;
* construct the owned event;
* resolve and normalize the event path;
* classify the path against the policy scope snapshot;
* enforce the global outstanding event budget;
* enqueue an in scope event or send an immediate verdict.

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

Maintain both a global outstanding event descriptor budget and a per profile pending Ask budget.

The usable global limit must not exceed the process soft `RLIMIT_NOFILE` after reserving descriptors for databases, sockets, logs, configuration, scope references, and normal daemon operation.

When the global budget is exhausted, immediately deny newly parsed events whenever a response can still be written safely. When a profile reaches its pending Ask budget, immediately deny additional Ask events for that profile until its count falls below the limit.

Immediate rule and profile default decisions do not consume the per profile Ask budget because they do not remain pending, but their descriptors still count against the global budget until their responses complete.

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
* wait for durable Always rule persistence before answering the current event.

## Prompt coordinator

Prompt presentation is asynchronous, but an enforcing prompt retains its owned events until the user answers, the request times out, overload policy denies it, a profile update resolves it, or controlled shutdown resolves it.

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

### Snapshot revision and reevaluation

Each prompt group records the profile snapshot revision used to create it.

When that profile receives a new snapshot:

1. Reevaluate every pending group for that profile against the new rules and default action.
2. Automatically resolve a group if the new result is allow or deny.
3. Keep the group open only if the new result remains Ask.
4. Update the stored revision after reevaluation.

This applies to UI edits, imports, resets, programmatic changes, and successful in memory Always rule updates.

### Prompt results

* Allow and Deny resolve the current exact group only.
* Allow Always and Deny Always update the in memory profile snapshot and dirty rule overlay first.
* After the snapshot update, reevaluate the current group and every other pending group for that profile.
* Start durable rule persistence only after the current permission events have received their verdicts.
* Prompt timeout defaults to deny.
* Controlled shutdown denies every unresolved prompt group.

## Durable permanent rule persistence

Permanent rule persistence must not share a droppable observation queue.

Use a separate per profile dirty rule mechanism with these properties:

* an in memory overlay immediately represents every accepted Always rule;
* pending writes are serialized per profile;
* persistence retries with bounded backoff;
* failures remain visible until resolved;
* a profile reload merges or reapplies the dirty overlay instead of overwriting it;
* newer profile revisions cannot silently discard an unpersisted rule;
* duplicate pending rules are coalesced safely;
* controlled shutdown attempts a bounded flush but does not delay already required permission responses.

If persistence remains unsuccessful, the active in memory policy stays authoritative for the current run and the UI clearly reports that the change is not yet durable.

## Shutdown and forced termination

### Shared closing state

Controlled shutdown begins by atomically entering one shared closing state observed by the reader, workers, prompt coordinator, configuration callbacks, mount reconciliation, response writer, persistence worker, and observation worker.

After closing begins:

* configuration callbacks and mount reconciliation stop changing scopes or marks;
* no new event enters the decision queue;
* the prompt coordinator denies every new ownership transfer;
* workers that produce Ask after closing transfer directly to a deny response path;
* pending durable rule writes may continue within the shutdown deadline;
* observation work may be discarded.

### Controlled shutdown sequence

1. Enter the shared closing state.
2. Stop configuration callbacks and mount reconciliation.
3. Reject new queue admission and deny new prompt transfers.
4. Remove fanotify marks.
5. Continue reading and servicing events while any mark removal failure means new events may still be generated.
6. Deny queued events that have not begun policy evaluation.
7. Allow active rule or default decisions to finish, but convert every new Ask result to deny.
8. Deny every existing prompt group.
9. Drain response writes and close event descriptors within a bounded deadline.
10. Close the fanotify group only after outstanding event ownership reaches zero or the deadline expires.

A mark removal failure is a serious shutdown warning. The reader must remain active until marks are confirmed removed or the group is deliberately closed. Do not stop the reader while the kernel may still generate permission events.

### Forced termination limitation

Closing the fanotify group allows queued and pending permission events. A process cannot perform cleanup after `SIGKILL`. One userspace process owning the group therefore cannot guarantee fail closed behavior after its own forced termination.

A later hardening phase may introduce a small root owned broker that owns the fanotify group and denies requests while the main service is unavailable. Killing that broker still fails open. Protection against a privileged attacker requires an in kernel policy mechanism such as an LSM.

The initial redesign should still harden the Filemaster service against signals and modification from unprivileged processes and restart it promptly after unexpected exit.

## Observation

Send the fanotify response first. After a successful response write, enqueue audit records, file activity, detailed logs, and metrics.

The observation queue is bounded and may drop records during overload, but it must never delay an allow or deny response. Report observation drops separately from enforcement overload, permanent rule persistence failure, response failure, or kernel queue overflow.

## Configuration and UI

Add backend settings and matching UI controls for:

* decision worker count;
* decision queue capacity;
* global outstanding event budget and descriptor reserve;
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
* read `EMFILE` count and descriptor pressure state;
* decision queue depth and peak depth;
* decision queue saturation deny count;
* configured and active workers;
* decision and response latency;
* current and peak outstanding event descriptors, including unclassified events;
* per profile pending count and overload deny count;
* prompt group count and grouped event count;
* response retry count and unrecoverable response errors;
* unresolved path deny count;
* dirty permanent rule count, retry count, and oldest dirty age;
* observation queue depth and dropped record count;
* configured policy scopes and resolved mount IDs;
* missing required marks and partial coverage state;
* mount reconciliation errors and delayed coverage warnings;
* shutdown mark removal failures.

Kernel queue overflow, `EMFILE`, unresolved paths, unrecoverable response failure, dirty rule persistence failure, and partial coverage are serious enforcement warnings and must be prominent.

## Tests and rollout

1. Preserve and run tests for the implemented `[/home]` default, explicit `/`, root validation, daemon profile seeding, systemd profile seeding, user edit preservation, no global traversal exclusions, and Filemaster self profile synchronization.
2. Exercise the systemd profile on a real systemd host where PID 1 is systemd.
3. Test mount ID parsing from `/proc/self/mountinfo`, nested mount discovery, bind mount identities, deduplication, reconciliation, topology changes, and partial mark failures that retain successful marks.
4. Test the staged scope transition and prove there is no newly marked old snapshot allow window.
5. Test bitwise event mask additions and removals without unnecessary mark teardown.
6. Test component aware path containment, configured symlinks, renamed scopes, bind mount aliases, deleted paths, unresolved paths, and rejection of nonexistent configured directories.
7. Test file open, directory open, file read, directory read, and `readdir()` behavior with `FAN_ONDIR` and optional read interception.
8. Test path scope classification when a mount mark observes unrelated paths.
9. Test kernel overflow detection before event descriptor validation.
10. Test descriptor accounting immediately after read, multi event read batches, descriptor headroom limiting, outside scope descriptor accounting, and explicit `EMFILE` handling.
11. Test one logical verdict, serialized response writes, `EINTR` retry, short write detection, descriptor closure only after success, and fatal degraded response handling.
12. Test parallel completion, bounded queues, global and per profile budgets, ownership transfer, and response before observation.
13. Test Filemaster core allow, block, Ask, profile refresh, and recorded self events through the new pipeline.
14. Test process identity reuse, exec refresh, immutable snapshot replacement, and rule edits that preserve the same rule count.
15. Test exact prompt grouping, grouped event accounting, snapshot revision reevaluation, timeout, overload denial, and profile changes while prompts are open.
16. Test dirty permanent rule overlays, retry, reload merging, revision conflicts, visible failure, and bounded shutdown flush.
17. Test shutdown races involving active workers producing Ask, failed mark removal, continued reader service, and complete ownership draining.
18. Exercise the fake source through the same ownership, response writer, and coordinator interfaces as the real source.
19. Run the existing backend, Playwright, and Karma suites.
20. Run a confined fanotify integration test and a real host systemd safety test.
21. Re run the root benchmark with real profile handling, cold process resolution, exact prompt grouping, descriptor accounting, response writes, durable rule persistence, and observation enabled.
22. Keep root scope Ask mode behind configuration until queue limits, grouping, shutdown, diagnostics, persistence reliability, and real host systemd safety have passed end to end testing.
