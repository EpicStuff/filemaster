# Fanotify Core Plan

## Goal

replace dir marking with mount marking

Watch configured filesystem scopes, including `/`, without recursive startup
marking or serially delaying ordinary desktop activity. Filemaster must make
permission decisions in parallel, preserve enforcement for prompted accesses,
and keep logging/audit/UI work off the decision-critical path.

## Current constraints

- A fanotify permission event blocks only its requesting `open()` or `exec()`
  until Filemaster replies `FAN_ALLOW` or `FAN_DENY`.
- Many processes and threads can have events pending concurrently. A browser
  can therefore create many pending events even though each individual thread
  is blocked on one request.
- The host fanotify event queue has a 16,384-event limit per fanotify group.
- The existing source handles events serially and currently logs before it
  replies, so it must be split into reader, decision, reply, and observation
  stages.

## Mark strategy

### Mount marks

Use `FAN_MARK_MOUNT` for each configured distinct mount identity that needs
complete coverage. This applies one mark to the mount and naturally covers
new directories and files without a recursive walk.

Configured paths are resolved to their mount identity and deduplicated. Paths
on the same mount require one kernel mark. Policy scope remains separate from
mark scope: a mount mark may observe more paths than a configured protected
directory, and the in-memory decision path immediately allows paths outside
the protected scope.

### Recursive directory marks

Retain recursive directory marks only for intentionally narrower,
best-effort scopes. They must react to directory create/move-in notifications
and mark only the new subtree. A recursive strategy cannot guarantee perfect
coverage of a newly created deep tree because there is a race before the new
directory becomes marked; use a mount mark where complete coverage matters.

### Configuration changes

Do not re-walk every configured root on every config change. Reconcile the
old and new mount/path sets: add only new marks and remove only obsolete
marks. Dynamic directory creation is handled by filesystem events, not by a
configuration reload.

## Parallel event pipeline

```text
fanotify kernel queue
        ↓
single reader: parse metadata and enqueue only
        ↓
bounded decision-worker pool
        ↓
reply FAN_ALLOW / FAN_DENY immediately
        ↓
asynchronous audit, activity feed, logging, and metrics
```

- Start with four decision workers; expose the count as a backend setting.
  The root-mount benchmark found four workers best for path classification and
  eight best for a nearly empty allow path.
- Use a bounded internal queue, never a goroutine per event.
- Each event FD has one owner and is closed after its verdict is sent.
- The reader performs no profile lookup, prompt work, rule evaluation, or
  per-event logging.
- Track queue overflow, worker utilization, decision latency, and response
  errors. A queue overflow must be visible as a serious enforcement warning.

## Decision path

- Cache process/profile resolution by PID plus a process-start identity to
  prevent PID reuse from returning a stale profile.
- Reuse the profile system's pre-parsed in-memory rule snapshots.
- Rule hits and profile default allow/block decisions reply immediately.
- Do not synchronously persist audit records, write verbose logs, or update
  UI activity before sending the verdict.
- Before adding a new cache utility, inspect upstream Portmaster for an
  existing process/profile cache that can be reused.

## Prompt handling: first phase

Prompt presentation is asynchronous, but an enforcing prompt keeps its
matching permission event pending until the user answers.

- A decision worker registers an unmatched ask event with a prompt coordinator
  and then becomes available for more work.
- The coordinator owns the pending event FD and sends its eventual allow/deny
  reply.
- There is initially no path-scope prompt grouping. Each unmatched event is a
  separate pending decision/request.
- Each app has a large, configurable pending-request budget.
- Once an app reaches that budget, new requests from that app are immediately
  denied. They are not retained or left waiting.
- Expose the current pending count and overload-deny count for each app.
- Prompt timeout and shutdown retain an explicit default verdict, initially
  deny unless policy changes it deliberately.

## Prompt grouping: later phase

Do not implement path grouping in the first pass. The later design should
turn several related pending requests into one user-facing decision such as:

```text
Chrome wants access to ~/.config/google-chrome/
```

The unresolved design task is choosing a safe policy/rule boundary at which
to stop the path. It must avoid both hundreds of per-file prompts and an
over-broad decision that unintentionally grants access to unrelated files.

## Audit and activity recording

Separate decision and observation interfaces. Send the permission verdict
first, then enqueue the `filequery` record, activity update, and detailed log
event. The observation queue may be bounded and may report dropped records;
it must not delay an allow/deny reply.

## Configuration and UI

Backend options will cover at least:

- watched mount/path scopes and mark strategy;
- worker count and internal queue capacity;
- per-app pending-request budget;
- prompt timeout and overload behavior;
- read-syscall interception, disabled by default and especially unsuitable
  for root-wide watching;
- metrics/diagnostic visibility.

Every backend option requires a matching Angular UI control, description, and
safe default. UI implementation is deliberately deferred until the backend
contract is stable.

## Tests and rollout

1. Unit-test mount add/remove/reconciliation and dynamic recursive additions.
2. Test parallel completion of blocked events, FD ownership, queue bounds, and
   response-before-observation ordering.
3. Test profile-cache correctness, PID reuse, rule/default fast paths, prompt
   timeout, per-app overload denial, and shutdown behavior.
4. Exercise the fake fanotify source end-to-end.
5. Re-run the root-mount benchmark with real profile/rule/cache handling, then
   with real pending prompt coordination.
6. Enable root/mount watching through config first, inspect metrics and
   desktop behavior, then choose the final default.
