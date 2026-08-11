# Filemaster Backend Rewrite Plan

## 1. Goals

Filemaster will use the same user facing Read, Write, and Execute rule lists for files and folders. Files and folders may appear together in each ordered list. Rules are checked from highest priority to lowest priority. The first matching rule that applies to the requested operation decides. If no applicable rule matches, the profile default action decides. The current release exposes only the rule lists it can enforce: file and folder Access (opens) and file and folder Execute. Folder Execute is shown but inactive. Write is hidden until it becomes enforceable with LSM support. The future full model exposes all three lists (see sections 16 and 17).

## 2. User Facing Rule Model

### Current Release

| Rule    | File meaning                                | Folder meaning            |
| ------- | ------------------------------------------- | ------------------------- |
| Access  | Open the file for reading, writing, or both | Open the folder           |
| Write   | Not exposed                                 | Not exposed               |
| Execute | Launch the file as a program                | Exposed but has no effect |

Folder Execute must remain visible because file and folder rules share the same Execute list.

### Future LSM Release

| Rule    | File meaning                                                                         | Folder meaning                                            |
| ------- | ------------------------------------------------------------------------------------ | --------------------------------------------------------- |
| Read    | Read file contents and metadata                                                      | List entries and read folder metadata                     |
| Write   | Modify contents, append, truncate, rename, delete, replace, link, or change metadata | Create, rename, delete, replace, link, or change metadata |
| Execute | Launch the file as a program                                                         | Traverse the folder                                       |

Metadata reads count as Read. Metadata changes count as Write.

## 3. Rule Matching

First determine which rules apply to the requested operation. Then check those applicable rules in their configured priority order. The first matching applicable rule decides. A file rule does not automatically outrank a folder rule, and a folder rule does not automatically outrank a file rule.

Example:

```text
Deny Write	/folder
Allow Write	/folder/file.txt
```

Writing, appending, truncating, or changing the metadata of `/folder/file.txt` is allowed. The `/folder` rule does not apply because those operations modify the existing file itself rather than the folder entry.

Deleting or renaming `/folder/file.txt` is denied. Those operations modify an entry inside `/folder`, so both rules apply and the folder Deny matches first.

Example:

```text
Allow Write	/folder/file.txt
Deny Write	/folder
```

Deleting or renaming `/folder/file.txt` is allowed because the file Allow is the first applicable matching rule.

A rule for `/folder` controls the folder itself and operations involving its entries. It does not automatically control content changes to existing descendants. A recursive rule such as `/folder/**` may control matching descendants.

### Implementation: separate per-operation lists

The Access, Write, and Execute rules are stored in three separate profile config keys (`fileaccess/readRules`, `fileaccess/writeRules`, `fileaccess/execRules`) and are also kept **separate after parsing**: a `DecisionSnapshot` holds one parsed `PathRules` list per operation plus one shared default action, all published together as one immutable value. Deciding an event determines the operation, selects the matching list via `DecisionSnapshot.rulesFor` (the single routing point; opens fold to the Read list, an unsupported operation fails closed and never borrows another list), then runs the one shared matcher over that list, applying the shared default on no match. Each rule's operation is implied by the list it lives in — it is not encoded in the parsed rule or in the stored string. Rules may be unqualified (matching files and folders), `file:`-qualified, or `folder:`-qualified. Literal paths escape the existing glob metacharacters, such as `+ file:/foo/\*` and `+ folder:/foo/\?`.

**LSM default-action prerequisite.** Current fanotify Access and Execute decisions already use `snapshot.Lookup` and then apply `DecisionSnapshot.DefaultAction`, and constructor-built snapshots currently copy the resolved shared default into each parsed list for the future non-prompt engine. Before Phase 5 wires LSM enforcement, make the no-match invariant structural: every `DecisionSnapshot` decision path, including directly constructed/fallback snapshots, must resolve an unmatched operation from `DecisionSnapshot.DefaultAction` rather than depending on a copied or zero-value `PathRules.Default`. Add explicit tests for unmatched Write/Read/Execute with Block and Ask defaults; non-prompt Ask must fail closed unless that path has an explicit prompt mechanism.

**LSM/source hardening prerequisite — unsupported operations must fail closed end-to-end.** The current `FileOp` routing primitive, profile persistence routing, fallback list selection, and permanent-rule overlay reject unsupported operations. Before adding LSM, another runtime source, or synthetic production events, verify the invariant across the complete decision path for both `FileOp` and `DecisionOp`: an unknown operation must not default to the Access/Read list, reach a prompt that can Allow it, enter an in-memory learned-rule overlay, or create a durable rule. In particular, operation-to-list conversion for logical `DecisionOp` values must distinguish known Access/Read operations from unknown values, and fallback handling must treat an unsupported `FileOp` as a definitive deny rather than ordinary "no matching rule". Add end-to-end tests covering unknown `FileOp` and unknown `DecisionOp` values.

**Development reset requirement.** This refactor removed the internal operation-tagged rule representation and changed the on-disk schema of the fallback per-exe rules file (`persistedFileVersion` 1 → 2, now three lists per exe). A version-1 fallback file is refused rather than silently dropped. Backward compatibility with existing development databases is intentionally not provided: **after pulling this change, delete and recreate the Filemaster/profile database (and any fallback rules file) so special profiles are re-seeded.** The stored per-operation rule strings themselves are unchanged, so profile rule content is not lost by editing, but a clean reset is the supported path and avoids the refused fallback file.

## 4. Current Access Behaviour

### File Access

File Access maps to `FAN_OPEN_PERM` because the current backend cannot determine whether the file is being opened for Read, Write, or both.

`FAN_ACCESS_PERM` and the `InterceptReads` mode are removed. They only fired on reads through an already open descriptor, could not distinguish Read from Write, and added no enforcement that `FAN_OPEN_PERM` does not already provide. Access is decided once at open time.

### Folder Access

Folder Access maps to `FAN_OPEN_PERM` for the folder itself.

It represents opening the folder. `FAN_OPEN_PERM` fires on `open`/`opendir` of the directory; it does not fire on listing entries (`getdents`) or on traversing through the folder to reach a child. Denying it therefore blocks applications that explicitly open the folder, but does not by itself block listing or traversal. Those become enforceable only with LSM support (Folder Read and Folder Execute).

### Folder Execute

Folder Execute is exposed in the shared Execute list but has no effect in the current release. It becomes folder traversal when LSM support is added.

## 5. Future Open Freezing

**Future only.** This entire section describes LSM-era behaviour and does not apply to the current release. Splitting an open into separate Read and Write decisions depends on the LSM `file_open` hook exposing the open flags; fanotify cannot do this, because at `FAN_OPEN_PERM` time the descriptor does not yet exist and its access mode cannot be inspected.

Open freezing remains enabled after LSM support is added. When a program requests an open, Filemaster determines whether the request includes Read, Write, or both. Read and Write are decided separately.

| Read decision | Write decision | Open result    | Later behaviour                 |
| ------------- | -------------- | -------------- | ------------------------------- |
| Allow         | Allow          | Open succeeds  | Read and Write work             |
| Allow         | Deny           | Open succeeds  | Read works and Write is blocked |
| Deny          | Allow          | Open succeeds  | Write works and Read is blocked |
| Deny          | Deny           | Open is denied | Neither works                   |

This allows a program to request both Read and Write while Filemaster grants only one. Open freezing remains the interactive prompt point. Later operations are restricted according to the permissions granted during that decision. Operations that modify data immediately, including Create and Truncate, must pass their Write decision before the modification occurs.

Enforcing a granted subset of permissions after the open is not always clean. Blocking Read while allowing Write (or the reverse) must also cover indirect paths such as `mmap`, and how completely it can be enforced depends on the LSM hooks available. This is a future concern and does not affect the current release.

## 6. Read Behaviour

### File Read

File Read includes reading contents, reading metadata, reading through ordinary file operations, and reading through file mappings.

### Folder Read

Folder Read includes listing entries and reading folder metadata.

## 7. Write Behaviour

### File Write

File Write includes writing contents, appending, truncating, renaming, deleting, replacing, changing metadata, writing through file mappings, serving as the source of a link, and other modifications to the file.

### Folder Write

Folder Write includes creating files, creating subdirectories, creating other filesystem objects, renaming entries, deleting entries, replacing entries, creating links, changing folder metadata, and other modifications to the folder or its entries.

## 8. Execute Behaviour

### File Execute

File Execute means launching the file as a program.

### Folder Execute

Folder Execute means traversing the folder to reach a known child path. It is exposed but inactive in the current release and becomes enforceable with LSM support.

## 9. File Content Modification

> **Future only.** Sections 9 through 15 describe the rule-evaluation semantics for Write, Delete, Create, Rename, Move, Replacement, and Links. The current fanotify backend cannot observe these operations (there are no permission events for write, unlink, rename, or create, and `FAN_MODIFY` is not used), so none of them are enforced or presented as blockable in the current release. They are enforced only with LSM support (Phase 5). The rule-matching logic itself can still be built and unit-tested ahead of enforcement (Phase 3).

Writing, appending, truncating, or changing metadata on an existing file uses the Write rules that apply to that file. A nonrecursive rule for its parent folder does not apply because the folder entry is not being added, removed, renamed, or replaced.

Example:

```text
Deny Write	/folder
Allow Write	/folder/file.txt
```

Writing to `/folder/file.txt` is allowed.

## 10. Delete Behaviour

Deleting a file or folder requires one Write decision for the target operation. Rules for the target object and rules for its containing folder may both apply because deletion removes an entry from the folder. The first applicable matching Write rule decides.

Example:

```text
Deny Write	/folder
Allow Write	/folder/file.txt
```

Deleting `/folder/file.txt` is denied.

Example:

```text
Allow Write	/folder/file.txt
Deny Write	/folder
```

Deleting `/folder/file.txt` is allowed.

Deleting a folder follows the same model.

## 11. Create Behaviour

Creating a new object requires one destination Create decision using the Write rule list. A rule may match the exact destination path even though the object does not yet exist. A rule for the destination folder may also match.

Example:

```text
Allow Write	/destination/new-file.txt
```

This may allow creating `/destination/new-file.txt`.

Example:

```text
Allow Write	/destination
```

This may also allow creating `/destination/new-file.txt`.

The first applicable matching rule decides. If nothing matches, the profile default action decides.

## 12. Rename and Move Behaviour

Rename and Move are treated as two logical operations:

```text
Source Delete
Destination Create or Destination Write
```

Both decisions must allow the operation.

### Source

The existing source path is evaluated as a Delete. Rules for the source object and its containing folder may apply. The first applicable matching Write rule decides.

### Destination Does Not Exist

The destination is evaluated as a Create. An exact rule for the nonexistent destination path or an applicable destination folder rule may decide.

### Destination Already Exists

The destination is evaluated as Write on the existing destination object. A parent folder Allow does not authorize replacing the existing destination. A parent folder Deny may still block replacement if it is the first applicable matching rule.

A Rename or Move therefore requires:

```text
Source Delete is allowed
AND
Destination Create or Destination Write is allowed
```

## Stuff

- Temporary files receive no special treatment. Treat it as any other file
- Link Behaviour:
  - **Hard link**: creating one requires `Source Read and Write and Execute AND Destination Create`. A hard link is a second name for the same inode, so after linking, reading, writing, or executing through either name affects the same underlying file. The source permissions granted to the new name must therefore match the permissions the source already has. If the destination already exists, Destination Delete is also required.
  - **Symbolic link**: creating one requires only `Destination Create`. A symlink is an independent object that merely stores a path; creating it does not grant any access to the target, so no source Read, Write, or Execute decision is needed. Access through the symlink is governed by the rules that apply to the resolved target path at use time. If the destination already exists, Destination Delete is also required.

## 16. Current Release Scope

The current release exposes:

```text
File Access
Folder Access
File Execute
Folder Execute
```

Folder Execute remains visible but inactive.

File Write and Folder Write are not enforced, so the Write rule list is **hidden from the UI** in the current release. It is hidden, not removed: the Write rule storage, config key, and scoping plumbing are retained internally so the future Write evaluation engine (Phase 3) can be built and unit-tested against them before enforcement lands (Phase 5). No runtime write event exists in the current fanotify backend, so nothing populates or consults the Write list at runtime yet.

`FAN_ACCESS_PERM` and its `InterceptReads` toggle are removed outright (see section 4); unlike Write, they carried no future evaluation semantics worth keeping. The test-only fake write event is likewise dropped.

## 17. Future LSM Scope

The future release exposes and enforces:

```text
File Read
File Write
File Execute
Folder Read
Folder Write
Folder Execute
```

It must support separate Read and Write decisions, Read allowed while Write is blocked, Write allowed while Read is blocked, open freezing, folder traversal, Create, Delete, Rename, Move, Replacement, Metadata changes, Truncate, Append, file mappings, and Links.

## 18. Rule Migration

When LSM support is added:

```text
Existing File Access rules
	Copy to File Read and File Write

Existing Folder Access rules
	Convert to Folder Read

Existing File Execute rules
	Remain File Execute

Existing Folder Execute rules
	Remain Folder Execute and become active
```

Rule priority and ordering must be preserved.

## 19. Rewrite Phases

### Phase 1: Remove Dead Runtime Paths — ✅ Done

1. ✅ Delete `FAN_ACCESS_PERM` interception: remove it from the fanotify perm-event mask, remove the `case mask&FAN_ACCESS_PERM` branch in the mask decoder, and remove the `InterceptReads` config option and its diagnostics field. Real fanotify then emits only `OpOpen` and `OpExec`.
2. ✅ Delete the runtime `OpWrite` event, which is only emitted by the test-only fake socket source. No real source produces a write permission event. (Dropped both the fake `write` and `read` socket ops; `opFromString` now yields only `OpExec`/`OpOpen`.)
3. ✅ Leave the Write rule list, its config key, and the rule-scoping plumbing in place (they are hidden and retained per Phase 2, not deleted here). `OpRead`/`OpWrite` `FileOp` constants retained as internal rule-scope identities.

### Phase 2: Rewrite Current Rules — ✅ Done

1. ✅ Keep File Access for ordinary file opens. (`OpOpen` on a file → Access/Read list.)
2. ✅ Treat Folder Access as opening the folder (not listing or traversal). (Inherent: `FAN_OPEN_PERM` + `FAN_ONDIR` fires on `open`/`opendir` only; listing/traversal are not observed.)
3. ✅ Keep File Execute. (`OpExec` via `FAN_OPEN_EXEC_PERM`.)
4. ✅ Expose Folder Execute as inactive. (No source emits exec for a folder, so it is inherently inactive; `CurrentRuleModel` reports it as exposed-but-inactive. The "Execute Rules" UI description now states folder entries are accepted but have no effect in the current release.)
5. ✅ Hide the Write rule list from the UI until Write is enforceable; retain its storage and plumbing internally. (`service/profile/config.go`: Write list registered at `ExpertiseLevelDeveloper` — hidden from normal/expert UI, storage + plumbing intact. Verified by `TestFileAccessWriteRulesHidden`.)
6. ✅ Clearly report which rules are active. (`CurrentRuleModel` in `rule_decision.go`, surfaced as `FileAccessDiagnostics.RuleModel`.)

UI done: the "Read Rules" list is relabelled "Access Rules" (open semantics), the "Execute Rules" description surfaces the inactive Folder Execute state, and Write stays hidden (developer expertise). Verified on the live Settings page (`Access Rules` + `Execute Rules` shown; `Read Rules`/`Write Rules` absent).

### Phase 2.5: Expose Mount Attribution for Dashboard Activity — ✅ Done (core; filter/group-by deferred)

Every persisted File Access and File Execute record must expose the mount that was protected when the decision occurred.

1. ✅ Attribute each Access and Execute permission event to its active protected mount using the source's mount-reconciliation state and event path/file descriptor information. (`fanotifySource.attributeMount` over a lock-free `activeMounts` snapshot published by `publishMountAttributionLocked` at the end of `reconcileLocked`; longest mount point wins for nested/bind mounts.)
2. ✅ Do **not** use `FAN_REPORT_MNT`. (Attribution is derived from the source's own mark/reconciliation state and the resolved event path; `FAN_REPORT_MNT` is not used.)
3. ✅ Persist a stable mount ID and display mount path with each `FileAccessRecord`. (`FileEvent.MountID/MountPath` → `FileAccessRecord.MountID/MountPath`, `sqlite:"mount_id"`/`"mount_path"`.)
4. ⏳ Partial: **schema migration** done (`Database.ensureColumns` idempotently ALTERs missing columns into existing DBs, backfilling old rows to unknown) and mount ID/path are carried in query results (`SELECT *`). **Retention:** restored as per-profile, time-based cleanup of `file_events`; the default is 30 days, `0` retains forever, and cleanup runs hourly after an initial 10-minute delay. **filequery filter/group-by on mount:** deferred — it is self-contained in the query handler, works off the already-persisted columns, and can be added later without rework.
5. ✅ Represent unavailable attribution explicitly as unknown; never infer a mount from an unrelated path after a mount has changed. (Pending reconciliation or no containing mount → `(0, "")`; snapshot is cleared while pending.)
6. ✅ Test nested and bind mounts, dynamically discovered mounts, unmounts, and events received while mount reconciliation is pending. (`mount_attribution_linux_test.go`, `mount_migration_test.go`.)

UI done: the mount is surfaced in the Angular monitor event-details panel (a "Mount" row alongside Executable / PID / Path), verified live showing `Mount: /` for a real `cat` under a protected folder. It is shown in the expandable details rather than as a dedicated always-visible grid column to avoid reworking the row's per-breakpoint `grid-template-columns`; a top-level column remains an optional later change.

Still deferred to a later session: filequery filter + group-by on mount ID/path (self-contained in the query handler, works off the already-persisted columns).

### Phase 3: Rewrite Rule Evaluation — ✅ Done (matching engine + unit tests; enforcement/hardening deferred to Phase 5)

Implemented in `service/fileaccess/rule_decision.go` (engine) and `rule_decision_test.go` (unit tests covering the worked examples in sections 3, 9-12, and Links). Layered additively on the existing `PathRule`/`PathRules` matching so the current runtime open/exec prompt path is untouched; `DecideOperation` is the verdict-or-default engine future non-prompt enforcement will call. Phase 3 marks the rule-applicability and ordering semantics complete; it does **not** mark the Phase 5 LSM default-action and unsupported-operation hardening prerequisites above as complete.

1. ✅ Put file and folder rules in shared ordered lists. (Per-operation lists each mix files and folders; applicability is operation-scoped so within-list order is decisive.)
2. ✅ Determine rule applicability based on the operation. (`ruleAppliesToDecision` + `DecisionOp.scopeOp`/`entryOp`.)
3. ✅ Make the first applicable matching rule decisive.
4. ✅ Define the semantic that the profile default is used only when no applicable rule matches. Constructor-built snapshots currently propagate that default into the operation lists; Phase 5 must make the invariant structural at the `DecisionSnapshot` decision layer for every snapshot construction path.
5. ✅ Support Delete decisions. (`DecisionDelete`; folder rule applies to the entry.)
6. ✅ Support Create decisions for nonexistent paths. (`DecisionCreate`.)
7. ✅ Support Source Delete and Destination Create or Write for Rename and Move. (`DecideRename`.)
8. ✅ Treat replacement differently from creation. (`RenameRequest.DestExists` → Write on existing dest.)
9. ✅ Preserve rule priority. (Engine iterates rules in stored order.)

Items 5 through 8 build the rule-evaluation engine and its unit tests only. Delete, Create, Rename, Move, and Replacement are not observable by the current fanotify backend and are not enforced until Phase 5. The engine is written now so that enforcement can be wired to it later without reworking rule matching. Before that wiring, complete the default-action and unsupported-operation hardening prerequisites documented in section 3 and Phase 5.

### Phase 4: Prepare Future Permissions — ✅ Done (structural prep folded into Phase 3)

1. ✅ Preserve Access rules for future migration. (Rule storage/plumbing retained from Phase 1; `OpRead`/`OpWrite` scope identities kept.)
2. ✅ Define future Read, Write, and Execute meanings. (Documented on the `DecisionOp` constants.)
3. ✅ Prepare for source and destination decisions. (`RenameRequest`, `LinkRequest`, `DecideRename`.)
4. ✅ Prepare for Create, Delete, Rename, Move, Replacement, Links, Metadata, Truncate, Append, and file mappings. (Create/Delete/Rename/Move/Replacement/Links modeled; Metadata/Truncate/Append/mappings are Write-semantic and covered by `DecisionWrite`.)
5. ✅ Keep unsupported rules clearly inactive. (`DecisionOp.RuntimeObservable` marks Access/Execute as the only runtime-active operations.)

### Phase 5: Add Future LSM Enforcement

1. Add separate File Read and File Write enforcement.
2. Add Folder Read and Folder Write enforcement.
3. Activate Folder Execute traversal enforcement.
4. Retain open freezing.
5. Allow an open when at least one requested permission is allowed.
6. Block denied Read or Write operations after open.
7. Enforce Create, Delete, Rename, Move, Replacement, Metadata, Truncate, Append, file mappings, and Links.
8. Use the matching rule or profile default for operations that cannot wait for a prompt.
9. Make no-match handling structurally use `DecisionSnapshot.DefaultAction` for every operation and every snapshot construction path, including fallback/direct snapshots; do not rely on copied or zero-value per-list defaults. Test unmatched Read/Write/Execute under Permit, Block, and Ask.
10. Fail closed on unsupported `FileOp` and `DecisionOp` values end-to-end. Unknown operations must not borrow Access/Read policy, reach an Allow-capable prompt, enter learned-rule overlays, or persist rules. Cover both operation types through complete decision-path tests.

### Phase 6: Migration and Compatibility

1. Copy File Access rules to File Read and File Write.
2. Convert Folder Access rules to Folder Read.
3. Preserve File Execute and Folder Execute rules.
4. Preserve rule order.
5. Test common editors, file managers, package managers, browsers, compilers, and databases.
6. Add compatibility changes only when actual application behaviour justifies them.

## 21. Final Behaviour Summary

### Current

| Object | Access                        | Write       | Execute              |
| ------ | ----------------------------- | ----------- | -------------------- |
| File   | Open for Read, Write, or both | Not exposed | Launch program       |
| Folder | Open the folder               | Not exposed | Exposed but inactive |

### Future

| Object | Read                      | Write                                                                        | Execute        |
| ------ | ------------------------- | ---------------------------------------------------------------------------- | -------------- |
| File   | Contents and metadata     | Modify, rename, delete, replace, truncate, append, link source, and metadata | Launch program |
| Folder | List entries and metadata | Create, rename, delete, replace, link destination, and metadata              | Traverse       |

### Operation Requirements

| Operation                     | Required decisions                                               |
| ----------------------------- | ---------------------------------------------------------------- |
| Modify existing file contents | Target File Write                                                |
| Delete                        | Target File Write or containing folder write                     |
| Create                        | File Write or containing folder write                            |
| Rename                        | Source Delete and Destination Create or Destination Write        |
| Move                          | Source Delete and Destination Create or Destination Write        |
| Replace existing destination  | Source Delete and Existing Destination Write                     |
| Create hard link              | Source File Read, Write, and Execute and Destination Create      |
| Create symbolic link          | Destination Create only                                          |
