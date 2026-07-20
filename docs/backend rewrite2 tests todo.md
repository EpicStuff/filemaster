## Behaviour Tests

### Rule Matching

1. First applicable matching rule wins.
2. Rules that match a path but do not apply to the operation are skipped.
3. File rules and folder rules use the same priority order.
4. File rules do not automatically outrank folder rules.
5. Folder rules do not automatically outrank file rules.
6. Profile default is used only when no applicable rule matches.
7. Exact path rules work for existing objects.
8. Exact path rules work for destination paths that do not yet exist.
9. Recursive rules apply only to matching descendants.
10. Nonrecursive folder rules do not control content changes to existing child files.

### File Content Changes

1. File Write Allow permits ordinary writes.
2. File Write Deny blocks ordinary writes.
3. Append follows File Write rules.
4. Truncate follows File Write rules.
5. File metadata changes follow File Write rules.
6. Parent folder Write rules do not affect ordinary writes to an existing child file.
7. Parent folder Write rules do not affect append, truncate, or metadata changes to an existing child file.
8. Recursive folder rules may affect matching child files.

### Current File Access

1. Opening a file for Read triggers File Access.
2. Opening a file for Write triggers File Access.
3. Opening a file for Read and Write triggers one File Access decision.
4. Allow permits the open.
5. Deny blocks the open.
6. Multiple opens are evaluated independently when no persistent rule exists.
7. Always Allow creates the expected rule.
8. Always Deny creates the expected rule.

### Current Folder Access

1. Opening a folder triggers Folder Access.
2. Folder Access controls obtaining a descriptor for the folder.
3. Folder Access does not claim to represent listing.
4. Folder Access does not claim to represent traversal.
5. Denying a folder open blocks applications that explicitly open that folder.
6. Path operations that traverse the folder without opening it are not blocked.
7. Operations using an already open folder descriptor do not require another folder open decision.

### Execute

1. File Execute Allow permits launching the program.
2. File Execute Deny blocks launching the program.
3. Ordinary file open does not count as Execute.
4. Folder Execute rules are visible.
5. Folder Execute rules have no effect in the current release.
6. The interface clearly shows that Folder Execute is inactive.
7. Future Folder Execute controls traversal.

### Delete

1. Deleting a file uses Write rules applicable to the target and containing folder operation.
2. Deleting a folder follows the same rule model.
3. A higher priority folder Deny can block deletion of a child.
4. A higher priority exact file Allow can permit deletion despite a later folder Deny.
5. A folder rule does not block ordinary content writes merely because it can block deletion.
6. Default action is used when no applicable Delete rule matches.
7. Current fanotify operation does not claim to block Delete before LSM support exists.

Example:

```text
Deny Write	/folder
Allow Write	/folder/file.txt
```

Expected results:

```text
Write /folder/file.txt		Allowed
Append /folder/file.txt		Allowed
Truncate /folder/file.txt	Allowed
Delete /folder/file.txt		Denied
Rename /folder/file.txt		Denied
```

### Create

1. Exact Allow for a nonexistent destination permits creation.
2. Exact Deny for a nonexistent destination blocks creation.
3. Destination folder Allow permits creating a new child.
4. Destination folder Deny blocks creating a new child.
5. The first applicable rule wins when both exact destination and folder rules match.
6. Creating a regular file uses Create behaviour.
7. Creating a folder uses Create behaviour.
8. Creating a symbolic link uses Create behaviour.
9. Creating another supported filesystem object uses Create behaviour.
10. Current fanotify operation does not claim to block Create before LSM support exists.

### Rename Within One Folder

1. Rename requires Source Delete and Destination Create when the destination does not exist.
2. Rename requires Source Delete and Destination Write when the destination exists.
3. Both decisions must allow.
4. Source Deny blocks the rename.
5. Destination Deny blocks the rename.
6. Source and destination may be decided by different rules.
7. Renaming only the case of a filename follows the same rules.
8. Renaming a folder follows the same rules as renaming a file.

### Move Between Folders

1. Moving requires Source Delete.
2. Moving to a nonexistent destination requires Destination Create.
3. Moving over an existing destination requires Destination Write.
4. Both source and destination decisions must allow.
5. Source folder rules may decide Source Delete.
6. Exact source rules may decide Source Delete.
7. Destination folder rules may decide Destination Create.
8. Exact destination rules may decide Destination Create.
9. Destination folder Allow does not authorize replacing an existing object.
10. Destination folder Deny may block replacement when it is the first applicable match.

### Replacement

1. Replacing an existing file uses Destination Write, not Destination Create.
2. Replacing an existing folder uses Destination Write.
3. Exact destination Allow permits replacement.
4. Exact destination Deny blocks replacement.
5. Parent folder Allow is ignored as authorization for replacing an existing destination.
6. Parent folder Deny may block replacement.
7. The first applicable destination object protection rule decides.
8. Replacement also requires Source Delete.

Example:

```text
Allow Write	/destination
Deny Write	/destination/existing.txt
```

Expected result:

```text
Create /destination/new.txt		Allowed
Replace /destination/existing.txt	Denied
```

### Temporary Files

1. Temporary files receive no special treatment.
2. Creating a temporary file uses ordinary Create behaviour.
3. Writing a temporary file uses ordinary File Write behaviour.
4. Renaming a temporary file uses ordinary Source Delete and Destination Create or Write behaviour.
5. Temporary naming patterns do not bypass rules.
6. Saving through temporary replacement works when all ordinary decisions allow.
7. Saving fails cleanly when any required decision denies.

### Links

1. Creating a link requires Source Write.
2. Creating a link requires Destination Create.
3. Both decisions must allow.
4. Exact rules may match the future link path.
5. Destination folder rules may authorize new link creation.
6. Replacing an existing destination with a link requires Destination Write.
7. Parent folder Allow does not authorize replacing an existing destination.
8. Hard links and symbolic links are tested separately.

### Metadata

1. Reading file metadata follows Read rules in the future backend.
2. Reading folder metadata follows Read rules.
3. Changing file metadata follows File Write rules.
4. Changing folder metadata follows Folder Write rules.
5. Metadata changes do not accidentally use Read rules.
6. Common metadata checks do not generate misleading content Read events.

### Current Unsupported Behaviour

1. Write rules are not shown before Write enforcement exists.
2. Folder Execute is shown but clearly marked inactive.
3. Delete is not presented as blockable before LSM support.
4. Create is not presented as blockable before LSM support.
5. Rename and Move are not presented as blockable before LSM support.
6. Metadata changes are not presented as blockable before LSM support.
7. Capability and status information matches what the backend actually enforces.

### Future Open Freezing

1. Read only open freezes and prompts for Read.
2. Write only open freezes and prompts for Write.
3. Read and Write open freezes once and shows both requested permissions.
4. Read Allow and Write Allow permits both.
5. Read Allow and Write Deny permits open, allows Read, and blocks Write.
6. Read Deny and Write Allow permits open, blocks Read, and allows Write.
7. Read Deny and Write Deny blocks the open.
8. The selected permissions are installed before the open is released.
9. No write can occur between the open response and enforcement activation.
10. Existing persistent rules avoid unnecessary prompts.

### Future Read Enforcement

1. Ordinary Read follows File Read rules.
2. Folder listing follows Folder Read rules.
3. Metadata reads follow Read rules.
4. Read through an existing descriptor follows the granted Read decision.
5. Read through a descriptor inherited by another process follows the intended process policy.
6. Read through file mappings follows Read rules.
7. Blocking Read does not automatically block Write when Write is allowed.

### Future Write Enforcement

1. Ordinary Write follows File Write rules.
2. Append follows File Write rules.
3. Truncate follows File Write rules.
4. Writable shared mappings follow File Write rules.
5. Metadata changes follow Write rules.
6. Write through an already open descriptor is still blocked when required.
7. Write through an inherited descriptor follows the intended process policy.
8. Blocking Write does not block Read when Read is allowed.
9. Opening with immediate truncation cannot modify the file before Write is approved.
10. Creating during open cannot occur before Destination Create is approved.

### Future Folder Execute

1. Traversing a folder follows Folder Execute rules.
2. Traversal is checked even when the folder is not explicitly opened.
3. Accessing a known child requires traversal through each relevant ancestor.
4. Folder Read Deny with Folder Execute Allow permits known child access without listing.
5. Folder Read Allow with Folder Execute Deny permits listing but blocks reaching children where supported.
6. Folder Execute rules apply to Create, Delete, Rename, Move, metadata access, and ordinary opens that traverse the folder.

### Rule Migration

1. Existing File Access rules copy to File Read and File Write.
2. Existing Folder Access rules convert to Folder Read.
3. File Execute rules remain unchanged.
4. Folder Execute rules remain unchanged and become active.
5. Rule order is preserved.
6. Rule actions are preserved.
7. Recursive and exact path behaviour is preserved.
8. Migration can run more than once without duplicating rules.
9. Profiles with no rules retain their default action.
10. Failed migration does not leave partially converted policy.

### Prompts and Persistent Decisions

1. Allow Once affects only the current request.
2. Deny Once affects only the current request.
3. Always Allow creates the correct rule at the correct priority.
4. Always Deny creates the correct rule at the correct priority.
5. Read and Write choices are persisted independently in the future backend.
6. Source and destination prompts identify the correct path and operation.
7. Replacement prompts distinguish Create from replacing an existing object.
8. Concurrent identical requests are grouped only when safe.
9. Cancelling a prompt produces the configured fallback result.
10. Shutdown releases every frozen operation with the intended safe verdict.

### Application Compatibility

Test at minimum:

1. Text editors that save through temporary files.
2. File managers performing copy, move, rename, delete, and folder creation.
3. Shell commands such as `cat`, `cp`, `mv`, `rm`, `mkdir`, `ln`, and `chmod`.
4. Package managers creating and replacing many files.
5. Compilers reading many inputs and writing many outputs.
6. Browsers using caches and temporary files.
7. Databases using append, truncate, rename, file mappings, and locking.
8. Archive tools extracting and replacing directory trees.
9. Backup and synchronization tools.
10. Applications using folder descriptors and `*at()` style operations.
