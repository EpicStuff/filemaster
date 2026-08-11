# Future LSM Backend Test Plan

This document covers behavior that remains unimplemented until the LSM backend
lands (Phases 5 and 6 in `backend-todo-plan.md`). It intentionally excludes the
current fanotify Access/Execute behavior and the completed Phase 3/4
rule-evaluation engine tests.

## Future Open Freezing

1. Read-only open freezes and prompts for Read.
2. Write-only open freezes and prompts for Write.
3. Read-and-Write open freezes once and shows both requested permissions.
4. Read Allow and Write Allow permits both.
5. Read Allow and Write Deny permits the open, allows Read, and blocks Write.
6. Read Deny and Write Allow permits the open, blocks Read, and allows Write.
7. Read Deny and Write Deny blocks the open.
8. The selected permissions are installed before the open is released.
9. No write can occur between the open response and enforcement activation.
10. Existing persistent rules avoid unnecessary prompts.

## Future Read Enforcement

1. Ordinary Read follows File Read rules.
2. Folder listing follows Folder Read rules.
3. Metadata reads follow Read rules.
4. Read through an existing descriptor follows the granted Read decision.
5. Read through a descriptor inherited by another process follows the intended process policy.
6. Read through file mappings follows Read rules.
7. Blocking Read does not automatically block Write when Write is allowed.

## Future Write Enforcement

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

## Future Mutation Enforcement

### Delete

1. Deleting a file uses Write rules applicable to the target and containing-folder operation.
2. Deleting a folder follows the same rule model.
3. A higher-priority folder Deny can block deletion of a child.
4. A higher-priority exact file Allow can permit deletion despite a later folder Deny.
5. A folder rule does not block ordinary content writes merely because it can block deletion.
6. The profile default is used when no applicable Delete rule matches.

### Create

1. Exact Allow for a nonexistent destination permits creation.
2. Exact Deny for a nonexistent destination blocks creation.
3. Destination-folder Allow permits creating a new child.
4. Destination-folder Deny blocks creating a new child.
5. The first applicable rule wins when both exact destination and folder rules match.
6. Creating regular files, folders, symbolic links, and other supported objects uses Create behavior.

### Rename, Move, and Replacement

1. Rename or move requires Source Delete and Destination Create when the destination does not exist.
2. Rename or move requires Source Delete and Destination Write when the destination exists.
3. Both decisions must allow.
4. Source and destination may be decided by different rules.
5. Source folder and exact source rules can decide Source Delete.
6. Destination folder and exact destination rules can decide Destination Create.
7. Destination-folder Allow does not authorize replacing an existing object.
8. Destination-folder Deny may block replacement when it is the first applicable match.
9. Renaming only the case of a filename follows the same rules.
10. Renaming a folder follows the same rules as renaming a file.

### Temporary Files and Links

1. Temporary files receive no special treatment: creation, writes, and renames use their ordinary decisions.
2. Temporary naming patterns do not bypass rules.
3. Saving through temporary replacement works when all ordinary decisions allow and fails cleanly when one denies.
4. Creating a hard link requires Source Read, Write, and Execute plus Destination Create.
5. Creating a symbolic link requires only Destination Create.
6. Exact rules may match a future link path.
7. Destination-folder rules may authorize new link creation.
8. Replacing an existing destination with a link requires Destination Write.
9. Hard links and symbolic links are tested separately.

## Future Folder Execute

1. Traversing a folder follows Folder Execute rules.
2. Traversal is checked even when the folder is not explicitly opened.
3. Accessing a known child requires traversal through each relevant ancestor.
4. Folder Read Deny with Folder Execute Allow permits known-child access without listing.
5. Folder Read Allow with Folder Execute Deny permits listing but blocks reaching children where supported.
6. Folder Execute rules apply to Create, Delete, Rename, Move, metadata access, and ordinary opens that traverse the folder.

## Rule Migration

1. Existing File Access rules copy to File Read and File Write.
2. Existing Folder Access rules convert to Folder Read.
3. File Execute rules remain unchanged.
4. Folder Execute rules remain unchanged and become active.
5. Rule order, actions, and recursive/exact behavior are preserved.
6. Migration can run more than once without duplicating rules.
7. Profiles with no rules retain their default action.
8. Failed migration does not leave partially converted policy.

## Prompts and Persistent Decisions

1. Read and Write choices are persisted independently.
2. Source and destination prompts identify the correct path and operation.
3. Replacement prompts distinguish Create from replacing an existing object.
4. Concurrent identical requests are grouped only when safe.
5. Cancelling a prompt produces the configured fallback result.
6. Shutdown releases every frozen operation with the intended safe verdict.

## Application Compatibility

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
