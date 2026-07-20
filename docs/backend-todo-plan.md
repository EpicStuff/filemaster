# Filemaster Backend Rewrite Plan

## 1. Goals

Filemaster will use the same user facing Read, Write, and Execute rule lists for files and folders. Files and folders may appear together in each ordered list. Rules are checked from highest priority to lowest priority. The first matching rule that applies to the requested operation decides. If no applicable rule matches, the profile default action decides. The current release will expose all three rule lists, but rules that cannot yet be enforced must be clearly shown as inactive.

## 2. User Facing Rule Model

### Current Release

| Rule    | File meaning                                | Folder meaning            |
| ------- | ------------------------------------------- | ------------------------- |
| Access  | Open the file for reading, writing, or both | List folder entries       |
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

## 4. Current Access Behaviour

### File Access

File Access maps to `FAN_OPEN_PERM` because the current backend cannot determine whether the file is being opened for Read, Write, or both.

### Folder Access

Folder Access maps to `FAN_OPEN_PERM` for the folder itself.

It represents opening the folder, not necessarily listing its entries or traversing through it.

### Folder Execute

Folder Execute is exposed in the shared Execute list but has no effect in the current release. It becomes folder traversal when LSM support is added.

## 5. Future Open Freezing

Open freezing remains enabled after LSM support is added. When a program requests an open, Filemaster determines whether the request includes Read, Write, or both. Read and Write are decided separately.

| Read decision | Write decision | Open result    | Later behaviour                 |
| ------------- | -------------- | -------------- | ------------------------------- |
| Allow         | Allow          | Open succeeds  | Read and Write work             |
| Allow         | Deny           | Open succeeds  | Read works and Write is blocked |
| Deny          | Allow          | Open succeeds  | Write works and Read is blocked |
| Deny          | Deny           | Open is denied | Neither works                   |

This allows a program to request both Read and Write while Filemaster grants only one. Open freezing remains the interactive prompt point. Later operations are restricted according to the permissions granted during that decision. Operations that modify data immediately, including Create and Truncate, must pass their Write decision before the modification occurs.

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
- Link Behaviour: Creating a link requires `Source Read and Write AND Destination Create`. If the destination already exists, destination delete is also required.

## 16. Current Release Scope

The current release exposes:

```text
File Access
Folder Access
File Execute
Folder Execute
```

Folder Execute remains visible but inactive. File Write and Folder Write are not exposed because they are not enforced.

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

### Phase 2: Rewrite Current Rules

1. Keep File Access for ordinary file opens.
2. Treat Folder Access as listing entries.
3. Keep File Execute.
4. Expose Folder Execute as inactive.
5. Keep Write hidden until it is enforceable.
6. Clearly report which rules are active.

### Phase 3: Rewrite Rule Evaluation

1. Put file and folder rules in shared ordered lists.
2. Determine rule applicability based on the operation.
3. Make the first applicable matching rule decisive.
4. Use the profile default only when no applicable rule matches.
5. Support Delete decisions.
6. Support Create decisions for nonexistent paths.
7. Support Source Delete and Destination Create or Write for Rename and Move.
8. Treat replacement differently from creation.
9. Preserve rule priority.

### Phase 4: Prepare Future Permissions

1. Preserve Access rules for future migration.
2. Define future Read, Write, and Execute meanings.
3. Prepare for source and destination decisions.
4. Prepare for Create, Delete, Rename, Move, Replacement, Links, Metadata, Truncate, Append, and file mappings.
5. Keep unsupported rules clearly inactive.

### Phase 5: Add Future LSM Enforcement

1. Add separate File Read and File Write enforcement.
2. Add Folder Read and Folder Write enforcement.
3. Activate Folder Execute traversal enforcement.
4. Retain open freezing.
5. Allow an open when at least one requested permission is allowed.
6. Block denied Read or Write operations after open.
7. Enforce Create, Delete, Rename, Move, Replacement, Metadata, Truncate, Append, file mappings, and Links.
8. Use the matching rule or profile default for operations that cannot wait for a prompt.

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
| Folder | List entries                  | Not exposed | Exposed but inactive |

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
| Create link                   | Source File Write and Destination Create                         |
