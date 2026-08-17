# Storage Scope Technical Feasibility

> **Status: unreviewed research note.** This document collects hypotheses and
> constraints for a possible Storage Scope feature. Its conclusions have not
> been accepted as a design or verified as implementation guidance.

This note records technical constraints and proof points for the product
behaviour in [storage-scope.md](storage-scope.md). It does not change that
behaviour.

## Conclusion

Storage Scope is feasible, but it needs an app-specific filesystem view created
before the app starts. A pure Landlock sandbox cannot deliver the feature: it can
allow or deny access, but it cannot make a denied location appear as a private
replacement. Landlock may still be an additional safety layer.

No known Linux limitation makes the feature impossible. The following issues are
release blockers because getting any of them wrong would either let an app reach
the real files or stop ordinary apps from working.

## All-path coverage

The product requirement is that a scoped app's storage access is handled through
its scope regardless of the original path. Covering only the app's home folder
is therefore insufficient: an app could instead use a path under `/tmp`, `/var`,
an attached drive, or another mounted filesystem.

A scoped filesystem view must account for every storage location visible to the
app, including locations that appear after the app starts. A location must never
silently fall back to the real filesystem merely because it was not anticipated.
It must instead be included in the scope or be handled by the profile's ordinary
rules.

Apps also need a stable, read-only view of operating-system files such as their
program, libraries, and standard configuration. Redirecting those files to
private storage would stop normal programs from launching. The boundary between
this shared system view and redirectable storage must be explicit and tested.

## Landlock is not Storage Scope

Landlock is suitable for restricting a sandboxed process to an allowed set of
file hierarchies. It cannot redirect a path to private storage, so it cannot
provide the compatibility behaviour where an app successfully creates a file
after access to the real location was withheld. This is an inference from
Landlock's documented allow/deny rules; it exposes no path-replacement
operation.

Landlock also varies by kernel ABI. Some older ABI versions lack protections
needed for common operations such as cross-directory renames or truncation. It
must not be the only guarantee for Storage Scope unless the required ABI is
available on the user's system.

## Avoid stacked FUSE views

One FUSE filesystem can be mounted inside another, but Storage Scope must not
assume that this is cost-free or automatically safe. If a scoped view forwards
an app's request through a second FUSE view, every operation depends on both
filesystem daemons and can be handled twice. A failure, delay, or deadlock in
either layer breaks the app's access.

The kernel specifically guards FUSE passthrough against filesystem-stack loops
because nested FUSE and overlay configurations can create shutdown or unmount
deadlocks. Storage Scope should therefore use one effective FUSE view for a
scoped app's paths, rather than placing a separate scoped FUSE view on top of a
general Filemaster FUSE view. If Filemaster later uses FUSE for ordinary rules,
the scoped view must replace that view for scoped apps or both behaviours must
be combined into one view.

## Launch boundary

The scoped view must exist before any app code runs. Files, working directories,
or helper processes that exist before the scope is applied can retain access to
the real filesystem. This matches the product rule that enabling Storage Scope
requires a restart.

"Always scoped" also needs to cover every normal way a user starts the app,
including desktop launchers, file associations, and app-created helper
processes. If Filemaster cannot apply the scope, the launch must fail; silently
starting the app normally would violate the feature promise.

## Cross-boundary operations

An app may save through a temporary file and rename it into place, create links,
or move files between a private location and one handled by ordinary rules.
These operations cannot be left undefined. Before release, Filemaster must have
consistent behaviour for create, replace, rename, move, hard links, symbolic
links, and temporary-file saves across that boundary.

## Services outside the scope

Some applications ask another desktop service to access a file on their behalf,
for example through a file chooser, portal, synchronisation client, or another
IPC service. The service is not necessarily in the app's scope. Filemaster must
decide and document whether this is treated as access by the scoped app, access
by the service under its own profile, or an explicit user-granted handoff.

## Private-data containment

The app must not be able to reach its private backing data through a second
path, an inherited file handle, or a separately mounted view of the host.
Private storage is not private if the real backing data remains reachable. This
must be proven against an untrusted app, not only by testing cooperative apps.

## Compatibility and failure behaviour

The scoped view must preserve ordinary application behaviours such as file
locking, atomic saves, metadata changes, links, memory-mapped files, and access
to required runtime sockets. It also needs a defined failure mode: a failure of
the scoped filesystem must fail the scoped app's operation without exposing the
real path or leaving the app permanently hung.

## Release evidence required

Storage Scope should not ship until tests demonstrate all of the following:

1. A scoped app cannot read or write real storage through an alternate absolute
   path, a newly attached mount, a link, or an inherited handle.
2. An app can create, edit, rename, and delete its own private files without
   modifying the user's real files.
3. Excluded files and folders use the profile's ordinary rules and do not gain
   access merely by being excluded from the scope.
4. Normal desktop launching and helper processes remain scoped; a failed scoped
   launch does not fall back to an unscoped launch.
5. Editors, browsers, databases, file managers, and portal/file-chooser flows
   have an observed, documented result.
6. Resetting a scope removes only that profile's private data.

## Sources

* [Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
  describes Landlock as access control based on filesystem rules and documents
  its ABI-dependent limitations.
* [Linux mount namespace documentation](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
  describes the separate mount views used to isolate what processes can see.
* [Linux FUSE passthrough documentation](https://www.kernel.org/doc/html/next/filesystems/fuse/fuse-passthrough.html)
  documents filesystem-stack depth checks and the risk of dependency loops in
  nested FUSE and overlay configurations.
