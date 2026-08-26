# BPF LSM update option — technical proof and implementation note

## Result

The focused proof in `/root/vm/share/fanotify/bpf-lsm-poc` passed on
2026-08-26 against the running Arch guest kernel `7.1.8-arch1-3` on x86-64.
Its active LSM list included `bpf`. It built with Clang 22.1.8, loaded with
libbpf, and used the running kernel's BTF from `/sys/kernel/btf/vmlinux`.

The test attaches exactly four upstream BPF LSM programs:

| Filemaster operation | LSM hook |
| --- | --- |
| Delete file | `inode_unlink` |
| Delete empty folder | `inode_rmdir` |
| Create hard link | `inode_link` |
| Rename | `inode_rename` |

Each hook's BPF program calls the same static policy lookup. For every listed
operation, the proof verified all of the following before observing the
filesystem result:

| Static map state | Result |
| --- | --- |
| Allow | The syscall and its filesystem side effect succeed. |
| Deny | `-EPERM`; no side effect. |
| Ask | `-EPERM`; no prompt and no side effect. |
| No map entry | `-EPERM`; no side effect. |
| Unrepresentable value | `-EPERM`; no side effect. |

The test process is selected by TGID before it is resumed. That is only an
isolation mechanism for the proof; it is not the planned Filemaster process
identity or policy model.

## Lifecycle evidence

1. The object loaded and attached through a libbpf skeleton.
2. The policy hash-map value was updated for every test state.
3. After detaching the links, a selected process with a Deny map entry could
   delete a file. The proof therefore makes no claim of enforcement after
   detachment.
4. A fresh object and fresh map again denied an operation with no entry.
5. After the process exited, `bpftool prog show` and `bpftool link show` had
   no Filemaster proof program or link remaining.

The object-surface check accepts only the four `inode_*` sections above. It
contains no `file_open`, execute, or other program, so it cannot create a
second Open or File Execute decision path.

## Implementation consequences

1. Keep BPF structural enforcement separate from the current fanotify
   `Source` and decision pipeline. It has no event, prompt, or userspace wait;
   it should be a `FileAccess`-owned static structural enforcer with its own
   lifecycle and coverage status.
2. Share the operation enum and static outcome semantics with the Go policy
   compiler, but do not make BPF-map layout part of the product rule format.
   The loader alone translates an already-resolved static snapshot into maps.
3. Use the loader's separate load and attach phases: create/load the object,
   populate and validate the complete policy snapshot, attach every required
   link, then publish the backend as enforced. Do the reverse on planned
   shutdown. Never attach a globally fail-closed program before its intended
   scope and policy are ready.
4. Individual map updates are atomic, but a multi-map policy update is not a
   complete snapshot. Before production, prove one generation-switch design
   (for example an inactive generation plus one active selector) and test that
   a failed or interrupted update cannot expose a partial Allow policy.
5. The TGID gate in the proof is test isolation only. Do not reuse it as
   Filemaster process identity: it does not express profiles and is vulnerable
   to normal PID lifetime/reuse issues. Compile an independently proven process
   identity into the static policy instead.
6. The proof's links disappear when its loader exits. Production must explicitly
   choose and test its daemon-crash behaviour: detach and report no protection,
   or persist a known fail-closed policy/link until the service repairs it. A
   successful object load is not enough to claim protection.

## Hook-context limits to resolve before implementation

The tested hook signatures expose the following kernel objects (plus the LSM
chain's prior return value):

| Hook | Inputs | Consequence |
| --- | --- | --- |
| `inode_unlink`, `inode_rmdir` | Parent inode and target dentry | No mount or complete path is supplied. |
| `inode_link` | Source dentry, destination directory inode, destination dentry | The policy must account for both source and destination. |
| `inode_rename` | Old directory/dentry and new directory/dentry | The policy must account for both ends; the tested hook has no rename-flags argument. |

Consequently, the proof does not provide a safe map key for Filemaster path,
mount, original-path, profile, or hard-link semantics. That is a required P1:
prove the exact identity available at every claimed hook, including bind mounts,
hard links, replacement, and destination-overwrite rename. In particular, do
not promise a distinct `RENAME_EXCHANGE`, whiteout, or flag-specific policy
from this `inode_rename` hook unless a separately proven context source makes
the distinction available.

The first production VM matrix should add rename over an existing destination,
rename flag variants, cross-directory rename, hard-link creation followed by
later access, and the same operations through `*at()` callers. It must also
prove that Open and File Execute still follow fanotify alone while the BPF
links are active.

## Native-LSM reuse

The four proven hook locations and the static outcome matrix are reusable by
[LSM only](update-option-lsm-only.md), but native code does not create missing
path, mount, or rename-flag context. The kernel-policy transport, memory
lifetime, custom-kernel build, and control-plane code are a rewrite. See the
[LSM-only technical note](update-option-lsm-only-technical.md) for the native
implementation and BPF-to-LSM migration boundary.

## Important non-results

1. This is operation-only policy. It does not prove pathname, inode, mount,
   original-path, profile, or application identity for Filemaster rules.
2. `chmod` was intentionally run after reloading the proof and succeeded. It
   is outside the four-hook surface, so the result is a coverage limit rather
   than an Allow decision.
3. The proof does not test Filemaster's running fanotify service, interactive
   prompts, map pinning/replacement across a daemon restart, loader crash
   recovery, or an honest production coverage report.
4. It does not establish coverage for create, mkdir, symlink, metadata,
   truncate, allocation, clone/dedupe, or any other operation not listed in
   the table.

## Consequence

The target kernel can enforce the tested static structural subset using the
existing upstream BPF LSM hooks. That clears the minimal hook-feasibility gate
and supports the scoped four-hook estimate, but it does not justify extending
that estimate or claiming coverage for Filemaster's remaining requirements.
This static-only route can remain the final choice if its proven coverage meets
the chosen product scope; direct-kernel decisioning is a separate later route.
