# Backend Test Requirements

> **Status: unreviewed acceptance checklist.** These requirements apply when
> evaluating BPF LSM, LSM only, DKMS only, LSM + DKMS, "BPF then DKMS", FUSE,
> or a second fanotify group. They do not select an architecture or claim that any
> candidate already satisfies them.

## Shared requirements

1. Verify the current Open and File Execute behaviour remains correct
   while the candidate backend is enabled or disabled.
2. When a candidate supports separate Read and Write permissions, test open
   requests for read-only, write-only, and read/write access. These are
   open-time permissions, not fanotify read/write events.
3. Exercise ordered file and folder rules, profile defaults, permanent choices,
   prompt cancellation, concurrent requests, daemon restart, and shutdown.
4. Treat unsupported or ambiguous operations as unsupported; they must not
   silently borrow another operation's policy, create an Allow-capable prompt,
   or persist a rule.
5. Verify that a decision applies to the object and operation presented to the
   user. A pathname alone is not sufficient where the operation can race a
   rename, replacement, link, or mount change.
6. Simulate listener loss, worker exhaustion, queue overflow, malformed input,
   cancellation, and interrupted waits. The resulting behaviour must be
   explicit and must never claim enforcement that is no longer active.
7. Test common applications and workflows: text-editor saves through temporary
   files, file-manager copy/move/rename/delete, shell tools, compilers,
   browsers, databases, archive tools, backups, synchronisation, and `*at()`
   operations.
8. Run adversarial tests for bypasses and races, not only successful prompt
   round trips.

The development data is disposable. A backend change may replace the rule
format directly; it does not require migration or compatibility tests for old
local databases unless compatibility is later made a product requirement.

## FUSE-specific requirements

1. Prove that an application cannot reach a backing path, inherited descriptor,
   mount namespace, or alternate mount that bypasses the FUSE view.
2. Test each operation the filesystem actually mediates, including open,
   directory access, create, delete, rename, links, metadata changes, truncate,
   allocation, clone/copy, mappings, and interruption.
3. Define and test the semantics of an `O_RDWR` open. Do not claim separate
   Read/Write open permissions unless the implemented FUSE design can enforce
   them.
4. Test cancellation and `FUSE_INTERRUPT` handling so frozen requests cannot
   wedge an application or prevent clean shutdown.
5. Test cache, passthrough, mmap, and already-open-descriptor behaviour against
   the exact enforcement and revocation claims made by the implementation.

## BPF-LSM-specific requirements

1. Prove the exact LSM hooks used for every claimed structural operation and
   verify that a BPF deny stops the operation before it takes effect.
2. Verify that fanotify remains the only Open and Execute decision path. The
   initial BPF route must not attach an Open hook or create a second decision
   for either operation.
3. For every BPF-owned operation, test Allow, Deny, Ask, no matching static
   policy, unsupported operation, and unrepresentable policy. Only Allow may
   permit the operation; every other case denies without prompting.
4. Test program loading, map installation, map replacement, detachment, daemon
   restart, and loader failure. The service must report precisely which static
   operations are no longer protected and must not claim coverage it lacks.

## LSM-only-specific requirements

1. Verify that the native LSM is built into and active on the exact custom
   kernel under test, and that every claimed operation uses an existing upstream
   LSM hook.
2. Treat LSM only as static enforcement. It must not claim an interactive
   userspace prompt at an LSM hook; existing fanotify remains responsible for
   current interactive Open and Execute decisions.
3. Test the static Allow/Deny and unsupported-policy behavior for every claimed
   hook, including kernel restart and policy replacement.
4. Prove the kernel evaluates nothing: every outcome it produces must be one the
   daemon published, and no kernel path may derive an outcome for an object the
   daemon did not decide.
5. Test the marked-directory walk: nearest-ancestor selection, nested marks, an
   unmarked tree, a mark removed mid-walk, a concurrent ancestor rename, a
   disconnected dentry, and both views of a bind mount. Record the bind-mount
   collision as a limitation rather than treating it as a defect.
6. Prove both endpoints of every rename are checked, and that a
   `RENAME_EXCHANGE` swapping a protected object with an unprotected one is
   denied while the flags remain invisible at the hook.
7. Prove the uninitialised, active, and failed table states are distinguishable
   at runtime, that an uninitialised table never enforces, and that a failed
   publication is reported rather than silently reached.
8. Prove kernel threads produce no decision and that a single delete on an
   overlayfs mount yields exactly one Filemaster decision.

## DKMS-only-specific requirements

1. Test every claimed interception point on the supported stock kernels and
   verify capabilities at module load and daemon startup. A successful DKMS
   build alone is not evidence of coverage.
2. Prove that interactive waits do not hold VFS, inode, directory, or rename
   locks. Revalidate object and operation identity before committing an approved
   operation where necessary.
3. Test self-recursion, overlay and stacked filesystems, io_uring, module
   unload, daemon crash, kernel update, Secure Boot/signing, and conflicts with
   tracing or live-patching facilities.
4. Run destructive and adversarial tests in a disposable virtual machine, with
   an automated reset path.

## BPF then DKMS-specific requirements

Formerly "BPF LSM + DKMS". Stage two replaces the BPF backend rather than
extending it, and stage two is the LSM + DKMS backend; see
[BPF then DKMS](update-option-bpf-dkms-technical.md).

1. Meet the BPF-LSM-specific requirements for the stock-kernel stage, and meet
   the LSM + DKMS-specific requirements in full for the kernel-change stage.
   Coming from BPF reduces none of them.
2. Verify exact stock/interactive capability reporting. A kernel without the
   interactive path must report rules requiring it as unsupported or fail
   closed; it must not silently fall back to a BPF Allow.
3. Prove that a structural operation owned by the kernel path has Filemaster as
   its only decision owner: no BPF structural hook remains attached for that
   operation, no duplicate prompt or unprotected hand-off occurs, and no stale
   BPF policy can permit it. Prove the same in reverse after a deliberate
   return to the stock BPF stage.
4. Prove no BPF program mediates any part of an interactive decision. There
   must be no BPF map consulted for a verdict, no BPF-side verdict storage, and
   no kfunc or task-local-storage bridge added to keep BPF in the path.
5. Test the two backends separately, against one frozen policy corpus, not
   concurrently on the same operation. A live zero-gap hand-off, if attempted,
   needs its own proof of equivalent policy generations.
6. Run the stock/custom differential, lifecycle, destructive, and adversarial
   test matrix in a disposable virtual machine with an automated reset path.

## LSM + DKMS-specific requirements

1. Meet the LSM-only requirements for the interim native-LSM phase and the
   applicable DKMS-only requirements for every added kernel component.
2. Test every claimed interception point on the exact direct-kernel build, and
   test the interim native LSM independently on the exact LSM-only build. For
   livepatch delivery, test every supported target kernel with its livepatch
   capability checks; for direct delivery, test the compiled custom-kernel
   build.
3. Verify the selected ownership model: the existing `path_*` hook returns an
   internal sentinel, VFS unwinds through its existing error paths and calls
   the new generic security hook with nothing held, and the Filemaster LSM owns
   the request, wait, verdict cache, and enforcement. Rules are evaluated only
   in the daemon; prove the LSM implements no second matcher, and that VFS
   implements no Filemaster policy or permission transport.
4. Prove the internal sentinel can never be returned to userspace, on every
   path through both patched functions.
5. Prove exactly one Filemaster decision per syscall and that at most one
   ask-retry occurs, with no livelock when the second pass still has no
   matching cached verdict. The same hook adapter serves both passes; other
   LSMs' ordinary later checks must still execute on the second pass.
6. Test LSM stacking against a real SELinux or AppArmor configuration, with
   Filemaster ordered last. Record the audit/AVC duplication caused by the
   two-pass sequence and confirm no check is skipped on the committing pass.
7. For every claimed Ask wait, prove with instrumentation and concurrent
   unrelated work that no lock, mount-write reference, or path/dentry/inode
   reference from the first pass spans the wait. Include `fsfreeze` and
   cross-directory renames on the same superblock during a live prompt. A fatal
   signal must cancel the request safely; daemon absence, receiver loss, queue
   exhaustion, malformed replies, and answer-generation mismatch must fail
   closed.
8. After every Ask Allow, prove the second pass re-resolves and re-locks
   normally and that the cached verdict is enforced only when operation,
   parent, name, target identity, mount, and generation all still match.
   Include stale, replacement, and two-side rename races, and daemon restart
   mid-wait.
9. Measure the cost of the doubled resolution under `rm -rf` and a large
   `git checkout`, with and without kernel-side scope marks.
10. Run destructive and adversarial tests in a disposable virtual machine, with
    an automated reset path.

## Second-fanotify-group requirements

1. Test rename and hard-link correlation using stable file identity, not only
   paths or process IDs.
2. Test event ordering against a blocked permission event, notification loss,
   queue overflow, unsupported FID reporting, mount changes, and correlation
   failure. Any uncertainty must not weaken existing protection.
3. Demonstrate the exact protection retained after an untrusted move to a less
   restricted path, and the exact conditions under which a permitted move
   changes that result. Cover at least: an unpermitted move records the origin
   path; a second unpermitted move keeps the first origin; a mover permitted to
   Open both ends clears the override; and a two-step launder — one unpermitted
   move followed by a move that is permitted only at the literal destination
   path — does not clear it.
4. Test moved folders, not only moved files. A descendant opened after its
   parent folder was moved must resolve to the parent's recorded origin, and the
   ancestor lookup this requires must be measured on the blocking open path.
5. Verify the startup capability probe: an unsupported filesystem or kernel in a
   watch scope must fail module startup with the responsible mount named, with
   no degraded mode.
6. Keep kernel-level namespace races explicit in the results. The test suite
   must not describe tracking as atomic prevention if the kernel does not offer
   that guarantee.
7. Do not add fanotify read/write classification. A second notification group
   addresses namespace tracking; it does not split an Open decision into
   Filemaster Read and Write permissions.
