# LSM-only update option — technical implementation note

## Scope

This note covers the static, existing-upstream-hook native LSM only. It excludes
the targeted VFS changes in the [+ DKMS route](update-option-+dkms.md), and it
does not add an interactive LSM prompt. Fanotify remains the owner of interactive
Open and File Execute decisions.

The first native proof should mirror the four BPF-proven hooks exactly:
`inode_unlink`, `inode_rmdir`, `inode_link`, and `inode_rename`. It should use
the same static outcomes: only Allow proceeds; Deny, Ask, no policy, and an
unrepresentable policy deny without a prompt.

## Native implementation shape

1. Build the Filemaster LSM into the custom kernel, with its own Kconfig,
   Makefile, LSM registration, and an explicit position in the configured LSM
   order. Boot tests must verify both the custom configuration and its presence
   in `/sys/kernel/security/lsm`.
2. Keep each hook non-blocking and static. It may read an already-published
   policy snapshot, but it must not wait for userspace, take a user-controlled
   lock, or perform filesystem/path resolution to manufacture context.
3. Choose a privileged policy-control interface in a small proof before
   building the backend. Generic netlink and securityfs are candidate shapes;
   whichever is chosen must authorize writers, publish immutable snapshots
   safely (normally with RCU-style lifetime), and expose the active generation
   to diagnostics.
4. Reuse Filemaster's product-level operation enum, rule compiler, profile
   resolution, static outcome semantics, health status, and VM test corpus.
   The native kernel policy store and control-plane protocol are not reusable
   from BPF maps.
5. Treat the same hook-context limits as BPF as real LSM-only limits. Native C
   can inspect more kernel data, but the existing `inode_*` hook contract still
   does not itself supply a complete mount/path identity or rename flags. Do
   not claim that native LSM alone solves those gaps.

## BPF LSM to LSM-only migration

Reusable work from a completed BPF backend includes:

1. Static policy semantics and the Go rule/profile compiler above the backend
   adapter.
2. The operation surface, fail-closed test matrix, FileAccess lifecycle/status
   contract, VM fixtures, and fanotify Open/File Execute coexistence tests.
3. The target-kernel hook evidence and negative cases, especially unsupported
   rename variants and unowned operations.

The following is a rewrite rather than a port:

1. BPF C programs, CO-RE object packaging, libbpf loader, map layout, links,
   and BPF-specific health checks.
2. The kernel policy store, safe userspace control path, kernel memory
   lifecycle, LSM registration, and custom-kernel packaging/CI.

Use a rebooted custom-kernel VM for the first cutover. Do not attach native and
BPF enforcement to the same structural operation merely to make the migration
look seamless: a disagreement can produce duplicate decisions or hide a
coverage gap. First compare the two backends in separate runs against one
frozen policy corpus. A live zero-gap hand-off needs its own proof of equivalent
policy generations; otherwise report the maintenance/reboot window honestly.

## Native proof sequence

1. Build and boot the exact custom kernel with a disabled-by-default native
   policy snapshot.
2. Verify the LSM is active, then enable only the four proven hooks with an
   operation-only test policy.
3. Reproduce the BPF Allow/Deny/Ask/missing/unrepresentable matrix and verify
   side effects, link/delete/rename edge cases, restart, and policy replacement.
4. Add the Filemaster policy-control proof: writer authorization, snapshot
   publication, failed update, kernel restart, and degraded-status reporting.
5. Only then attempt the path/mount/original-path identity P1. Escalate to
   LSM + DKMS if the existing hooks cannot supply enough correct context.
