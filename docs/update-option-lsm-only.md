# Update option: LSM only

## Status

LSM only is a native, Filemaster-specific LSM built into a custom kernel. It
uses existing upstream LSM hooks only. It is distinct from othe update options.

## Intended role

This route provides static Allow/Deny enforcement at existing LSM hooks. It may cover more naturally in native kernel code than BPF LSM, but it does not add or move VFS hook locations.

Fanotify remains responsible for the current interactive Open and Execute prompts. LSM only does not claim an interactive userspace prompt for any LSM hook.

## Boundary

LSM only implements only the static subset of desiered features that existing hooks can correctly enforce. It does not promise descriptor-mode downgrade, `O_TRUNC` cancellation, new event context, or an interactive wait where the existing hook is unsafe.
