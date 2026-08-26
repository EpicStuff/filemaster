# Update option: BPF LSM

## Status

This is a useful first backend that may remain the final choice. It is separate from update options. 

## Intended role

BPF LSM is to provide immediate, static Allow/Deny enforcement before they take effect which current fanotify can not do without the need for custom kernel.

Fanotify remains the sole owner of interactive Open and Execute decisions.

## Boundary

This option does not promise Filemaster's full future Read/Write model, descriptor-mode downgrades, or an interactive prompt at an LSM hook. It also does not add hook locations that the upstream kernel does not already expose.
