# Update option: BPF then DKMS and LSM + DKMS

This is a upgrade to the (BPF) LSM option.

## Meaning of `+ DKMS`

`+ DKMS` means a later **targeted-kernel change**, delivered either by directly building a custom kernel or, if proven suitable for the exact target, by `klp-build`/livepatch. The delivery method is deliberately unsettled.

Fanotify remains responsible for the current interactive Open and File Execute path.

## Selected LSM + DKMS architecture

VFS -> LSM -> filemaster -> decision

## Both routes end at the same backend

BPF on a stock kernel cannot ask. A custom kernel *could* hand BPF a native wait to call. But that is a custom kernel, which is the `+ DKMS` stage, and the wait still has to happen at a new, later point in the operation, because at the normal checkpoint the kernel is holding the directory and the answer could take minutes. So there is no stock-kernel BPF version of the `+ DKMS` backend, and the parts that make it work are the same parts either way.

Whichever first stage is chosen, the second stage needs the same kernel changes.

Whether the Filemaster side of those changes is written as a native kernel module or kept in BPF is still open, and is being decided by testing rather than argument. It does not change the cost either way.

## What each first stage costs

| First stage | Survives into `+ DKMS` |
|---|---|
| LSM only | ~65–75% |
| BPF LSM | ~45–50% |

What a route costs in total against building `+ DKMS` directly. Going via BPF adds roughly a **10–20% premium**
