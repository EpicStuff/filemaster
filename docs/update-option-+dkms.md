# Update option: BPF then DKMS and LSM + DKMS

This is a upgrade to the (BPF) LSM option.

## Meaning of `+ DKMS`

`+ DKMS` means a later **targeted-kernel change**, delivered either by directly building a custom kernel or, if proven suitable for the exact target, by `klp-build`/livepatch. The delivery method is deliberately unsettled.

Fanotify remains responsible for the current interactive Open and File Execute path.

## Selected LSM + DKMS architecture

VFS -> LSM -> filemaster -> decision

## Both routes end at the same backend

BPF cannot pause a program and wait for an answer. It can report, it cannot ask. That means there is no BPF version of the `+ DKMS` backend. Whichever first stage is chosen, the second stage is the same LSM + DKMS.

## What each first stage costs

| First stage | Survives into `+ DKMS` |
|---|---|
| LSM only | ~65–75% |
| BPF LSM | ~45–50% |

What a route costs in total against building `+ DKMS` directly. Going via BPF adds roughly a **10–20% premium**
