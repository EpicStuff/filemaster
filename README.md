# Filemaster

Filemaster is an in-development Linux file-access control project, forked from
[Portmaster](https://github.com/safing/portmaster). It adapts Portmaster's
profile and prompt infrastructure for file access rather than network traffic.

## Current permission model

**Open** is the current permission decision for a file or folder. It is backed
by fanotify `FAN_OPEN_PERM`; Filemaster does not distinguish whether the open
requested reading, writing, or both.

**Read** and **Write** are future permissions requested at open time, including
both permissions for an `O_RDWR` open. They do not refer to fanotify read/write
events, which are not part of Filemaster's design.

## Documentation

- [Build and install](docs/BUILDING.md)
- [Testing](docs/testing.md)
- [Fork history](docs/FORK_NOTES.md)

todo