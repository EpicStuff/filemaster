# Confined fanotify integration harness

The Linux integration harness uses a real `FAN_CLASS_CONTENT` fanotify group.
It is opt in because permission events deliberately block the file operations
that generate them.

Run it only on a Linux host where the test process has `CAP_SYS_ADMIN` in the
initial user namespace and may create a private mount namespace:

```sh
FM_FANOTIFY_INTEGRATION=1 \
  go test ./service/fileaccess \
  -run '^TestConfinedFanotifyIntegration$' -count=1 -v -timeout=45s
```

The test parent starts the Go test binary in a `CLONE_NEWNS` child. The child
makes its mount tree private, creates one temporary bind mount below `t.TempDir`,
and configures that mount as the only watch scope. It never configures or marks
`/`; root-scope benchmarking still needs the separate explicit acknowledgement
described by `cmds/fanotify-root-bench`.

Within that confined child, the harness verifies a real file open/read,
directory open/readdir (`FAN_ONDIR` with read interception), decision queue
admission, prompt coordinator ownership transfer and response, descriptor
accounting drain, mount mark removal, fanotify-group closure, and reader exit.
The surrounding focused unit tests cover synthetic malformed batches, queue
saturation, failure retention, nested/bind mount planning, and shutdown failure
paths that cannot be reliably induced from a real kernel group.

The harness skips with a precise reason when any required host primitive is
unavailable: explicit opt-in, effective root plus initial-user-namespace
`CAP_SYS_ADMIN`, `CLONE_NEWNS`, private/bind mounts, `fanotify_init`, or the
required mount mark. A skip is not integration evidence. Record a passing run
as trusted rollout evidence before considering the root Ask gate.

Every exit path removes fanotify marks, closes the fanotify group and scope
descriptors, detaches the temporary bind mount, cancels workers, and waits for
the reader to exit. The child process is also isolated from the invoking
process's mount namespace, so cleanup failure cannot leave a host mount marked.
