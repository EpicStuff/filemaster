# Confined fanotify pipeline verifier

`fanotify-confined-pipeline` is an explicit host-only verifier and benchmark
for the real Filemaster daemon. It creates a temporary source directory and a
separate temporary bind mount, configures Filemaster to watch only that bind
mount, then drives a `systemd-run` helper through the notifications API. It
never marks `/`.

Build the daemon and verifier from the repository root:

```bash
go build -o /tmp/portmaster-core ./cmds/portmaster-core
go build -o /tmp/fanotify-confined-pipeline ./cmds/fanotify-confined-pipeline
```

Run the interactive systemd verification (it chooses a free loopback API
port, writes a private temporary data directory, approves one `Allow always`
prompt, restarts the daemon, and proves the saved rule allows the same helper
without a second prompt):

```bash
sudo /tmp/fanotify-confined-pipeline --core /tmp/portmaster-core --mode verify
```

Run a confined, full daemon pipeline measurement. The result is one JSON
object on stdout; `--json` atomically writes the same object with mode 0600.
The `response_latency` measurement is the helper syscall-to-verdict duration,
so it includes real reader, descriptor, queue, lookup, rule, response, and
post-response observation work.

```bash
sudo /tmp/fanotify-confined-pipeline --core /tmp/portmaster-core \
  --mode benchmark --events 25 --json /tmp/filemaster-confined-benchmark.json
```

The verifier requires PID 1 to be systemd, effective root with
`CAP_SYS_ADMIN`, and the fanotify permissions required by Filemaster. It
stops transient units, unmounts the temporary bind mount, and removes all
temporary files on every exit path. It intentionally does **not** call
`RecordRootAskRolloutEvidence`: root-scope benchmark acknowledgement and the
remaining trusted-evidence review are separate safety requirements.
