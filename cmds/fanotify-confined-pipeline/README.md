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
`decision_latency` is measured in the daemon from creation of the owned kernel
permission event through acceptance of its response. `response_latency` starts
immediately before the reusable helper opens the probe and ends when that open
returns. Both exclude `systemd-run` service startup; the verifier rejects a
sample if another response races it, rather than reporting ambiguous latency.

The JSON contract includes event/verdict and prompt counts, queue/descriptor
denials and peaks, response/ownership/persistence status, decision and response
latency summaries, `shutdown_duration_ms`, kernel/container metadata, and
`effective_fileaccess_settings`. The settings are read from the daemon
diagnostics and include watched paths, read interception, effective worker,
queue, outstanding-event, and per-profile Ask limits, plus requested and
effective Root Ask gate state.

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

## Root scope status

Root scope testing is explicitly deferred from Phase 8. Do not invoke
`--root-scope` as part of Phase 8 verification, and do not treat a confined
result as root-scope evidence. The guarded root mode and Root Ask gate remain
for a future dedicated verification effort, but Root Ask stays closed until
that effort records valid backend-only evidence.
