# Root fanotify benchmark

This is a temporary, force-allow benchmark for measuring the lowest practical
overhead of a `FAN_MARK_MOUNT` mark on `/`. It is not Filemaster product code:
it has no profile lookup, rules, prompts, persistence, or per-event logging.

Build it from the repository root:

```bash
go build -o /tmp/fanotify-root-bench-bin ./cmds/fanotify-root-bench
```

Run a baseline without fanotify, then a watched run. The benchmark requires
root and automatically removes its mount mark when the command ends or times
out.

```bash
/tmp/fanotify-root-bench-bin --mode baseline -- go build ./cmds/portmaster-core
/tmp/fanotify-root-bench-bin --mode raw --workers 8 --timeout 5m -- go build ./cmds/portmaster-core
/tmp/fanotify-root-bench-bin --mode classified --workers 4 --scope /root/filemaster --timeout 5m -- go build ./cmds/portmaster-core
```

`raw` reads each permission event and immediately allows it. `classified` also
resolves the event path and performs an in-memory prefix check before allowing.
Use the built-in controlled stress workload to compare worker counts:

```bash
/tmp/fanotify-root-bench-bin --mode raw --workers 8 -- /tmp/fanotify-root-bench-bin storm --workers 24 --iterations 200
```

The command emits one JSON result with workload time, direct-child CPU time,
event count/rate, worker utilization, response-latency buckets, and failures.
An overflow, timeout, or response error gives the command a non-zero exit code.
