# Testing

Run Angular and Playwright commands from `desktop/angular`. Run `go` commands
from the repository root unless a command says otherwise.

## Quick Checks

Install dependencies first if needed:

```bash
npm install
npx playwright install chromium
```

List Playwright tests:

```bash
npx playwright test --list
```

## Unit Tests

Karma/Jasmine unit tests in visible Chrome:

```bash
npm test
```

One non-watch unit test run:

```bash
npx ng test --watch=false --browsers=Chrome
```

Coverage:

```bash
npx ng test --code-coverage
```

Current unit coverage: `NotificationsService`, `StatusService`,
`FileAccessDiagnosticsService`, the `FileAccessDiagnosticsComponent`, and a
smoke test for `AppComponent`.

## Playwright

Full browser E2E suite:

```bash
npm run e2e
```

`npm run e2e` runs the Playwright suite.

Playwright directly:

```bash
npm run e2e:playwright
```

Visible browser:

```bash
npm run e2e:playwright:headed
```

Interactive UI:

```bash
npm run e2e:playwright:ui
```

The app-shell test checks that Angular boots and redirects `/` to `/dashboard`.

## File Access E2E

Confined real fanotify mode (default):

```bash
npm run e2e:fileaccess
```

Confined real fanotify with visible browser:

```bash
npm run e2e:fileaccess:headed
```

Explicit alias for the default real-fanotify command:

```bash
npm run e2e:fileaccess:real
```

The default command creates a private mount namespace, bind-mounts its temporary
watch directory, and uses real Linux fanotify. It requires `unshare`, `mount`,
and `fanotify_init` permissions, usually `CAP_SYS_ADMIN` in the initial user
namespace. Use the fake source only for deterministic debugging:

```bash
npm run e2e:fileaccess:fake
```

The file-access test starts a test `filemaster-core` and points Angular at it.
It first allows a command that opens a watched file for writing, then blocks a
different command that opens the same file for reading. The monitor must show
two **Open** rows, one for each command. This verifies open-time decisions; it
does not classify events as separate Read or Write operations.

The prompt exposes only `Allow` and `Block`; both persist a permanent per-app
Open rule (there is no one-time option in the current backend). After the rule is
saved, the next Open lookup refreshes an outdated layered profile and uses the
saved rule without prompting again. File Execute follows the same lookup path.

## Confined fanotify integration harness

`service/fileaccess` has a Go integration test that drives a real
`FAN_CLASS_CONTENT` fanotify group. It is opt in because permission events
deliberately block the file operations that generate them.

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
`/`; this harness is not evidence for whole-system watch scopes.

Within that confined child, the harness verifies a real file Open followed by a
read, plus directory Open/readdir (`FAN_ONDIR`). The permission decision is the
Open; the later read and readdir are application behaviour, not separate Read
operations. It also verifies decision-queue admission, prompt coordinator
ownership transfer and response, descriptor accounting drain, mount mark
removal, fanotify-group closure, and reader exit.
The surrounding focused unit tests cover synthetic malformed batches, queue
saturation, failure retention, nested/bind mount planning, and shutdown failure
paths that cannot be reliably induced from a real kernel group.

The harness skips with a precise reason when any required host primitive is
unavailable: explicit opt-in, effective root plus initial-user-namespace
`CAP_SYS_ADMIN`, `CLONE_NEWNS`, private/bind mounts, `fanotify_init`, or the
required mount mark. A skip is not integration evidence.

Every exit path removes fanotify marks, closes the fanotify group and scope
descriptors, detaches the temporary bind mount, cancels workers, and waits for
the reader to exit. The child process is also isolated from the invoking
process's mount namespace, so cleanup failure cannot leave a host mount marked.

## BPF LSM structural enforcement (VM)

The structural BPF LSM tests need root and a kernel with `bpf` in its LSM
list, so they run in the dev VM (`vmctl`), not on the host. Build the test
binaries on the host with `make bpf`, then `go test -c` for
`./service/fileaccess` and `./service/fileaccess/bpflsm`, and `go build` for
`./cmds/bpflsm-live` and `./cmds/portmaster-core`. Use
`TMPDIR=/root/filemaster/tmp/gotmp`, because the host's `/tmp` is small.

- `bpflsm.test -test.v`: load and verifier counts, lifecycle (handover,
  SIGKILL between bank fill and flip, attach and verifier failures), ring
  overflow, labelling, label wait and its parent-lock stall. Set
  `FM_BPF_SUBVOLUMES=1` for the btrfs loop-device tests.
- `fileaccess.test` with `FM_BPF_DIFFERENTIAL=1`: the generated-rule
  differential. With `FM_BPF_MOUNTS=1`: the mount matrix (ext4, tmpfs, bind,
  private namespace, overlayfs) and the unrepresentable-policy test.
  `FM_BPF_DIFFERENTIAL_ROOT` selects the filesystem the scope lives on.
  `FM_BPF_CONTENTION=1` enables the preemption stress tests.
- `bpflsm-live -core ./filemaster-core -scope <dir>` drives a real daemon
  through the labelling and label-wait matrix. `-m4-only`, `-subvol-only` and
  `-m5-only` select the decision-record, btrfs-subvolume and hardening
  (coexistence, labelling, workflows, pressure) matrices.
- `cmds/bpflsm-live/live-test.sh` (enforce, SIGKILL persistence, restart, off)
  and `cmds/bpflsm-live/flatpak.sh` (Flathub micro's labelling and mkdir
  verdicts) drive the daemon from the shell; set `CORE` to the
  `filemaster-core` binary.

## Legacy Protractor

Legacy Angular E2E target:

```bash
npm run e2e:protractor
```
