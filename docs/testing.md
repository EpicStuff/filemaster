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
Open rule (there is no one-time option in the current backend).

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

## Legacy Protractor

Legacy Angular E2E target:

```bash
npm run e2e:protractor
```
