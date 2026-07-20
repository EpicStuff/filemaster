# Testing

Run commands from `desktop/angular`.

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

Fake fanotify mode:

```bash
npm run e2e:fileaccess
```

Fake fanotify with visible browser:

```bash
npm run e2e:fileaccess:headed
```

Real Linux fanotify mode:

```bash
npm run e2e:fileaccess:real
```

Real mode requires an environment where `fanotify_init` works, usually
`CAP_SYS_ADMIN` in the init user namespace.

The file-access test starts a test `portmaster-core`, points Angular at it,
tries a watched-file write like `echo test > <file>`, clicks `Allow`, checks the
file was written, and confirms a second write is auto-allowed by the persisted
per-app rule. It then tries a read like `cat <file>`, clicks `Block`, checks the
read is denied, and finally opens `/monitor` and confirms the write and read
activity rows are shown (and reachable from the per-app "File Events" tab).

The prompt exposes only `Allow` and `Block`; both persist a permanent per-app
File Access rule (there is no one-time option in the current backend).

## Legacy Protractor

Legacy Angular E2E target:

```bash
npm run e2e:protractor
```
