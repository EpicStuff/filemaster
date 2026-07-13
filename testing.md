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

Current unit coverage is mostly `NotificationsService`, plus smoke tests for
`AppComponent` and `StatusService`.

## Playwright

All Playwright tests:

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
tries a watched-file write like `echo test > <file>`, clicks `Allow once`,
checks the file, tries a read like `cat <file>`, clicks `Deny once`, checks the
read is blocked, then opens `/monitor` and checks the read/write activity is
shown in the app.

The prompt and allow/block parts currently run. The `/monitor` assertion exposes
the missing file-access activity UI until that page is implemented.

## Legacy Protractor

Legacy Angular E2E target:

```bash
npm run e2e
```
