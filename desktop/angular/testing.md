# Testing

This Angular workspace currently uses two browser test layers:

- Karma/Jasmine for focused Angular unit and service tests.
- Playwright for full browser end-to-end tests against the served app.

## Karma/Jasmine

Run the existing unit tests with:

```bash
npm test
```

Karma is configured to run the specs in visible Chrome. It is useful for Angular
services, components, dependency injection, templates, and browser APIs that can
be tested without driving the full app like a user.

Current meaningful coverage is concentrated in
`src/app/services/notifications.service.spec.ts`. It covers:

- querying notifications through the mocked Portmaster API websocket
- executing notification actions by notification object
- rejecting unknown notification actions
- executing notification actions by notification key
- resolving pending notification actions by object
- rejecting already executed notifications
- resolving pending notification actions by key
- emitting new/action-required notifications from the `new$` stream
- creating notifications from an object
- creating notifications from parameters

The file-access enforcement diagnostics also have dedicated specs:

- `src/app/services/fileaccess-diagnostics.service.spec.ts` covers the
  `FileAccessDiagnosticsService` (the `fileaccess/diagnostics` endpoint client).
- `src/app/pages/settings/fileaccess-diagnostics.component.spec.ts` covers the
  `FileAccessDiagnosticsComponent` (the enforcement status panel).

There are also smoke tests for:

- `AppComponent` creation and its `title` value
- `StatusService` creation through Angular dependency injection

The configured Karma targets under `projects/` are present, but there are no
substantial specs there at the moment.

## Playwright

Run the full browser E2E suite with:

```bash
npm run e2e
```

`npm run e2e` runs the Playwright suite.

Run Playwright directly with:

```bash
npm run e2e:playwright
```

Run the same tests in a visible browser with:

```bash
npm run e2e:playwright:headed
```

Open Playwright's interactive test UI with:

```bash
npm run e2e:playwright:ui
```

Playwright is configured in `playwright.config.ts`. It starts the Angular dev
server with `npm run serve`, waits for `http://localhost:4200`, and runs tests
with Chromium.

The first Playwright test is `playwright/app-shell.spec.ts`. It covers the
minimum full-app browser boot path:

- opens `/` in Chromium
- verifies the document title contains `Portmaster`
- verifies the Angular root element `app-root` is attached
- verifies the router redirects to `/dashboard`

This test intentionally avoids backend-dependent dashboard data. It proves that
the built Angular app serves, boots, mounts the root component, and reaches the
default route in a real browser. Add deeper Playwright tests for user flows,
navigation, settings screens, onboarding, and backend/proxy behavior.

## File Access E2E

Run the fake fanotify file-access test with:

```bash
npm run e2e:fileaccess
```

Run the same test in a visible browser with:

```bash
npm run e2e:fileaccess:headed
```

Run against real Linux fanotify with:

```bash
npm run e2e:fileaccess:real
```

Real mode requires an environment where `fanotify_init` works, usually
`CAP_SYS_ADMIN` in the init user namespace.

The file-access test starts a test `portmaster-core`, points Angular at it,
tries a watched-file write like `echo test > <file>`, clicks `Allow`, checks the
file was written, and confirms a second write is auto-allowed by the persisted
per-app rule. It then tries a read like `cat <file>`, clicks `Block`, checks the
read is denied, then opens `/monitor` and confirms the write and read activity
rows are shown (and reachable from the per-app "File Events" tab).

The prompt exposes only `Allow` and `Block`; both persist a permanent per-app
File Access rule (there is no one-time option in the current backend).

## Legacy Protractor

The old Angular Protractor target is still available for legacy checks:

```bash
npm run e2e:protractor
```
