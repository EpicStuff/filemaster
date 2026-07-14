# UI gaps after the file-access conversion

Static audit of UI HTTP calls against the daemon that remains after the
network-stack strip. The file-access monitor and app activity views now use
`filequery`; the outstanding gaps are predominantly legacy dashboard widgets.

## HTTP calls to deleted endpoints

| UI call | Caller | Status |
| --- | --- | --- |
| `GET /v1/intel/geoip/countries` | `country-name.pipe.ts` constructor | **Fixed**: HTTP call removed; map stays empty (pipe returns raw code). Was the only init-fired call that toasted. |
| `POST /v1/spn/account/login` | Former SPN page | **Removed from the rendered application**: the SPN sidebar feature is no longer declared or shown. |
| `DELETE /v1/spn/account/logout` | Former SPN settings drilldown | **Removed from the rendered application** with the SPN sidebar feature. |
| `GET /v1/spn/account/user/profile` | Legacy dashboard/components | Legacy subscription remains; feature flags stay `false`. No visible SPN navigation remains. |
| `POST /v1/spn/reinit` | Former menu item | Menu item removed. |
| `POST /v1/netquery/query` | Legacy connection-oriented components | Monitor and app **File Events** no longer call this endpoint; remaining legacy consumers render empty. |
| `POST /v1/netquery/query/batch` | Dashboard "Recent Activity" | Dashboard numbers remain zero. File Access Activity uses `/v1/filequery/query/batch` instead. |
| `POST /v1/netquery/history/clear` | (was "Cleanup Network History" menu) | Menu item removed. |
| `POST /v1/netquery/charts/bandwidth` | `netquery.service.ts:bandwidthChart` | Dashboard line chart stays empty. |
| `POST /v1/netquery/charts/connection-active` | `netquery.service.ts:activeConnectionChart` | Dashboard active-connection chart stays empty. |
| `POST /v1/dns/clear` | (was "Clear DNS Cache" menu) | Menu item removed. |
| `GET /v1/debug/network` | (was network-debug pane) | Pane removed; method exists in service but unreferenced. |
| `POST /v1/control/pause` | navigation pause menu items | Menu items removed. |
| `POST /v1/control/resume` | navigation pause menu items | Menu items removed. |

## What the user actually sees on first page load

After `c1cfa304` (the country-pipe fix), no error toasts fire on a plain
dashboard load. Legacy widgets that depended on the dropped backends show
empty data:

- "Recent Activity" tile: all zeros
- "Recent Connection Countries" / "Recent Bandwidth Usage" / "Active vs
  Blocked Connections": empty charts, "Available in Portmaster Plus"
  labels for the paid-feature gates
- "Recently Blocked Applications": empty list ("No applications have
  been blocked in the last 10 minutes")
- "News" widget: empty body (intel/news 404)
- Welcome modal: still pops the first time, dismissible

Functional surfaces:

- Sidebar prompt-tray: lights up yellow on a real fileaccess prompt
  (verified live -- the original screenshot diff)
- App overview list: shows the auto-created profiles from the profile
  DB
- Monitor: **File Access Activity** uses the shared filequery viewer with
  Portmaster-style search, filters, grouping, sorting, a file-access graph,
  and the file event table.
- App detail → **File Events**: reuses that same viewer, scoped to the selected
  app, including its graph.
- App settings → File Access Rules: renders via the generic rule-list
  editor (allow `+`, deny `-`)
- Settings page: File Access is organized as **File Access**, **Rules**, then
  **Other**; **Intercept Read Syscalls** is in Other, after File Access Rules.
- Support page: external (GitHub issues) -- still works

## What's intentionally kept but non-functional

These legacy network-oriented surfaces still render but their data backends
are gone:

- Dashboard connection, bandwidth, country, and blocked-application widgets
  still use netquery and therefore show empty data.
- Per-app **Insights** remains network-era scaffolding.
- `app-qs-internet` / `app-qs-history` header tiles → toggles map to
  removed config keys; clicks no-op.

## What an end-to-end "this works" test looks like today

1. Daemon up with `core/devMode=true` + a `fileaccess/watchPaths`
   entry.
2. `ng serve` on :4200, browser at `http://<host>:4200/`.
3. Dismiss the welcome modal.
4. `cat <watched-path>/some-file` in a shell → prompt-tray icon turns
   yellow within ~1s.
5. Click the prompt-tray icon → dropdown shows the prompt card with
   Path: + Op: rows.
6. Click "Allow once" → `cat` unblocks and prints the file content.
7. Click "Always deny this path" on a second access → a new entry
   appears in the profile's `fileaccess/rules` (visible in the App
   Settings tab). Next access of the same path skips the prompt and
   returns EPERM directly.
8. Visit `/monitor` → File Access Activity shows the event in the shared
   viewer and its graph. Open that app and select **File Events** → the same
   activity is shown, scoped to that app.

The dashboard network widgets remain dead-but-render. SPN is no longer part of
the rendered sidebar application.
