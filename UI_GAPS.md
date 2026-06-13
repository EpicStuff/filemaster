# UI gaps after the network-stack strip

Static audit of every UI HTTP call vs. what the daemon still implements.
The Angular tree was kept largely intact (only routes / nav items /
declarations stripped); the underlying services still try to talk to
endpoints whose backend code we deleted. This file is the punch list.

## HTTP calls to deleted endpoints

| UI call | Caller | Status |
| --- | --- | --- |
| `GET /v1/intel/geoip/countries` | `country-name.pipe.ts` constructor | **Fixed**: HTTP call removed; map stays empty (pipe returns raw code). Was the only init-fired call that toasted. |
| `POST /v1/spn/account/login` | `spn-login.ts` (button) | Dead button; toast only on click. SPN section unreachable from nav. |
| `DELETE /v1/spn/account/logout` | `spn-account-details.ts` (button) | Dead button; dialog only reachable from settings drilldown that itself doesn't render. |
| `GET /v1/spn/account/user/profile` | `SPNService.profile$` (subscribed by dashboard + several components) | Silent failure; `profile$` errors, downstream `featureBw` / `featureSPN` stay `false`. No toast (no error handler). |
| `POST /v1/spn/reinit` | `portapi.service.ts:reinitSPN` (was menu item) | Menu item already removed. |
| `POST /v1/netquery/query` | `netquery.service.ts:query` | Multiple consumers; all silent. Widgets render empty. |
| `POST /v1/netquery/query/batch` | `netquery.service.ts:batch` | Dashboard "Recent Activity" → numbers stay 0. |
| `POST /v1/netquery/history/clear` | (was "Cleanup Network History" menu) | Menu item removed. |
| `POST /v1/netquery/charts/bandwidth` | `netquery.service.ts:bandwidthChart` | Dashboard line chart stays empty. |
| `POST /v1/netquery/charts/connection-active` | `netquery.service.ts:activeConnectionChart` | Dashboard active-connection chart stays empty. |
| `POST /v1/dns/clear` | (was "Clear DNS Cache" menu) | Menu item removed. |
| `GET /v1/debug/network` | (was network-debug pane) | Pane removed; method exists in service but unreferenced. |
| `POST /v1/control/pause` | navigation pause menu items | Menu items removed. |
| `POST /v1/control/resume` | navigation pause menu items | Menu items removed. |

## What the user actually sees on first page load

After `c1cfa304` (the country-pipe fix), no error toasts fire on a
plain dashboard load. Widgets that depended on the dropped backends
show empty data:

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
- App settings → File Access Rules: renders via the generic rule-list
  editor (allow `+`, deny `-`)
- Settings page: shows the registered options (DefaultAction,
  watchPaths, interceptReads, etc.)
- Support page: external (GitHub issues) -- still works

## What's intentionally kept but non-functional

We left these as scaffolding so future file-access-activity work can
slot in without re-adding the templates. They currently render but
their data backends are gone:

- `/monitor` route + "Network Activity" sidebar button → renders
  netquery viewer, which 404s. No data, no toast.
- Per-app "Connections" tab → same.
- Per-app "Insights" tab → same.
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

Everything else (the network widgets, the SPN page if you find it
through deep linking, etc.) is dead-but-renders.
