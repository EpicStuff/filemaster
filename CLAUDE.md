# filemaster — project coding instructions

## What this project is

filemaster is a fork of [Portmaster](https://github.com/safing/portmaster) that replaces
network-connection prompts/monitoring with file-access prompts/monitoring using fanotify.
The network stack (`service/network`, `service/netquery`, `service/firewall`, etc.) was
deleted; see `FORK_NOTES.md` for the full deletion log.

## Reuse upstream Portmaster code

Before writing a new utility, search the upstream Portmaster codebase (git remote
`upstream`, branch `main`) to see if it already exists.

```bash
git fetch upstream main --depth=1
git show FETCH_HEAD:path/to/file.go
git ls-tree FETCH_HEAD --name-only some/package/
```

Reuse by copying the upstream file and making the minimal required changes
(package name, import paths, field renames). Leave the ported logic intact —
don't refactor it.

## Keep ported and custom code in separate files

When a package contains both upstream-ported code and filemaster-specific code,
split them into separate files:

| File | Rule |
|------|------|
| Ported verbatim or near-verbatim from upstream | No special prefix; add a comment at the top: `// Ported from service/netquery/foo.go — <summary of changes>.` |
| filemaster-specific (new logic, schema, wiring) | Also no prefix, but clearly different in content |

`service/filequery/` is the canonical example:
- `orm/` — 4 files copied verbatim from `service/netquery/orm/`
- `query_request.go`, `query_handler.go`, `database.go` — near-verbatim ports
- `record.go`, `manager.go`, `module.go` — filemaster-specific

Never mix ported logic and new logic in the same function. If a ported function
needs one filemaster-specific line, add it at the boundary (before or after the
ported block) with a comment, rather than interspersing it throughout.

## Commit and push autonomy

Feel free to commit at every coherent stopping point — no need to ask. Push
immediately after every commit. Do not batch commits waiting for permission to
push.

## Test before every commit

Compiling clean is not testing. Every behavioral change must be exercised and
observed before committing. Do not skip this.

### Backend / daemon changes

The fake socket source is faithful to the real kernel source: the event
carries only `pid`, `path`, and `op` — **no `exe`**. The profile is resolved
from `/proc/<pid>/exe`, exactly as in production. This means you must send a
**real, live PID**: spawn an actual process, send its PID, then kill it. A
made-up PID (e.g. 9001) will not resolve to any profile — the same failure
mode you'd get in production for a dead process.

```bash
# Build and start fresh with the fake socket source:
go build -o /tmp/portmaster-core ./cmds/portmaster-core/
pkill -f portmaster-core 2>/dev/null; sleep 1
FM_FAKE_SOCKET=/tmp/fm-fake.sock /tmp/portmaster-core \
  --data-dir /tmp/fm-test --devmode --log info &
sleep 2   # wait for socket to appear

# Spawn real, long-lived processes and inject THEIR pids (empty exe, like
# the kernel). Keep them alive until the daemon has read /proc, then kill.
sleep 300 & SLEEP_PID=$!
tail -f /dev/null & TAIL_PID=$!
sleep 0.3
echo "{\"pid\":$SLEEP_PID,\"path\":\"/tmp/secret.txt\",\"op\":\"write\"}" \
  | ./fake-fanotify -socket /tmp/fm-fake.sock
echo "{\"pid\":$TAIL_PID,\"path\":\"/etc/passwd\",\"op\":\"read\"}" \
  | ./fake-fanotify -socket /tmp/fm-fake.sock
# (each blocks ~30s on the prompt timeout since no UI answers it)
kill $SLEEP_PID $TAIL_PID 2>/dev/null

# Verify events were recorded:
curl -s http://127.0.0.1:818/api/v1/filequery/query \
  -X POST -H 'Content-Type: application/json' -d '{"pageSize":5}'
# Expected: each result has a real profile like "local/PTVMx..." (source
# prefixed exactly ONCE — not "local/local/...") and app_name "Sleep"/"Tail".
# A profile of "/" means the PID did not resolve (dead process or fake PID).
```

### UI changes (Angular)

Screenshots must be saved to `./tmp/` (repo root, gitignored). Always use the
Read tool to open each screenshot and look at it — do not assume it looks right.

```bash
# After injecting events (above), sweep all main pages:
node desktop/angular/screenshot.mjs http://localhost:4200/dashboard  ./tmp/dashboard.png
node desktop/angular/screenshot.mjs http://localhost:4200/monitor    ./tmp/monitor.png
node desktop/angular/screenshot.mjs http://localhost:4200/settings   ./tmp/settings.png
```

**What to verify in each screenshot:**

- **Sidebar** (visible in every page): must show the real resolved app names
  (e.g. "Sleep", "Tail" for the injections above) — NOT "Other Access" only.
  If events exist but all land in "Other Access"/"/", profile resolution from
  the PID is broken (or you injected a fake/dead PID).
- **Monitor page**: shows "File Access Activity" with the filequery-viewer
  (search bar, filter chips, event table). No "Network Activity", no
  "Loading connections…", no "Loading Chart".
- **No stuck spinners**: any persistent "Loading…" means silent API failure —
  check network tab in devtools or daemon logs for 403s.
- **Important**: Also make sure to check the bug you are fixing or the feature
  you are implementing is actually working/fixed.

### Always run the Playwright tests

```bash
cd desktop/angular
npx playwright test                  # both app-shell and file-access suites
npx ng test --watch=false            # Karma unit tests (uses ChromeHeadlessNoSandbox)
```

Both must pass before committing. The file-access E2E test exercises the full
write-prompt-allow → read-prompt-deny → monitor page flow end-to-end. If it
passes, the core prompt/verdict/audit pipeline is working.

### Silent API failure (CORS without --devmode)

The Angular dev build sends requests directly to `127.0.0.1:818` while the page
origin is `localhost:4200`. Without `--devmode` on the daemon the CORS check
blocks with 403; Angular's `catchError(() => of([]))` swallows the error and
shows empty state silently. Always start the daemon with `--devmode` when using
ng serve. (The `environment.ts` default now goes through the proxy so this only
bites explicit `?api-port=PORT` overrides.)

- Pure refactors / doc-only: type-check is enough.
- Logic or config change: exercise the changed path and confirm correct output.
- UI change: screenshot every affected page, read each one with the Read tool.
- If a runtime test is genuinely impossible, say so explicitly — never skip silently.

## Other conventions

- Consult upstream first when debugging or modifying forked code.
- The git remote `upstream` points to `https://github.com/safing/portmaster.git`.
