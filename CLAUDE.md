# filemaster — project coding instructions

## What this project is

filemaster is a fork of [Portmaster](https://github.com/safing/portmaster) that replaces
network-connection prompts/monitoring with file-access prompts/monitoring using fanotify.
The network stack (`service/network`, `service/netquery`, `service/firewall`, etc.) was
deleted; see `FORK_NOTES.md` for the full deletion log.

## File-access terminology

Use these terms consistently in code, tests, plans, and user-facing text:

- **Open** is the current `FAN_OPEN_PERM` decision. It is the current file permission operation.
- **Read** and **Write** are future permissions requested at open time. A read/write (`O_RDWR`) open requests both permissions.
- Read and Write do **not** mean fanotify read/write events. Do not add, use, test, or propose fanotify read/write interception or classification.
- **Prompt** is a untimed decision request that suspends the operation before it commits and blocks no unrelated process while it waits.

Use “file access” only as the general product category, not as the operation
name in rules, prompts, events, or tests.

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

Feel free to commit at every coherent stopping point — no need to ask, unless its only documentation changes,
then leave it and commit it with the next feature commit. Push immediately after every commit.
Do not batch commits waiting for permission to push.

## Development data and migrations

This is a development fork with disposable local data. Do not add migrations,
backward-compatible parsers, or legacy fallbacks for replaced configuration,
profile, or rule formats unless the user explicitly asks for compatibility.
When a format changes, prefer one clean current representation; developers may
reset or reinstall instead of preserving obsolete local state.

## Test before every commit

Compiling clean is not testing. Every behavioral change must be exercised and
observed before committing. Do not skip this.

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
- **No stuck spinners**: any persistent "Loading…" means silent API failure —
  check network tab in devtools or daemon logs for 403s.
- **Important**: Also make sure to check the bug you are fixing or the feature
  you are implementing is actually working/fixed.
- make sure to stop/kill the program/ui after testing is done

## Other conventions

- Consult upstream first when debugging or modifying forked code.
- The git remote `upstream` points to `https://github.com/safing/portmaster.git`.
- make sure to check the docs folder for what notes already exist, and read ones that are relevent to the task, and make sure to keep them update, deleting/updating outdated info
