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

Commit at every coherent stopping point — no need to ask. Push immediately
after every commit. Do not batch commits waiting for permission to push.

## Test before every commit

Compiling clean is not testing. Before committing any behavioral change, run
the affected surface and observe it:

```bash
# Start the daemon with fake fanotify (no CAP_SYS_ADMIN needed):
go build -o /tmp/portmaster-core ./cmds/portmaster-core/
FM_FAKE_SOCKET=/tmp/fm-fake.sock /tmp/portmaster-core --data-dir /tmp/fm-test --devmode --log info &

# Inject a fake event:
echo '{"pid":1234,"exe":"/usr/bin/cat","path":"/etc/passwd","op":"open"}' \
  | ./fake-fanotify -socket /tmp/fm-fake.sock

# Hit an API endpoint:
curl -s http://127.0.0.1:818/api/v1/filequery/query -X POST \
  -H 'Content-Type: application/json' -d '{"pageSize":5}'
```

- Pure refactors and doc/comment-only edits: type-check is enough.
- Any logic or config change: must exercise the changed code path and observe
  correct output before committing.
- If a runtime test is genuinely impossible (no env, blocked perms), say so
  explicitly — never silently skip it.

## Other conventions

- Consult upstream first when debugging or modifying forked code.
- The git remote `upstream` points to `https://github.com/safing/portmaster.git`.
