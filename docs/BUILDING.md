# Building Filemaster

Filemaster uses Portmaster's installed architecture without its containerized
release pipeline:

```text
filemaster.service → filemaster-core (privileged file-access enforcement)
desktop app     → Tauri shell → Angular UI → local core API
```

The core, UI payload, assets, and desktop app are built natively on Linux.
File access enforcement depends on fanotify, so Linux is the supported target.

## Prerequisites

Install Go 1.24 or newer, Node.js/npm, Rust/Cargo, the Tauri CLI, `bsdtar`, and
the Linux development libraries required by Tauri/WebKitGTK. Install the Tauri
CLI with:

```bash
cargo install tauri-cli --version 2.2.7 --locked
```

## Build targets

```bash
make build    # core daemon, Angular payload, assets, and Tauri desktop binary
make package  # stage those artifacts and produce Linux .deb/.rpm packages
make test     # production Go tests plus the fake-source test variant
```

`make build` writes `filemaster-core` and the desktop application to
`dist/linux_amd64/`, and writes the UI and asset ZIP payloads to `dist/all/`.
`make package` downloads the configured Intel payload, stages it with the core
and UI archives, then writes packages to `dist/linux_amd64/packages/`.

The production core does not compile the fake fanotify socket source. Tests that
need it build explicitly with `-tags filemaster_test`.

The build uses the `node` and `npm` already on `PATH`. Node 18 is also available
at `/opt/node18/bin` if you want to select it explicitly:

```bash
make NODE_BIN=/opt/node18/bin build
```

For local development, start the daemon with a temporary data directory and
the Angular development server separately, as documented in `CLAUDE.md`.

## Production install and run

From a normal user account that can use `sudo`, one command builds and installs
the production application:

```bash
make install
```

It requests administrator access only for installation, writes the core, UI,
and payloads to `/opt/filemaster`, writes mutable state to `/var/lib/filemaster`,
and installs `filemaster.service`. Start the UI as the normal desktop user with
`filemaster`. In the UI, click **Start** to start the real fanotify core. The
Filemaster's service manager invokes `pkexec systemctl start
filemaster.service`, which displays the graphical administrator-authentication
prompt.

`make` on its own only builds; it never launches or installs anything.

`INSTALL_DIR` is the application directory: it contains the real desktop binary,
the core, and the UI/assets archives. `BIN_DIR` contains only a small `filemaster`
launcher that passes the application directory to the desktop binary. Keeping
that launcher in `/usr/local/bin` lets you start Filemaster by name without
putting `/opt/filemaster` on `PATH`.

Install locations can be overridden in the same command:

```bash
make install \
  INSTALL_DIR=/opt/filemaster \
  DATA_DIR=/var/lib/filemaster \
  BIN_DIR=/usr/local/bin \
  SERVICE_DIR=/etc/systemd/system
```

The installer writes those locations into the service unit, including the
core's `--bin-dir` and `--data-dir` arguments. This Start action requires a
running systemd host and a graphical polkit agent. On a system without systemd,
the UI cannot manage the core; run it directly with `sudo
/opt/filemaster/filemaster-core --log info` and start the UI with `filemaster`.

`--bin-dir` must point at `INSTALL_DIR` (the application directory), **not**
`BIN_DIR`. The API authenticator only trusts clients whose executable lives
under `--bin-dir`, and the real desktop binary lives in `INSTALL_DIR` (the
`BIN_DIR` launcher `exec`s it, so the connecting process resolves to
`INSTALL_DIR/filemaster`). Pointing `--bin-dir` at the launcher directory
instead denies the UI with a 403. The bundled systemd unit already passes
`--bin-dir /opt/filemaster`; only manual invocations need care. For local
development you can instead enable Development Mode (`core/devMode`), which
disables API authentication entirely.
