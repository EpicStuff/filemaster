# Linux packages

Filemaster is Linux-only because it enforces file access through fanotify.
The native build is intentionally free of Earthly and Docker.

Install the Linux development requirements for Tauri/WebKitGTK, plus Go,
Node.js/npm, Rust/Cargo, `cargo-tauri`, and `bsdtar`. From the repository root,
run:

```bash
make package
```

The target builds and stages the core daemon, Angular UI payload, shared assets,
and Intel bootstrap data before invoking Tauri's native packager. The resulting
`.deb` and `.rpm` files are written to `dist/linux_amd64/packages/`.

The packages install immutable payloads in `/opt/filemaster`, state in
`/var/lib/filemaster`, and the privileged system unit as `filemaster.service`.
