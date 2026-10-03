# Codex task prompt — BPF LSM milestone M0

> You are working in the Filemaster repository (`/root/filemaster`, branch
> `claude/dev`). Read `CLAUDE.md` first and follow it. Pay attention to the
> rules on ported versus custom code and on testing before committing. Then
> read these parts of `docs/bpf-lsm-implementation-plan-technical.md`:
> §1 Scope, §2.1 Tree layout, §2.2 Build integration, and the M0 row in §3.
> That doc is the spec. Where this prompt and the doc disagree, this prompt
> wins.
>
> **Goal.** Import Cordon's BPF LSM program into Filemaster as a Rust crate,
> build it into a BPF object, and embed that object in the Go daemon. Then
> prove every remaining program passes the kernel verifier on both target
> kernels. **No enforcement, no policy and no daemon wiring yet.** Those are
> M1 and M2.
>
> **Source.** Clone `https://github.com/nikicat/cordon` and check out commit
> `b40a8c7bb23e4fe194c6686909524f444407c534`. It is licensed Apache-2.0. Port
> from `crates/bpf` and `crates/bpf-common` only.
>
> **Steps.**
>
> 1. **Tree layout.** Create the tree exactly as §2.1 describes:
>    - `bpf/filemaster-lsm/` ported from `crates/bpf`;
>    - `bpf/filemaster-lsm-common/` ported from `crates/bpf-common`;
>    - `bpf/rust-toolchain.toml` pinning `nightly-2026-06-23` with `rust-src`;
>    - `bpf/LICENSE-cordon`, the Apache-2.0 text from Cordon's `LICENSE`.
>
>    Rename the crates. Keep a workspace `Cargo.toml` and `Cargo.lock` under
>    `bpf/`.
> 2. **Port headers.** Every ported `.rs` file starts with a header like this
>    one, with that file's own changes summarised:
>
>    ```
>    // Ported from cordon crates/bpf/src/main.rs @ b40a8c7 (Apache-2.0) — <summary of changes>.
>    ```
>
>    Keep the ported logic otherwise intact; do not refactor it.
> 3. **Apply the gate patch.** It is in `tmp/bpf-spike/cordon-gate.diff`, two
>    lines in total:
>    - in `kernel.rs`, `#[inline(always)]` on `caller_exe`;
>    - in `main.rs`, `clamped()` returns `-EPERM` or `0` explicitly.
>
>    Without it, every program fails the verifier, and `inode_link` and
>    `inode_rename` exceed the 512-byte stack.
> 4. **Strip what is not ported** (§2.1). Remove:
>    - blessing: the `BLESSED` map, `blessed_class`, the cgroup class logic;
>    - the `file_open` program and `decide` / `requested_action`;
>    - the `bprm_check_security` program.
>
>    Keep:
>    - `inode_unlink`, `inode_rmdir`, `inode_mkdir`, `inode_link`, `inode_rename`;
>    - `decide_reparent` / `decide_remove` / `decide_create` / `consult` /
>      `find_object`;
>    - the event emission, the suppressor and `fill_comps`.
>
>    Subject matching falls back to exe-only once the class is gone. Do the
>    minimum needed to keep the rest compiling. Note every removal in that
>    file's port header. Cordon's *decision* semantics stay for now; M2
>    replaces them.
> 5. **Build.** Add a Makefile `bpf` target and make `core` depend on it
>    (§2.2). The target builds the object with the pinned toolchain for
>    `bpfel-unknown-none` (`-Z build-std=core`). It copies the object to
>    `service/fileaccess/bpflsm/obj/filemaster-lsm.bpf.o`, which must be
>    gitignored. It also prints `bpf-linker --version` and the object's SHA-256.
>
>    Prerequisites: `bpf-linker` **0.11.0 from the Arch `extra` repo**, installed
>    with pacman. `cargo install bpf-linker` fails here because it can't find
>    LLVM. Add both prerequisites to `docs/BUILDING.md`.
> 6. **Embed.** Create the Go package `service/fileaccess/bpflsm` with
>    `//go:build linux`. It embeds the object with `//go:embed` and exposes only
>    what the load test needs.
>
>    Add a `filemaster_test` build-tag stub that embeds nothing, and use it from
>    `make test-fake` (`Makefile:112`). Unit tests must keep running without the
>    Rust toolchain.
> 7. **Load test.** Write a Go test, root-only and skipped without root, that:
>    - parses the embedded object with cilium/ebpf (v0.20.0, already in
>      `go.mod`);
>    - fills the `OFFSETS` `.rodata` global from `/sys/kernel/btf/vmlinux`.
>      The object has no BTF, so `VariableSpec.Set` refuses; write the
>      `.rodata` bytes directly the way `tmp/bpf-spike/spike2-main.go` does.
>      Reuse that code;
>    - loads every program through the verifier;
>    - asserts each of the five programs loaded.
>
>    It must **not** attach anything.
>
> **Exit test (must be observed before committing):**
>
> - `make core` builds and embeds the object. `make test-fake` passes without
>   the Rust toolchain on `PATH`.
> - The load test passes in the dev VM on **both** `7.1.0-filemaster-p1` and
>   `6.18.46-lts`. The VM is at `/root/vm`, driven by `vmctl`. The host kernel
>   has no BPF LSM; run it on the host as well if it can load the programs.
> - Paste the verifier result for each program and each kernel into the commit
>   message body.
>
> If a program fails the verifier, the full verifier log tail is required.
> First suspect your stripping, which may have changed inlining and stack
> frames. Fix it with the smallest change and record it in the port header. If
> you can't fix it, stop and report. **Do not** work around it by dropping a
> program.
>
> **VM cleanup.** Afterwards, make sure the VM's GRUB default is
> `linux-filemaster-p1`. Last time `vmctl kernel` could not switch back, and
> `/etc/default/grub` plus `grub-mkconfig` were needed. Stop the VM.
>
> **Commit and push** per `CLAUDE.md`, as one commit. Include the pending
> uncommitted `docs/` changes; per `CLAUDE.md`, docs-only changes ride along
> with the next feature commit. Do **not** include `zellij-copy`. Do not add
> AI attribution trailers.
>
> **Report back** (under ~300 words):
> - the files added, with production line counts (non-blank, non-comment);
> - what was stripped;
> - any changes beyond the gate patch;
> - the per-kernel verifier results;
> - the build time;
> - the commit hash;
> - anything in the plan that looks wrong now that you've done the work.
>
> Label claims **verified by running it**, **verified from source** or
> **judged**.
