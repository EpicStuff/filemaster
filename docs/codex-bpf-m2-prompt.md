# Codex task prompt — BPF LSM milestone M2

> You are working in the Filemaster repository (`/root/filemaster`, branch
> `claude/dev`). Read `CLAUDE.md` first and follow it. Pay attention to the
> rules on ported versus custom code, on reusing existing code, and on testing
> before committing. Then read `docs/bpf-lsm-implementation-plan-technical.md`:
> §1 Scope, §2.4 Decision table and policy compiler, §2.5 including "As built
> in M1", §5 risk 1, and the M2 row in §3. That doc is the spec. Where this
> prompt and the doc disagree, this prompt wins.
>
> **Goal.** Replace Cordon's decision model in the BPF object with
> Filemaster's. Compile Filemaster rules into banked verdict tables, publish
> them from the daemon, and add the kernel-side audit switch. Then prove with a
> differential test that the kernel's verdict equals the Go engine's.
> **Not in M2:** process labelling (M3), events in the monitor and the deny
> notice (M4), the full hardening matrix (M5).
>
> **What M1 left you** (commit `fceef27b`; read the code before changing it):
>
> - `service/fileaccess/bpflsm/`:
>   - `loader.go`: probe, `.rodata` offsets, the `Hooks` list;
>   - `abi.go`: map layout constants, encoders, `pathFileID`, which keys
>     objects by mountinfo `s_dev`, never `stat`;
>   - `enforcer.go`: generations, handover, `removeGeneration`;
>   - `selftest.go`: the tmpfs self-test on bank 1.
> - `service/fileaccess/structural_linux.go`: the
>   `fileaccess/structuralEnforcement` mode option. Audit and enforce are
>   identical today.
> - The BPF object still uses Cordon's `PROTECTED` / `RULES` / `RULE_COUNT`
>   maps and its decision: default-deny, escapes always denied, pid+exe daemon
>   bypass.
>
> **Steps.**
>
> 1. **Decision table, BPF side.** Put it in a new Filemaster-specific file,
>    `bpf/filemaster-lsm/src/decide.rs`. Change ported functions only at their
>    boundary, and update their port headers.
>    - Keep the `find_object` ancestor walk, the banks and the R0 clamp.
>    - Replace what the walk looks up with the §2.4 tables: `VERDICT` keyed by
>      `(bank, object, label, decision_op, relation)`, and `NOMATCH` keyed by
>      `(bank, label, decision_op)`.
>    - **Plan correction: the key also needs the target kind (file or
>      folder).** Rules carry an `ObjectKind` (`rule.go:31-68`), so the same
>      path can get different verdicts as a file and as a folder.
>      - The parent-folder check for Create/Delete always evaluates as a
>        folder.
>      - Take the kind from the inode mode, or from the hook (rmdir and mkdir
>        are folders).
>    - Per hook, combine lookups in the same order and with the same
>      short-circuit as the Go reference:
>      - unlink and rmdir: `DecisionDelete`;
>      - mkdir: `DecisionCreate`;
>      - link: `DecideHardLink` (`rule_decision.go:228`);
>      - rename: `DecideRename` (`:201`), where "destination exists" means the
>        destination dentry is positive.
>    - **Destinations with no object** use `NOMATCH` when any object the
>      operation touches is covered (§2.4, owner decision). An operation that
>      touches no object at all is allowed. Delete Cordon's unconditional
>      escape deny.
>    - **`RENAME_EXCHANGE`.** Verify from the 6.12 and 7.1 kernel sources how
>      `security_inode_rename` calls the hook for an exchange. I believe it
>      calls it twice with the arguments swapped; that is unverified. The
>      reference verdict is `DecideRename(a→b, DestExists)` AND
>      `DecideRename(b→a, DestExists)`. If the kernel cannot give you both
>      directions, deny the exchange. Never allow it on one side's verdict.
>    - **Labels.** Only `UNIDENTIFIED` (1) and `SELF` (2) exist in M2. Every
>      process gets `UNIDENTIFIED`, except the daemon, which keeps M1's
>      pid+exe bypass. Labelling arrives in M3, so do not add a label map.
>    - **Audit switch.** Add a mode field the daemon writes, for example in
>      `SETTINGS`. In audit, a deny becomes allow, and a per-CPU counter of
>      would-be denies per operation is incremented. Enforce returns `-EPERM`.
>      Show the counters in diagnostics (`FileAccessDiagnostics.Structural`),
>      so audit is observable before M4's events exist.
>    - Remove the Cordon maps that are now dead, and note each removal in the
>      port header.
> 2. **ABI manifest.** In `filemaster-lsm-common`, add a `cargo test` that
>    writes a JSON manifest of `size_of` and `offset_of` for every map key and
>    value. Add a Go test that checks `abi.go`'s layout against it. Commit the
>    manifest, and make the Go test fail on drift. `checkMapLayout` and
>    `policyMaps` follow the new maps.
> 3. **Compiler, Go side.** Put it in `service/fileaccess/bpflsm/compile.go`.
>    It must call the existing engine and never reimplement matching. The
>    engine is `DecisionSnapshot.DecideOperation` (`rule_decision.go:150`)
>    with `verdictFromDefaultAction` (`decision_snapshot.go:46`).
>    - Evaluation glue that needs package `fileaccess` goes in a new
>      `structural_*.go` file, which passes plain tables into `bpflsm`. See
>      "Isolation" below.
>    - **Objects** (§2.4):
>      - each watch-path scope root;
>      - each rule's base path;
>      - each current match of a single-segment glob.
>    - Per object, evaluate `O`, `O/<n>` and `O/<n>/<n>` for Delete, Create,
>      Write, Read and Execute, as file and as folder. `<n>` is a sentinel name.
>    - **Known gaps.** Report each one as a `DegradedWarning` that lists rule
>      patterns, not user paths. Do not paper over them:
>      - a glob that would match a name created later;
>      - an exact-path or glob rule whose path does not exist yet, so there is
>        no inode to key on, and creating it gets the parent's verdict;
>      - a sentinel name that some glob would match.
>      Exclude exactly these cases from the differential test, and list the
>      exclusions in the report.
>    - The `UNIDENTIFIED` snapshot is the unidentified process's profile, with
>      the `DefaultActionAsk` fallback from `profile_binding.go:86-92`. Get it
>      through the existing lookup path; do not build a parallel one.
> 4. **Banked publish.** Fill the inactive bank, clearing its stale entries
>    first, then flip `active_bank` in one write.
>    - Publish on the first start, a profile change, a config change and a
>      mode change. A config change covers watch paths, global rules and
>      the mode.
>    - Register your **own** callbacks in `structural_linux.go` on the events
>      `module.go` already uses:
>      - `profiles.Profile().EventConfigChange`, the way `module.go:105`
>        does;
>      - `cfg.Config().EventConfigChange`, which `structural_linux.go`
>        already uses for the mode.
>    - Do **not** reuse or change the single snapshot observer
>      (`profile_binding.go:168`). The prompt path owns it.
>    - Mount-change triggers may wait for M5. If you skip them, say so.
>    - A publish failure leaves the previous bank active and shows a
>      diagnostics error.
> 5. **Self-test.** Update `selftest.go` to the new tables. It must still check
>    every argument index of every hook under a deny table and an allow table.
>    Escapes are now allowed under an allow table and an allow `NOMATCH`, so
>    test them in both phases. Test the audit switch too: deny table plus
>    audit means allowed and counted.
> 6. **Differential test.** It is root-only and runs in the VM. Each run uses a
>    fresh enforcer with its own pin root, like
>    `TestEnforcerLifecycle`, with the daemon bypass pid set to 0.
>    - Generate rule sets from a logged seed: exact, `/**` and single-segment
>      glob rules; Allow and Deny; file, folder and any kinds; every profile
>      default action. Build a real tree for each.
>    - Run every operation in enforce mode and compare the syscall result
>      (EPERM or success) with the Go reference verdict for the same request.
>    - Cases include:
>      - unlink, rmdir, mkdir;
>      - link and rename within, into, out of and across scopes;
>      - destinations with and without rules;
>      - rename-over;
>      - atomic save (write a temp file, rename it over);
>      - `RENAME_EXCHANGE` and `RENAME_NOREPLACE`;
>      - `*at()` calls with directory file descriptors.
>    - Print a minimal reproducer (seed, rules, operation) for any mismatch.
>    - A mismatch is a bug in the table or the compiler. Fix it; do not loosen
>      the test. If a rule shape cannot be expressed exactly, take §5 risk 1:
>      degrade it with a warning, and list it.
>
> **Exit test (must be observed before committing):**
>
> - `make test-fake` passes without the Rust toolchain. `make test` passes,
>   including the ABI manifest test.
> - On **both** VM kernels, the differential test passes with zero mismatches,
>   and so do the M1 load and lifecycle tests. Run them on tmpfs and on btrfs
>   (root). The kernels are the default Arch `7.1.9-arch1-2`, and Debian
>   `6.12.107+deb13-amd64` via `vmctl kernel linux-debian`.
> - **Daemon check (VM).** Use a watched folder with no Write rules and the
>   default Ask action.
>   - In audit: `rm` succeeds and the would-deny counter rises in
>     `/api/v1/fileaccess/diagnostics`.
>   - Switch to enforce live: `rm` gets EPERM.
>   - Add an Allow Write rule for the folder: the publish flips the bank and
>     `rm` succeeds without a restart.
>   - Off: everything detaches, as in M1.
> - Paste per-kernel and per-filesystem results into the commit body: the
>   number of cases, the seeds and the mismatch count.
>
> **VM notes** (learned in M1):
>
> - The VM is at `/root/vm`, driven by `vmctl`. The repo is mounted at
>   `/mnt/share/filemaster` in the guest.
> - Use `pkill -x filemaster-core`. `pkill -f` matches the `vmctl ssh` session
>   and kills it.
> - Run the daemon with `--devmode` for API access on `127.0.0.1:818`.
> - `tmp/m1/` has working helpers:
>   - `daemon-test.sh` and `live-test.sh`: start a daemon with a config;
>   - `setmode`: change the mode live over the database websocket;
>   - `plant`: write a pinned map.
>   Copy and adapt them into `tmp/m2/`; that path is gitignored.
> - Built binaries must be static, or built inside the guest.
> - Leave the VM on the default kernel (Arch 7.1), and stop it when done.
>
> **Isolation from Filemaster code.** The BPF backend is an add-on, and the
> Open/Execute prompt path must be byte-for-byte untouched. You may change:
>
> - `bpf/`;
> - `service/fileaccess/bpflsm/`;
> - `service/fileaccess/structural_*.go`;
> - the structural section of `diagnosticsWarnings`;
> - the `Makefile`;
> - `docs/`.
>
> Use everything else in `service/fileaccess`, `service/profile` and the rest
> **read-only**: call it, never edit it. That includes the rule engine
> (`rule*.go`, `decision_snapshot.go`), `profile_binding.go`,
> `profile_handler.go`, `module.go` and the fanotify source.
>
> If something needs a change there, even an unexported helper you would like
> exported, **stop and report it** with the exact change you propose. Don't
> make it. Glue that has to live in package `fileaccess` to reach unexported
> engine functions goes in a new `structural_*.go` file. Report its line
> count.
>
> **Rules.**
>
> - A blocked network (DNS failure, connection refused, unreachable) means stop
>   and report the host. Do not retry or switch mirrors.
> - Do **not** run `go mod tidy`. It prunes unrelated requirements. Add only
>   the requirements you need.
> - Keep `decide.rs`, `compile.go` and other new logic out of ported
>   functions.
>
> **Commit and push** per `CLAUDE.md`, as one commit. Include the pending
> uncommitted `docs/` changes; docs-only changes ride along with the next
> feature commit. Update the plan doc: mark M2 ✅, add an "As built in M2"
> note, correct §2.4's table key to include the target kind, and record any
> other plan errors you hit. Delete this prompt file in the same commit. Do
> **not** include `zellij-copy`. Do not add AI attribution trailers.
>
> **Report back** (under ~350 words):
> - the commit hash;
> - every file changed outside the allowed set (this should be none), plus any
>   changes you proposed but did not make;
> - the files changed, with production line counts (non-blank, non-comment),
>   BPF and Go separately;
> - the table design, with key layouts and map types and sizes;
> - the per-kernel verifier result and the largest stack frame;
> - the differential results per kernel and filesystem;
> - every excluded or degraded case;
> - how `RENAME_EXCHANGE` is handled, and the kernel source evidence;
> - the clean build time;
> - anything in the plan that looks wrong now.
>
> Label claims **verified by running it**, **verified from source** or
> **judged**.
