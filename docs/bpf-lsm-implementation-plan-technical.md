# BPF LSM backend — implementation plan

> Decision record: [BPF LSM option](update-option-bpf.md),
> [technical proof and gate](update-option-bpf-technical.md), and
> [cost re-cost as a Cordon port](update-options-cost-technical.md#bpf-lsm-re-costed-as-a-cordon-port-2026-10-03).
> Requirements: [backend features](backend-features.md) and
> [BPF-LSM test requirements](backend-test-requirements-technical.md#bpf-lsm-specific-requirements).
> Budget: **8–11 sessions**. This plan sums to 8.5–11.5; see
> [Estimate check](#estimate-check).

## 1. Scope

**In scope.** Static, pre-commit enforcement on a stock kernel for:

| Filemaster operation | LSM hook | Rule-engine decision |
|---|---|---|
| Delete file | `inode_unlink` | `DecisionDelete` |
| Delete folder | `inode_rmdir` | `DecisionDelete` |
| Create folder | `inode_mkdir` | `DecisionCreate` |
| Hard link | `inode_link` | `DecideHardLink`: source Read+Write+Execute, then destination Create |
| Rename / move / replace | `inode_rename` | `DecideRename`: source Delete, then destination Create, or Write then Delete if the destination exists |

The decision semantics are the ones already written for future backends in
`service/fileaccess/rule_decision.go`:

- the operation enum, `:49-67`;
- the operation → rule-list mapping, `:103-120`;
- the parent-folder rule for entry operations, `:122-145`;
- `DecideOperation`, `:150`;
- `DecideRename`, `:201`;
- `DecideHardLink`, `:228`.

The BPF side must reproduce these decisions, not Cordon's own model (§2.4).

**Ask, and no match under an Ask/Block default, deny with feedback.**
`verdictFromDefaultAction` (`decision_snapshot.go:46`) already maps
everything except Permit to Deny for non-prompt operations. The denial is
reported, and the user can allow and retry
([decided behaviour](update-option-bpf-technical.md#decided-behaviour-deny-with-feedback)).

**Non-goals for this plan:**

- regular-file create (`inode_create`), `symlink`, `mknod`, truncate, metadata,
  and listing;
- prompting for any structural operation;
- any change to Open or Execute.

Fanotify stays the only Open/Execute decision path (test requirement BPF-2).
The labelling hooks (`bprm_check_security`, `bprm_committed_creds`, fork and
exit tracepoints) **observe only and always return 0**. Cordon's `file_open`
program and its exec decision are not ported.

## 2. Architecture

### 2.1 Tree layout

| Path | Contents | Origin |
|---|---|---|
| `bpf/filemaster-lsm/` | Rust no_std crate (`aya-ebpf` 0.1.1), compiled to `filemaster-lsm.bpf.o` | Ported from Cordon `crates/bpf` at `b40a8c7` |
| `bpf/filemaster-lsm-common/` | `#[repr(C)]` map keys/values, the record layout, and a layout-manifest test | Ported from Cordon `crates/bpf-common` |
| `bpf/rust-toolchain.toml` | `nightly-2026-06-23` + `rust-src` | Cordon's pin, unchanged |
| `bpf/LICENSE-cordon` | Cordon's Apache-2.0 text | Required by Apache-2.0 §4 |
| `service/fileaccess/bpflsm/` | Go package, `//go:build linux`: loader, probe, publisher, labeller, event reader | Filemaster-specific |
| `service/fileaccess/bpflsm/obj/` | Built object, embedded with `//go:embed`; gitignored | Build output |

**Licence.** Apache-2.0 code may be combined into this GPLv3 project
(`LICENSE`). The same rules as ported Portmaster code apply (CLAUDE.md):

- Every ported file starts with
  `// Ported from cordon crates/bpf/src/main.rs @ b40a8c7 (Apache-2.0) — <summary of changes>.`
- Filemaster-specific BPF logic, chiefly the decision table (§2.4) and labels
  (§2.6), goes in **separate files** (`decide.rs`, `label.rs`). It is never
  interleaved inside ported functions.
- Cordon ships no NOTICE file, so `LICENSE-cordon` plus the per-file change
  summaries satisfy §4(b).
- The BPF object keeps its `license` section as `"GPL"`, as Cordon has it
  (`main.rs:595`).

**Cordon code that is not ported:**

- blessing: `BLESSED`, `blessed_class`, the cgroup classes;
- `file_open` / `decide` / `requested_action`;
- `bprm_check_security`'s decision path;
- the CLI and the TOML rule DSL.

The 2-line gate patch (`clamped()` R0 fix, plus `#[inline(always)]` on
`caller_exe`) goes in with the first import.

### 2.2 Build integration

- **Makefile:** a new `bpf` target. `core` depends on it (today `core` is just
  `go build ./cmds/portmaster-core`, `Makefile:58-60`). The target runs
  `cargo +nightly-2026-06-23 build --release -Z build-std=core --target bpfel-unknown-none`
  in `bpf/filemaster-lsm`, then copies the object to `service/fileaccess/bpflsm/obj/`.
- **Prerequisites:** `bpf-linker` 0.11.0 from Arch `extra`. `cargo install`
  failed to find LLVM during the spike. Add both to `docs/BUILDING.md`
  prerequisites.
- **Embedding:** the Go package embeds the object, so `.deb`/`.rpm` packaging
  and `make package` are unchanged; the object ships inside `filemaster-core`.
- **Without the object:** a plain `go build` fails at the embed. That is
  acceptable, because `make core` is the supported entry point.
- **`make test-fake`** (`Makefile:112`) gains a `filemaster_test` stub that
  embeds nothing, so unit tests run without the Rust toolchain.
- **Reproducibility:** the verifier outcome depends on the LLVM in
  `bpf-linker` (spike finding). Record `bpf-linker --version` and the object's
  SHA-256 in the build log. A self-test at load (§2.5) fails loudly rather than
  shipping an object that does not verify.

### 2.3 Go loader (`bpflsm/loader.go`, `probe.go`)

Pattern from `scratchpad/spike2/main.go` (cilium/ebpf v0.20.0, already a
direct dependency in `go.mod:15`).

1. **Probe.**
   - `bpf` is listed in `/sys/kernel/security/lsm`.
   - `/sys/kernel/btf/vmlinux` exists.
   - bpffs is mounted at `/sys/fs/bpf`.
   - Each hook's `bpf_lsm_<hook>` BTF stub exists.

   Each failure becomes a `DegradedWarning` (`diagnostics_linux.go:23`) naming
   exactly which operations are unprotected (test requirement BPF-4).
2. **Offsets.** Fill the `OFFSETS` `.rodata` global from vmlinux BTF using
   `cilium/ebpf/btf`. Cordon's object has no BTF, so the spike wrote `.rodata`
   bytes directly, because `VariableSpec.Set` refuses. Cordon's `btf.rs`
   (235 lines) becomes about 40–80 lines of Go.
3. **Load and attach.** Order: load → seed bank 0 → attach the five `lsm/*`
   programs plus the labelling programs → self-test (§2.5) → pin → sweep older
   generations. This is Cordon's handover order (STATUS.md, M5).

### 2.4 Decision table and policy compiler (`bpflsm/compile.go`)

**Cordon's matcher is not Filemaster's.** Cordon resolves the deepest protected
object, then applies its own precedence: object depth → subject → deny>allow,
plus an unconditional "escape" deny. Filemaster rules are instead:

- per-profile **ordered first-match** lists, with the profile's own rules first
  and then the global rules (`rule_scope.go:78-93`);
- of three kinds only: exact path, `dir/**`, or a single-segment glob
  (`rule.go:115-126`);
- with entry operations also consulting the containing folder
  (`rule_decision.go:122-145`).

The port keeps Cordon's **mechanism** and replaces its **decision**:

- **Kept:** the dentry ancestor walk to the deepest object (`find_object`),
  the banked maps, the R0 clamp, path reconstruction for events.
- **Replaced:** what the walk looks up. It now reads a precomputed verdict table:

```
VERDICT[(bank, object_id, label, decision_op, relation)] -> allow | deny | audit
relation = SELF (target is the object) | CHILD (object is the target's parent)
         | DESCENDANT (deeper, no closer object)
```

**Compiler.** For each object `O` and each label `L`:

1. Evaluate the profile's existing `DecisionSnapshot.DecideOperation`
   (`rule_decision.go:150`) on three synthetic paths: `O`, `O/<n>` and
   `O/<n>/<n>`. `<n>` is a sentinel name that no pattern can match.
2. Do this for Delete, Create, Write, Read and Execute; the hard-link source
   needs Read/Write/Execute.

This is exact for `/**` and exact-path rules: every descendant of `O` with no
closer object sees the same applicable rule set. Order semantics stay
Filemaster's own because the Go engine computes them.

**Where the BPF side applies it.** Rename and link combine table lookups in the
same order as `DecideRename` and `DecideHardLink`. "Destination exists" comes
from the destination dentry being positive, which is how Cordon already detects
rename-over (`decide_reparent`). Unlink, rmdir and mkdir are single lookups.

**Destinations with no object (owner decision, 2026-10-03).** "Not covered →
allow" applies only when *every* object an operation touches is uncovered. A
rename or hard link whose source is covered still decides its destination,
even when the destination has no object.

Such a destination matches no rule, so it gets the label's no-match verdict:
the profile default through `verdictFromDefaultAction`
(`decision_snapshot.go:46`). The compiler stores this per label as
`NOMATCH[(bank, label, decision_op)]`. The result matches `DecideHardLink`
(`rule_decision.go:228`) and `DecideRename` (`:201`) exactly:

- a hard link or move out of a watched folder to a place with no rules is
  denied unless the profile default is Permit;
- a destination covered by a rule, including a global rule outside every watch
  scope, which is an object in its own right, follows that rule.

This replaces Cordon's unconditional escape deny. M2's differential test must
include link and rename to an uncovered destination.

**Objects** are:

- each configured watch-path scope root (`config.go:13`, `mount_linux.go:42`);
  there the profile default applies, and outside every scope the operation is
  **not covered** and allowed (reported as coverage);
- the base path of every rule (exact path, or the prefix of a `/**` rule);
- every current match of each single-segment glob.

Objects are keyed by `(sb->s_dev, ino)`. `s_dev` comes from
`/proc/self/mountinfo` (`readMountInfo`, `mount_linux.go:198`) and never from
`stat`, because the btrfs minors differ (gate finding).

**Globs.** A glob is expanded when the policy is built. A file created later
that matches a glob falls back to its folder's or the scope's verdict. This
degradation is shown as a `DegradedWarning` that lists the affected rule
patterns (not user paths). The degraded objects are re-expanded on the existing
mount/reconcile triggers and on each re-publish.

**Labels.** A label is an equivalence class of *(ordered Read/Write/Exec lists,
default action)* over all profiles, after global rules are merged. Profiles
that share both get one label. Reserved labels:

| Label | Meaning |
|---|---|
| `0 = PENDING` | Every verdict is deny |
| `1 = UNIDENTIFIED` | The unidentified-process profile, with `DefaultActionAsk`, as in `profile_binding.go:86-92` |
| `2 = SELF` | The Filemaster daemon; every verdict is allow |

**Publication.**

1. Fill the inactive bank.
2. Flip `SETTINGS.active_bank` in one write (Cordon `seed.rs`).
3. Re-publish on any of: a profile or rule change (the existing snapshot
   observer, `profile_binding.go:168`), a watch-path change (`module.go:220`),
   a mount change, an exe inode change (§2.6), or glob re-expansion.

**ABI agreement.** `filemaster-lsm-common` has a `cargo test` that emits a
JSON manifest of `size_of` and `offset_of` for every map key/value. A Go test
asserts its mirrored structs against that manifest; it fails the build on any
drift.

### 2.5 Lifecycle and crash behaviour (`bpflsm/lifecycle.go`)

- **Pinning.** Links are pinned to `/sys/fs/bpf/filemaster/<gen>/`, so
  enforcement with the last published policy survives a daemon SIGKILL.
- **Config.** New option `fileaccess/structuralEnforcement`:
  `off | audit | enforce`, **default `audit`** (§5, risk 2).
  - `audit` uses the same table but turns every deny into allow-and-record.
  - `off` unpins and detaches. Detach is asynchronous (Cordon), so the daemon
    polls until it completes before reporting "unprotected".
- **Self-bypass.** The daemon's own operations bypass enforcement through
  `SELF`, keyed by `(tgid, start_time)` plus an exe check. The pid-only
  weakness Cordon documents (`main.rs:199`) is closed by the start-time key.
- **Restart window.** A restarted daemon gets a new tgid, so the **old** pinned
  generation enforces against it until handover. Startup must therefore do no
  structural operations inside watched scopes before step 3 of §2.3.
- **Self-test.** Run before pinning, in a private tmpfs:
  - each hook denies under a deny table and allows under an allow table;
  - this exercises every argument index, catching the silent fail-open Cordon
    warns of (`main.rs:139-145`).
- **Uninstall.** A packaging `postrm` runs `filemaster-core --bpf-teardown`.

### 2.6 Process labelling (`label.rs`, `bpflsm/labeller.go`)

**Kernel side:**

| Hook | Action |
|---|---|
| `tp_btf/sched_process_fork` | Copy the parent's label to the child `(tgid, start_time)`. It fires after `start_time` is set and before the child is woken (fork.c, verified in the survey). |
| `bprm_check_security` | Called once per binfmt pass. On the first pass, if `bprm->file` is not the final interpreter, record the script `(dev, ino)` in the exec scratch for this task. |
| `bprm_committed_creds` | Recompute the label (below), then emit an `ExecRecord` on the ring buffer with exe `(dev, ino)`, script `(dev, ino)` and argv/envp. argv/envp are captured with `bpf_probe_read_user` from the new mm before user code runs, truncated to fixed buffers with a truncation flag. |
| `tp_btf/sched_process_exit` | Delete the entry, for the group leader only. |

Recompute at exec:

1. If the exe is in `EXE_LABEL` and is not a known interpreter, use that label
   (fast path, no gap).
2. If a carried script inode is in `SCRIPT_LABEL`, use that label.
3. Otherwise set `PENDING`.

The `env`/interpreter re-exec rule: if a script inode was recorded and the next
exec's argv names that same script, the inode carries across.

**Map type.** Use a `HASH` with exit cleanup in preference to `LRU_HASH`:
eviction would silently turn a live process into `PENDING`. A full map denies,
and its counter is reported. LRU remains the fallback if the exit tracepoint
proves unreliable. Task-storage maps are not usable: they need BTF, which the
object lacks (survey).

**Daemon side:**

1. Read `ExecRecord`s and resolve the profile with the existing
   `process.GetProcessWithProfile` path, fed with the **captured** argv/envp.
   Today `loadProcess` reads cmdline and env from `/proc` through gopsutil
   (`service/process/process.go:317`, `:332`), which a process can rewrite.
   This needs a boundary change to the upstream-ported `process` package: an
   optional pre-captured `CmdLine`/`Env` override, set before the ported block
   with a comment, per CLAUDE.md.
2. Write the label for `(tgid, start_time)`.
3. Interpreter tags then set `MatchingPath` to the script
   (`process/tags/interpreter_unix.go:236`, `:248`), and fingerprint scoring
   (`profile/fingerprint.go:261-351`) picks tag, cmdline, env and path profiles
   unchanged.

**Script-open labelling.** When fanotify reports `FAN_OPEN_PERM` by a `PENDING`
interpreter process on a file matching its captured script argument, the
daemon writes the label **before** answering the open. So the script's own code
never runs unlabelled. This only applies to scripts inside watched mounts;
scripts elsewhere are labelled from the exec record alone.

**Fast-path tables.**

- `EXE_LABEL` is compiled for exe paths whose profile cannot depend on
  cmdline, env or tags. That means no enabled profile has a cmdline or env
  fingerprint and the exe is not an interpreter. Otherwise the exe goes
  through `PENDING`.
- An exe inode change (package upgrade) is detected by re-stat'ing the
  `EXE_LABEL` paths on re-publish and on a periodic tick. It triggers a
  re-publish; until then, new execs of the upgraded binary are `PENDING`, which
  the daemon labels from the exec record. A fanotify `FAN_ATTRIB`/moves watch
  on those paths is a possible improvement; it is untested.

**Daemon tgid → start_time.** The daemon keeps this map from exec records. For
processes that started before the daemon, it is seeded once by walking `/proc`
at load. `/proc/<pid>/stat` `starttime` is in clock ticks; it is converted and
matched within one tick.

### 2.7 Events, feedback and status

- **Records.** The ring buffer carries `DecisionRecord`s: operation, verdict,
  label, object id, the leaf-to-object name components (Cordon `fill_comps`),
  and a second object for rename/link. The daemon prefixes the object's path
  and emits `filequery.FileAccessRecord` (`service/filequery/record.go:7`). `Op`
  is `delete`, `create`, `rename` or `link`, with mount attribution from
  `attributeMount` (`mount_linux.go:861`).
- **Volume.** Cordon's in-kernel suppressor (`kernel.rs:367`) is kept.
- **Deny notice.** A new informational notification, modelled on
  `NotificationsPrompter` (`prompt_notifications.go:43-101`). It shows what was
  blocked and offers **Allow**, which appends a `+ <path>` Write rule through
  `profileRuleStore.AppendRule` (`profile_binding.go:240`). That triggers a
  re-publish, and the user retries.
- **Rule model.** `CurrentRuleModel` (`rule_decision.go:34`) must report Write
  as **active** when structural enforcement is `enforce`. The UI must expose the
  Write list, which is "hidden and retained only" today.
- **Status.** Coverage and degraded warnings flow through
  `diagnosticsWarnings` (`diagnostics_linux.go:159`):
  - BPF LSM unavailable;
  - per-hook attach failure;
  - mode;
  - glob degradation;
  - label map full / `PENDING` denials count;
  - an orphaned older generation.

## 3. Milestones

Each milestone is one coherent commit with a VM-observed exit test (CLAUDE.md
"test before commit"), on both `7.1.0-filemaster-p1` and `6.18.46-lts`, using
both tmpfs and btrfs.

| # | Slice | Exit test (observed in VM) | Sessions |
|---|---|---|---:|
| M0 | Vendor the crates with port headers and the licence; apply the gate patch; strip blessing/open/exec; Makefile `bpf` target, `go:embed`, `test-fake` stub | `make core` embeds the object; a Go test loads every program through the verifier on both kernels | 0.5 |
| M1 | Loader, probe, `.rodata` offsets, attach, pin generations, handover, self-test, teardown, mode option, degraded warnings | Enable → 5 hooks attached and shown in diagnostics; SIGKILL → enforcement persists; restart → generation swap with no gap; `off` → detached and reported unprotected | 1.5 |
| M2 | Decision table (`decide.rs`) + Go compiler + banked publish + ABI manifest test; single label `UNIDENTIFIED` | Differential test: for generated rule sets, the BPF verdict equals `DecideOperation`/`DecideRename`/`DecideHardLink` across the operation matrix, including rename-over, atomic save, cross-directory moves and `*at()` callers | 2–2.5 |
| M3 | Labelling: fork/exec/exit programs, argv/envp capture, `EXE_LABEL`/`SCRIPT_LABEL`, `process` boundary override, script-open labelling, `PENDING` deny | `python a.py` vs `python b.py` get distinct verdicts; `./x.py` with env shebang; bash/node/perl; `-m` resolves; `-c` falls to the interpreter profile; argv rewrite after start does not change the label; a child `rm` gets `rm`'s label | 2–2.5 |
| M4 | Events → filequery, deny notification with Allow-and-retry, Write list active in rule model and UI | Monitor shows delete/rename/link records; the notification appears; Allow → retry succeeds; screenshots of dashboard/monitor/settings checked per CLAUDE.md | 1.5–2 |
| M5 | Hardening matrix (§4) and fixes | §4 matrix green; coverage warnings correct for every injected failure | 1–1.5 |
| | **Total** | | **8.5–11.5** |

## 4. Test plan

**VM matrix.** Kernels 7.1 and 6.18; 6.12 needs a guest kernel that the VM
does not have yet, and is verifier-only today. Filesystems:

- tmpfs, btrfs (root), and ext4 (a loop device);
- overlayfs, both lower and upper; untested so far, and Cordon measured only
  `file_open`;
- a bind mount of a protected folder;
- a private mount namespace (`unshare -m`).

**Operation cases.** Each runs with Allow, Deny, Ask, no-match under each
default action, and an unrepresentable case (test requirement BPF-3):

- unlink, rmdir, mkdir;
- hard link in, out and within a scope;
- rename within, out, in, and over an existing file;
- `RENAME_EXCHANGE` and `RENAME_NOREPLACE`. `inode_rename` has no flags
  argument (BPF technical, "Required P1"); exchange must be decided as two
  renames or denied, never allowed on one side's verdict.

**Coexistence (BPF-2).**

- The Open and Execute prompts behave the same with the mode set to `off`,
  `audit` and `enforce`.
- No `file_open` program is attached; check with `bpftool link`.

**Lifecycle (BPF-4).** For each event below, the reported coverage must equal
the actual coverage:

- SIGKILL during publish, between the bank fill and the flip;
- a loader failure partway through attach;
- a forced verifier failure (a corrupted object);
- bpffs not mounted;
- `bpf` missing from the LSM list.

**Labelling.**

- Interpreters: python, bash, node and perl script open order (only CPython has
  been checked).
- Script forms: `#!/usr/bin/env python3`; `python -m pkg`; `python -c`.
- AppImage and flatpak.
- An argv-rewriting process (`prctl`/`setproctitle`).
- Ordering: fork then exec; a thread exec; daemon restart with live processes
  (seeded from `/proc`).

**Pressure.**

- A fork storm until the label map is full, which must deny and report, not
  evict.
- An event-storm ring-buffer overflow, which must be counted and must never
  turn a deny into an allow.

**Workflows (shared requirement 7).**

- editor atomic save (vim, VS Code);
- file-manager move, copy and delete;
- `git checkout`;
- `tar -x`;
- a package upgrade of a labelled exe, followed by re-publish.

## 5. Risks and fallbacks

1. **The decision table diverges from the Go engine on some rule shape.**
   - *Detect:* M2's differential test.
   - *If it fails:* restrict BPF to the shapes the table expresses exactly
     (`/**`, exact path) and report other rules as degraded. Never guess.
2. **Default Ask → Deny breaks the desktop on day one.** No profile has Write
   rules yet, because the list is hidden. So every delete, rename or mkdir
   inside a watched scope would deny.
   - *Mitigation:* default mode `audit`. The monitor shows what *would* be
     denied, and the user promotes rules before switching to `enforce`.
   - *If audit is not enough:* add a per-scope enforce toggle.
3. **Labelling misses or races.** Examples: an interpreter that opens its
   script after running user code, or an exec record dropped on overflow.
   - *Fallback:* that process stays `PENDING`, which means deny, with a visible
     reason.
   - *If the deny rate is unacceptable:* fall back for that interpreter to the
     exe-wide label, reported as degraded.
4. **Toolchain or verifier drift.** A new `bpf-linker`/LLVM, or a new kernel,
   rejects the object (as happened in the spike).
   - *Mitigation:* the toolchain is pinned, the M0 load test runs on both
     kernels, and the self-test runs at runtime.
   - *If it fails:* restructure the affected function. The gate's stack fix was
     one line.
5. **Overlayfs or bind-mount identity mismatch on the mutation hooks.**
   - *If it fails:* treat that mount as not covered and say so. Do not key on
     overlay inodes without proof.
6. **Restart window self-denial.** The old generation denies the restarted
   daemon's structural writes.
   - *If observed:* include the exe in `SELF`'s key with a generation-agnostic
     exe match, accepting the PID-reuse caveat only for the daemon's own exe.

## Estimate check

The plan sums to **8.5–11.5** against the 8–11 budget. Three code findings push
toward the top end:

- **Cordon's decision logic is replaced, not trimmed** (§2.4). The re-cost
  assumed 150–250 changed BPF lines; the decision table and its differential
  test are closer to 300–450.
- **The Write list is hidden, and the default maps to Deny.** That forces
  `audit` mode, UI exposure of the Write list and the deny notice. Most of this
  lands in M4, which the re-cost only partly covered.
- **Identity reads `/proc` today.** Feeding captured argv/envp needs a
  boundary change in the ported `process` package. Also, fanotify script-open
  labelling only applies inside watched mounts.

Untested assumptions are marked inline; none has been exercised on Filemaster
code yet.
