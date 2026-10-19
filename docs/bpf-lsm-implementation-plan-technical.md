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
  acceptable, because `make core` and `make test` are the supported entry
  points; both depend on `bpf` (M1).
- **`make test-fake`** (`Makefile:112`) gains a `filemaster_test` stub that
  embeds nothing, so unit tests run without the Rust toolchain.
- **Reproducibility:** the verifier outcome depends on the LLVM in
  `bpf-linker` (spike finding). Record `bpf-linker --version` and the object's
  SHA-256 in the build log. A self-test at load (§2.5) fails loudly rather than
  shipping an object that does not verify.

### 2.3 Go loader (`bpflsm/loader.go`, `abi.go`)

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

**Cordon's matcher is not Filemaster's, and neither was M2's precomputed table.**
Filemaster rules are per-profile **ordered first-match** lists (profile rules
then global rules, `rule_scope.go:78-93`), of three kinds — exact path, `dir/**`,
or a `filepath.Match` glob (`rule.go:115-126`) — with entry operations also
consulting the containing folder (`rule_decision.go:122-145`). A glob character
class can match `/`, and `filepath.Match` commits each star chunk at its leftmost
match, so segment splitting and two-pointer globbing are both wrong. The engine
is `matchPathPattern` over the **whole** path string.

The as-built M2-fix-up design reproduces that engine exactly by rebuilding each
target's full path in the kernel and running a faithful port of Go's
`path/filepath.Match` over it.

**Walk and path reconstruction.** The dentry ancestor walk (`decide.rs`,
`bpf_loop`, limit `WALK_LIMIT = 4096`) climbs from the target to the nearest
registered object, writing each component name backwards into a per-CPU path
buffer (`SCRATCH`, 16 KiB + 4 KiB slack, with bounded masked offsets). The
object context's stored absolute path is prefixed to give the target's exact
full path (and the parent's, for Create/Delete). Past the walk limit the
operation is **denied and counted**; a path longer than the buffer is **denied
and counted**; an unreadable kernel value **fails open and is counted**; a walk
that reaches an unregistered filesystem root is **not covered and counted**.

**Objects** are keyed by `(mountinfo s_dev, ino)` — `pathFileID` takes the
superblock device from `/proc/self/mountinfo` via `statx`'s `STATX_MNT_ID`,
never `stat`'s `st_dev` (btrfs minors differ). The object set is: every watch
scope root; the deepest existing ancestor of each rule's literal prefix; and
**every mount root** in `/proc/self/mountinfo` (including bind mounts whose root
is a subdirectory). Because mount roots are objects, the walk stops at them, so
nested mounts are covered with no separate splice step. A filesystem root
mounted at several paths produces several **contexts** (below), one per absolute
path, and the operation is denied if any denies.

**Contexts and rule lists.** Each object has one or more `Context`s, one per
absolute path it is reachable at, each holding: the absolute path; the watch
scopes that could contain a target under it (stored as strings, so scopes that
don't exist yet still decide by string); and its ordered list of rule
references, each carrying its list (Read/Write/Execute), verdict and ObjectKind.
A rule is included in a context's list if it could match the context path or
anything at or below it — over-inclusion is always safe because the kernel
matches exactly. The per-context cap is 256 rules / 32 scopes; past it the
context's operations are denied, an `error` warning lists the patterns, and it
is counted. The kernel evaluates every context and denies if any denies.

**Kernel matching (`matcher.rs`).** Pattern *parsing* — `scanChunk`, `getEsc`,
class syntax and `ErrBadPattern` detection — is static, so it runs in Go at
compile time (`tokens.go`), which emits a flat **token program** per pattern:
chunks (each with a star flag and a token range), tokens (literal byte, `?`, or
a class with a negated flag and a rune-range range), and ranges. A rule whose
pattern `filepath.Match` rejects never matches, so it is left out, with a
non-blocking `pattern-never-matches` diagnostic. The kernel executes only Go's
`Match`/`matchChunk` **control flow** over those tokens — the outer chunk loop,
the byte-wise star skip that cannot skip `/`, the last-chunk and trailing-star
rules, `matchChunk` per token, and the `DecodeRuneInString` port — as one flat
`bpf_loop` state machine, one small step per iteration (one token, one
class-range compare, or one chunk restart). A recursive `/**` rule and a watch
scope are matched by the exact `pathContains` prefix rule instead.

**Verifier convergence (the gate lesson).** Every mutable walk and matcher field
lives in a per-CPU map value (`EVAL`), not on the stack: the verifier does not
track map-value contents precisely, so the `bpf_loop` callback converges in a
few passes. Precise stack scalars in the callback are what previously blew
through the 1,000,000-instruction limit. Nested `bpf_loop` is not viable (it
explodes the verifier even for a trivial callback), so the matcher is one flat
loop. `memset`/`memcpy` from the linker are rejected by the verifier, so state
is zeroed with volatile word stores and subprograms return packed `u64`s rather
than multi-word tuples (which otherwise spill through an invalid `r11`).

**Destinations with no object (owner decision).** "Not covered → allow" applies
only when *every* object an operation touches is uncovered. A rename or hard
link whose source is covered still decides its destination: the destination's
context evaluates it, and with no matching rule the in-scope profile default
(`NOMATCH[(bank, operation, target_kind)]`, from `verdictFromDefaultAction`)
applies, matching `DecideRename`/`DecideHardLink` exactly. A hard link's target
is always a negative dentry (the VFS returns `EEXIST` before the hook), so the
link-over case does not arise.

**Operations.** Unlink, rmdir and mkdir are single evaluations. Rename and hard
link combine evaluations in `DecideRename`/`DecideHardLink` order; `evaluate` is
an out-of-line subprogram so a hook that calls it up to five times stays within
the verifier's budget. `RENAME_EXCHANGE` is **not** read from a flags argument
(`inode_rename` has four arguments, no flags): `security_inode_rename` calls the
hook a second time with the sides swapped, so each call is one directed rename
onto an existing destination (verified from the v6.12.107 and v7.1.9
`security/security.c` sources).

**Re-publish.** The compiler re-publishes on profile/rule and watch-path
changes, and on mount changes: structural code polls `/proc/self/mountinfo` for
`POLLPRI` (the fanotify mount code is untouched). The 1,024-object limit stays a
visible publish error, never a partial table; banked publication (fill the
inactive bank, flip `SETTINGS.active_bank` in one write) is unchanged.

**Labels.** M2 still uses the single `UNIDENTIFIED` label and the daemon's
pid+executable bypass; process labelling is M3.

**ABI agreement.** `filemaster-lsm-common` has a `cargo test` that emits a JSON
manifest of `size_of`/`offset_of` for every published table type and the table
sizes. A Go test asserts its mirrored structs and constants against that
manifest; it fails the build on any drift. The in-kernel `EvalState` is not
published, so it has no ABI.

### 2.5 Lifecycle and crash behaviour (`bpflsm/enforcer.go`, `selftest.go`)

- **Pinning.** Links are pinned to `/sys/fs/bpf/filemaster/<gen>/`, so
  enforcement with the last published policy survives a daemon SIGKILL.
- **Config.** New option `fileaccess/structuralEnforcement`:
  `off | audit | enforce`, **default `audit`** (§5, risk 2).
  - `audit` uses the same table but turns every deny into allow-and-record.
  - `off` unpins and detaches. Detach is asynchronous (Cordon). M1 found the
    trap: when unlinking the pin drops a link's last reference, the detach runs
    later on a kernel workqueue while the link ID already reads as gone, so
    polling IDs passes too early and the old programs keep enforcing briefly.
    The loader therefore opens each pinned link, unlinks the pin, then closes
    its own descriptor last; that close detaches synchronously
    (`removeGeneration`). The programs themselves are freed a little later
    still (RCU), which is harmless.
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
- **Uninstall.** `filemaster-core bpf-teardown` (a subcommand, like `version`
  and `update`) unpins every generation. The packaging `postrm` runs after the
  package's files are gone, so it removes `/sys/fs/bpf/filemaster` directly;
  removing the pins releases the links.

**As built in M1:**

- Generations are named by start time in nanoseconds. Each pins its links
  (`link-<id>`) and the four policy maps (`SETTINGS`, `PROTECTED`, `RULES`,
  `RULE_COUNT`).
- The self-test runs on bank 1 with no daemon bypass, in a tmpfs mounted at
  `/run/filemaster/bpf-selftest`. Deny table: unlink, rmdir and mkdir inside
  the protected folder, and link and rename both out of it (source argument)
  and into it (destination argument). Allow table: the same operations minus
  the escapes, which Cordon's model always denies. A failure detaches the new
  programs and leaves older generations in place.
- The daemon bypass is still Cordon's pid + exe record; `(tgid, start_time)`
  arrives with labelling (M3).
- Audit and enforce attach identically. With an empty policy they cannot
  differ; the kernel-side audit switch lands with the decision table (M2).
- Structural enforcement starts before the fanotify source, and only in the
  daemon (an instance with configuration). A failed fanotify start leaves the
  new generation pinned with an empty policy, which allows everything.

**As built in M2:**

- The M1 `PROTECTED`, `RULES`, and `RULE_COUNT` maps are gone. The policy maps
  are `OBJECTS` (hash, 1,024 entries), `VERDICT` (hash, 61,440 entries),
  `NOMATCH` (hash, 20 entries), and `AUDIT` (per-CPU array, five counters).
  `SETTINGS` carries the active bank and audit/enforce mode. The ABI manifest
  locks their key/value sizes and field offsets to Go's encoders.
- `VERDICT` is keyed by bank, object ID, label, operation, relation, and target
  kind; `NOMATCH` omits only the object and relation. M2 uses the one
  `UNIDENTIFIED` label, while the daemon keeps the M1 pid+executable bypass.
  Process labels and a label map remain M3 work.
- The compiler calls `DecisionSnapshot.DecideOperation` and the existing
  no-match default helper; it does not reimplement Filemaster matching. It
  materializes scope roots, rule bases, and current single-segment glob matches.
  Future glob matches, missing rule inodes, and sentinel-matching rules are
  pattern-only degraded warnings. Mount/reconcile re-publication is M5 work.
- A new generation receives its initial complete table before it is pinned and
  before older generations are swept. A failed publication leaves the active
  bank unchanged. Audit converts deny to allow and increments a per-operation
  counter; enforce returns `-EPERM`.
- `RENAME_EXCHANGE` evaluates both directions and requires both to allow. The
  v6.12 and v7.1 `fs/namei.c` sources invoke `security_inode_rename` once with
  exchange flags, so the second direction is evaluated in BPF rather than
  assumed to arrive as another hook invocation.

**As built in the M2 fix-up:**

The precomputed `VERDICT`/sentinel table above was replaced wholesale, because a
sentinel-based synthetic-path scheme cannot express `filepath.Match` globs (a
class matches `/`), names that do not exist yet, or nested mounts. The as-built
design is §2.4 "as-built": full-path reconstruction in the kernel plus a faithful
`filepath.Match` port over a Go-tokenized program, with all walk/matcher state in
a per-CPU `EVAL` map value for verifier convergence. Corrections to the notes
above:

- The maps are now `OBJECTS` (hash → `ObjectValue`), `CONTEXTS`, `PATTERNS`,
  `CHUNKS`, `TOKENS`, `RANGES`, `ARENA` (per-bank string arenas), `NOMATCH`
  (profile default by bank/operation/kind), `AUDIT` (per-CPU would-deny), and
  `COUNTERS` (per-CPU undecidable cases by reason × hook). `SETTINGS` is
  unchanged. There is no `VERDICT` table and no `SELF`/`PENDING` labels.
- The exchange double-call is **verified from source** in `security/security.c`
  (not `fs/namei.c`), on v6.12.107 and v7.1.9: `inode_rename` has four arguments
  and no flags, and the hook is called twice for `RENAME_EXCHANGE`. M2's earlier
  "once with exchange flags" claim was wrong.
- The compiler still delegates verdicts to `DecisionSnapshot.DecideOperation`
  semantics, but the kernel now matches names itself, so there are no
  glob-future-match / rule-no-existing-inode / glob-matches-sentinel warnings. A
  rule on a not-yet-existing path just works once created, with no re-publish.
- Mount-change re-publication is done (mountinfo `POLLPRI`), not deferred.
- Cases that are denied-or-counted rather than decided exactly: walk depth > 4096
  (deny), path longer than the buffer (deny), per-context rule/scope overflow
  (deny), evaluation step-budget exhaustion (deny), unregistered filesystem root
  (not covered), and unreadable kernel value (fail open). All are counted in
  `COUNTERS` and surfaced in diagnostics; a non-zero unreadable count is a
  warning.
- Per-hook verifier cost (verified instructions; largest single stack frame):
  Debian 6.12 — unlink 75 474 / 160 B, rmdir 75 377 / 160 B, mkdir 77 326 /
  144 B, link 185 110 / 208 B, rename 333 273 / 192 B. Arch 7.1 — unlink
  70 548 / 160 B, rmdir 70 448 / 160 B, mkdir 69 269 / 144 B, link 209 281 /
  208 B, rename 297 771 / 192 B. The matcher test object verifies at 2 136
  (6.12) / 2 688 (7.1) instructions.

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

**As built in M3:**

Kernel rule lookup is now per-label. A **label** is a daemon-assigned profile
number stable for the daemon's lifetime (0 = the unidentified profile). Labels
map to **policies** — the de-duplicated rule sets — so a profile edit
re-publishes a policy without relabelling live processes, and equal-ruled
profiles share one policy. The matcher's context/rule split changed to keep the
M2 verifier budget: a `Context` keeps only the path and watch scopes; its rules
moved into `RULELISTS`, and `POLICY_LISTS[(bank, policy, context)]` selects one
list. The M2 matcher state machine is unchanged apart from fetching the active
policy's list per context, so its convergence (and budget) survives — re-measured
below. `NOMATCH` is now keyed by `(bank, policy, operation, kind)`.

- **Maps.** `PROCS` (HASH `tgid → {start_boottime, seq, span, label}`),
  `RESOLVED` (HASH `tgid → {start, seq, label}`, daemon-written), `EXEC_LABELS`
  (HASH `{exe(dev,ino,gen), script(dev,ino,gen)} → label`, the `EXE_LABEL`/
  `SCRIPT_LABEL` fast path), `EXEC_SCRATCH` (LRU `binprm → first-pass file`),
  `LABEL_POLICY` (per-bank array `label → policy`), `POLICY_LISTS`, `RULELISTS`,
  `RECORDS` (ring buffer), `RECORD_BUF` (per-CPU assembly), `LABEL_COUNTERS`
  (per-CPU: map-full, record-drop, unreadable). `SETTINGS` moved here and now
  carries the daemon's `(tgid, start_boottime, span)` self-bypass, replacing the
  M1 pid+exe record; `span` is one clock tick, because `/proc` start times are
  tick-granular.
- **HASH + exit cleanup, not task storage (§2.6 revisited).** The M2 fix-up
  added BTF to the object, so task-local storage is no longer blocked by missing
  BTF. It was still rejected: (1) task storage is per-thread, but a label is a
  per-thread-group property, so it would need the group leader's storage plus a
  lookup on every hook; (2) it has no "map full → deny" semantics — allocation
  failures silently fall back, which would turn a labelled process unlabelled
  without a signal; and (3) aya-ebpf 0.1.1 ships no task-storage map type, and
  `bpf_local_storage_map_alloc_check` (verified in both kernel sources) requires
  BTF key/value type ids the daemon would have to synthesise. A plain `HASH`
  keyed by tgid with `sched_process_exit` cleanup (group leader only, detected by
  `signal->live == 0`) gives exact control, a real full-map deny, and one lookup.
- **Hook order (verified against v6.12.107 and v7.1.9 sources, not assumed).**
  `sched_process_fork` fires after `copy_process` sets `start_boottime` and
  before `wake_up_new_task`, so the child's key is valid. `bprm_check_security`
  runs once per binfmt pass inside `search_binary_handler`; the first pass is
  detected by `bprm->interp == bprm->filename`, and its file is the script when a
  later pass substitutes an interpreter. `bprm_committed_creds` runs inside
  `begin_new_exec`, *before* `load_elf_binary` sets `mm->arg_start`, so argv/envp
  are **not** captured there; the recompute and the argv/envp `bpf_probe_read_user`
  happen at `tp_btf/sched_process_exec`, which fires at the end of `exec_binprm`
  after `load_binary` and before the new program runs. `sched_process_exit` is
  `TP_PROTO(p)` on 6.12 and `TP_PROTO(p, group_dead)` on 7.1; only arg 0 is read,
  so one program fits both, and group death is read from `signal->live`.
- **PENDING flow.** Recompute at exec: `EXE_LABELS{exe, 0}` (fast path, no gap) →
  a carried script's `EXE_LABELS{exe, script}` → otherwise `PENDING`. A pending
  or unlabelled caller uses policy 0 (the pending policy: every label's rules as
  denies plus every scope under a deny default), so structural ops deny with a
  counted reason (`label-pending` / `unlabelled`). The daemon learns the exe-only
  fast path only for non-interpreters without cmdline/env/tag fingerprints, so
  distinct scripts under one interpreter never collapse onto one label.
- **Script-open path.** A minimal pre-decide hook in the fanotify open path
  (`DecisionPipeline.SetBeforeOpen`, invoked only for `OpOpen`) lets the labeller
  resolve a still-pending opener before the open is answered, so a script an
  interpreter is about to run is labelled before it runs. The exec-record argv
  path already names the script for `python a.py`, `-m`, `-c` and env-shebang
  interpreters, so this hook is the backstop for the resolution window.
- **Core (non-BPF) files touched.** `service/process/process.go` (the pre-captured
  cmdline/env override at the boundary of the ported `loadProcess` block, behind
  the new `service/process/identity_capture.go`) and
  `service/fileaccess/decision_pipeline.go` (the `beforeOpen` open hook). Both are
  the two boundaries §2.6 names; the ported `loadProcess` logic is unchanged and
  falls back to `/proc` when no capture is registered.
- **Verifier cost (verified instructions / largest single stack frame).**
  Arch 7.1 — unlink 31 565 / 24+200+64+40+72, rmdir 31 315, mkdir 15 645 /
  176+64+40+72, link 254 796 / 240+…, rename 149 609 / 240+…, bprm_check 145 / 40,
  fork 240 / 64, exec 909 / 168, exit 187 / 16. Debian 6.12 — unlink 43 667,
  rmdir 43 409, mkdir 14 623, link 95 874, rename 97 535, bprm_check 148, fork
  258, exec 959, exit 189. All well under the 1,000,000-instruction limit.
  (The structural counts shifted from the M2 fix-up because rules moved behind a
  per-context `POLICY_LISTS` lookup; both kernels still verify.)
- **Known gaps.** An interpreter invocation (`python a.py`, `-m`, `-c`,
  env-shebang) is never learned as an exe-only fast path, so every such exec
  emits a record and has a brief pending window the open hook closes for watched
  mounts; a short-lived interpreter that mutates before resolution and outside a
  watched mount denies (the documented PENDING fallback). argv-rewrite immunity
  comes from capturing argv at `sched_process_exec` before user code; a later
  `prctl(PR_SET_MM_*)` cannot retrigger it. The btrfs subvolume identity
  collision (risk 7) is still deferred to M5. UI exposure of labels and the deny
  notice are M4.

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
"test before commit"), on both of the VM's kernels, stock Arch `7.1.9-arch1-2`
and Debian 13's `6.12.107+deb13-amd64` (the dev host's kernel), using both
tmpfs and btrfs. The stock Arch 7.1 kernel ships BPF LSM
active, BTF and fanotify permission events, so the patched
`7.1.0-filemaster-p1` kernel (built only for the kernel-hook prompt
experiment) is not needed for this plan.

M1 exit evidence: the `bpflsm` load and lifecycle tests passed on 6.18 and
on 7.1, both `7.1.0-filemaster-p1` and stock Arch, on tmpfs and btrfs
(lifecycle 20/20 runs after the detach fix), and the daemon checks (enable,
SIGKILL, restart, off at startup and live) passed on 6.18 and stock Arch 7.1.
The load, lifecycle and startup daemon checks also passed on Debian 6.12
(6.18-lts has since been replaced by it in the VM).

| # | Slice | Exit test (observed in VM) | Sessions |
|---|---|---|---:|
| M0 | Vendor the crates with port headers and the licence; apply the gate patch; strip blessing/open/exec; Makefile `bpf` target, `go:embed`, `test-fake` stub | `make core` embeds the object; a Go test loads every program through the verifier on both kernels | 0.5 |
| M1 ✅ | Loader, probe, `.rodata` offsets, attach, pin generations, handover, self-test, teardown, mode option, degraded warnings | Enable → 5 hooks attached and shown in diagnostics; SIGKILL → enforcement persists; restart → generation swap with no gap; `off` → detached and reported unprotected | 1.5 |
| M2 ✅ (fixed up) | Full-path kernel matcher (`matcher.rs`, faithful `filepath.Match` port over a Go-tokenized program, all state in a per-CPU `EVAL` map) + Go compiler with mount-root objects and per-path contexts + banked publish + ABI manifest test; single label `UNIDENTIFIED` | Observed on Arch 7.1 and Debian 6.12, tmpfs and btrfs: Gate B matched ≥11 k generated `(pattern, path)` pairs against `filepath.Match` with zero mismatches; the generated-rule differential (8 seeds × 505 ops, ~60% expected denies) agrees with `DecideOperation`/`DecideRename`/`DecideHardLink` across the operation matrix — folder renames, `DestExists`, `RENAME_EXCHANGE`/`RENAME_NOREPLACE`, `*at()` callers, >100-deep paths, post-publish creations, and a tmpfs mounted inside a scope with re-publish — with zero mismatches; self-test, lifecycle, handover and live-daemon (enforce/SIGKILL-persist/restart/off) all pass | 2–2.5 |
| M3 ✅ | Labelling: fork/exec/exit programs, argv/envp capture, `EXE_LABEL`/`SCRIPT_LABEL`, `process` boundary override, script-open labelling, `PENDING` deny, `(tgid, start_time)` self-bypass, `/proc` seeding, per-label kernel rule lookup | Observed on Arch 7.1 and Debian 6.12, tmpfs and btrfs: `python a.py` (allow) vs `python b.py` (deny) get distinct verdicts; `./x.py`, `./s.sh`, `./s.js`, `./s.pl` env-shebang scripts labelled by their script arg; `python -m fmmod` resolves to the module profile and `python -c` to the interpreter profile; a child `rm` spawned by a deny-profile script gets `rm`'s allow label; an unresolved process stays `PENDING` and denies; a fork storm against an 8-entry label map denies and increments the map-full counter; argv rewrite after start does not change the label. No regressions: self-test, lifecycle, handover, the Gate B/differential (8×505, 0 mismatches) and live-daemon enforce/off all pass on both kernels and filesystems | 2–2.5 |
| M4 | Events → filequery, deny notification with Allow-and-retry, Write list active in rule model and UI | Monitor shows delete/rename/link records; the notification appears; Allow → retry succeeds; screenshots of dashboard/monitor/settings checked per CLAUDE.md | 1.5–2 |
| M5 | Hardening matrix (§4) and fixes; **btrfs subvolume/snapshot identity** (risk 7) — key objects by a subvolume-aware id, not just `(s_dev, ino)` | §4 matrix green; coverage warnings correct for every injected failure; multi-subvolume btrfs no longer collides objects | 1–1.5 |
| | **Total** | | **8.5–11.5** |

## 4. Test plan

**VM matrix.** Kernels: Arch 7.1 and Debian 6.12 (`vmctl kernel linux` /
`vmctl kernel linux-debian`). Develop and iterate on Arch 7.1, the VM
default. Run the full matrix on Debian 6.12 as well once per milestone,
before its commit; any 6.12-only verifier failure blocks the commit like any
other failure. Filesystems:

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

1. **The kernel matcher diverges from the Go engine on some rule shape.**
   - *Detect:* M2's generated-rule differential test (kernel syscalls vs
     `DecideOperation`/`DecideRename`/`DecideHardLink`) and the Gate B matcher
     differential (≥10 k generated `(pattern, path)` pairs vs `filepath.Match`),
     both on each kernel.
   - *Resolved as built:* the kernel rebuilds the full path and runs a faithful
     `filepath.Match` port over a Go-tokenized program, so there are no
     excluded-shape degradations; a pattern `filepath.Match` rejects is left out
     (it never matches). The only "can't decide exactly" cases are the counted
     ones in §2.4 (walk depth, path too long, context overflow, step budget,
     unregistered root, unreadable value).
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
7. **btrfs subvolume identity collision (DEFERRED, M5).** Objects are keyed by
   `(mountinfo s_dev, ino)`. That pair is **not** unique across btrfs
   subvolumes and snapshots: every subvolume root is inode 256, and a snapshot
   repeats the inode numbers (and generations) of its source. Two different
   files in two subvolumes of one filesystem can therefore collide on
   `(s_dev, ino)` and share an object, so a rule on one would wrongly apply to
   the other. This work does not address it (test runs use a single subvolume);
   a correct key needs the btrfs subvolume/root id (e.g. via `ino_lookup` or the
   subvol id the kernel exposes), which is M5. Until then, multi-subvolume
   btrfs coverage is unsound and must be documented as such.

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
