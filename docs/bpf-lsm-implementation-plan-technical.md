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

**Objects** are keyed by `(mountinfo s_dev, ino, subvolume)` — the superblock
device comes from `/proc/self/mountinfo` via `statx`'s `STATX_MNT_ID`, never
`stat`'s `st_dev` (btrfs minors differ), and the subvolume is the btrfs root
objectid (`STATX_SUBVOL`), 0 on every other filesystem (see "As built in M5:
subvolume-aware object identity" in §2.6). The object set is: every watch
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
than multi-word tuples (which otherwise spill through an invalid `r11`). The
per-CPU state is **not** private to one hook: hooks are preemptible, so each
decision claims one of the CPU's `STATE_SLOTS` decision states for itself (see
"As built: the per-CPU state race" and "As built in M5: claimed decision
states" in §2.6).

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
  are **not** captured there; the argv/envp `bpf_probe_read_user` happens at
  `tp_btf/sched_process_exec`, which fires at the end of `exec_binprm` after
  `load_binary` and before the new program runs. (The recompute itself moved to
  `bprm_committed_creds` with the race fix, below.) `sched_process_exit` is
  `TP_PROTO(p)` on 6.12 and `TP_PROTO(p, group_dead)` on 7.1; only arg 0 is read,
  so one program fits both, and group death is read from `signal->live`.
- **PENDING flow.** Recompute at exec: `EXE_LABELS{exe, 0}` (fast path, no gap) →
  a carried script's `EXE_LABELS{exe, script}` → otherwise `PENDING`. A pending
  or unlabelled caller uses policy 0 (the pending policy: every label's rules as
  denies plus every scope under a deny default), so structural ops deny with a
  counted reason (`label-pending` / `unlabelled`). The daemon learns the exe-only
  fast path only for non-interpreters without cmdline/env/tag fingerprints, so
  distinct scripts under one interpreter never collapse onto one label. (Since
  narrowed: see "Narrowed PENDING and the label wait" below.)
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
  falls back to `/proc` when no capture is registered. The live follow-up added
  `service/fileaccess/process_tags.go`, a blank import restoring the process tag
  handlers (see FORK_NOTES): upstream registers them from the deleted
  `service/network/connection.go`, so filemaster had never tagged an interpreter
  script, AppImage, Flatpak or Snap process.
- **Daemon labeller (as fixed by the live run).** A record's process is
  resolved through `GetProcessWithProfile` with the captured argv/envp; one that
  already exited is identified from the record alone (the kernel now records the
  loaded binary's path, `bprm->interp`, checked against the recorded inode), so
  a short-lived binary is still learned. A label's policy is published before
  the label is written (`ensurePublished`), and `/proc` seeding resolves all
  processes, then publishes once. Seeding runs for every new generation,
  including a live off → enforce switch. Interpreters are detected with the
  ported interpreter tag handler on a probe file, so `python -c` is never learned
  exe-only. Learned exec labels survive republishes and are dropped only when a
  fingerprint that could decide a learned path changes (a digest over prefix,
  regex, cmdline and env fingerprints plus the equals fingerprints naming learned
  paths); exe-only learning was off while any profile matched on cmdline or
  env (narrowed since, below). Note that the daemon renames a profile to its
  fingerprint-derived ID.
- **Live evidence (real daemon, `cmds/bpflsm-live`).** The tool starts
  `filemaster-core`, creates profiles through the database websocket API,
  switches to enforce live, and checks unlinks by real processes in the watched
  scope. Passed on Arch 7.1 and Debian 6.12, with the scope on btrfs and on tmpfs:
  `python3 a.py` (allow profile) vs `python3 b.py` (deny); `./x.py`
  (`#!/usr/bin/python3`), `./s.pl` and `./s.sh` scripts; `python3 -c` → the
  interpreter profile; a deny-profile script's child `rm` deletes under `rm`'s own
  allow profile; editing `b.py`'s rules through the API flips its verdict for the
  next run in about 50–90 ms without a restart; with cmdline profiles, bare
  `python3 a2.py`/`b2.py`, an env-shebang `./x2.py` and `python3 -m fmmod` resolve
  to their own profiles.
- **PENDING window (enforce, allow profile, unlink as the first action, 50 runs
  each).** A Python script outside every watched mount: 50/50 allowed on both
  kernels and filesystems, with no pending denials — interpreter start-up outlasts
  resolution. The same script inside the watched scope: 50/50 (one run of 300 was
  denied as pending on 7.1 tmpfs). Spawn → label latency: median about 9–11 ms,
  p90 10–13 ms, max 11–24 ms. The worst case is the first exec of a never-seen
  native binary (a fresh `rm` copy outside watched mounts): 0/50 allowed, all 50
  counted as `label-pending`; its next exec is labelled at once from the learned
  label.
- **Verifier cost (verified instructions / largest single stack frame).**
  Arch 7.1 — unlink 31 565 / 24+200+64+40+72, rmdir 31 315, mkdir 15 645 /
  176+64+40+72, link 254 796 / 240+…, rename 149 609 / 240+…, bprm_check 145 / 40,
  fork 243 / 64, exec 1 295 / 184, exit 187 / 16. Debian 6.12 — unlink 43 667,
  rmdir 43 409, mkdir 14 623, link 95 874, rename 97 535, bprm_check 148, fork
  261, exec 1 311, exit 189. All well under the 1,000,000-instruction limit.
  (The structural counts shifted from the M2 fix-up because rules moved behind a
  per-context `POLICY_LISTS` lookup; both kernels still verify.)
- **Known gaps.** An interpreter invocation (`python a.py`, `-m`, `-c`,
  env-shebang) is never learned exe-only, so every such exec emits a record and
  is pending for about 10 ms; the first exec of any new native binary that
  mutates at once is denied (measured above). The ported interpreter tag handler
  tags a script only when argv[0] is the interpreter's absolute path, so a bare
  `python3 a.py` or an env shebang is told apart only by cmdline fingerprints, and
  any cmdline/env profile turns exe-only learning off for every binary. Exec
  labels learned before a newly *created* (not yet active) profile are kept until
  a fingerprint change event. argv-rewrite immunity comes from capturing argv at
  `sched_process_exec` before user code. The btrfs subvolume identity collision
  (risk 7) was deferred to M5 (resolved in M5 stage 2); UI exposure of labels
  and the deny notice are M4.

**As built in M3: narrowed PENDING and the label wait.**

The measured M3 problem: any profile with a cmdline or env fingerprint turned
exe-only learning off for every binary, so every native exec was pending and an
immediate `rm`/`mv` in a watched scope was denied about half the time; without
such profiles a never-seen binary's first execs were denied (0/50 above). Two
changes fix it.

- **Narrowed PENDING (`service/fileaccess/exec_learning.go`).** Exe-only learning
  stays on for every native, non-interpreter executable that no fingerprint could
  claim. For an untagged process, profile resolution depends only on its exe path
  (fixed) and its command line and environment (variable), so: an **env**
  fingerprint can match any process and turns learning off (diagnostics say so:
  `Structural.Labelling.ExeLearning`); a **cmdline** fingerprint matches only
  command lines starting with some argv[0] — the captured command line is argv
  joined by single spaces, unquoted (`setCapture`, `splitNUL`) — so its literal
  prefix is worked out (equals/prefix directly; regex via `regexp/syntax`: it must
  be `\A`-anchored, literal runs, small classes, case folds and alternations
  expand to at most 64 literals, and it counts as a whole command line only if
  `$`-anchored). Every argv[0] up to a space in the literal is claimed exactly;
  the rest as a prefix. A bare argv[0] claims executables of that base name, an
  absolute one the file it resolves to, a relative one its base name; symlinks in
  the standard command directories and the daemon's `PATH` that a claimed name
  resolves through are followed (`vi` → `vim`). An unanchored or relative-path
  prefix (e.g. `/a2\.py `, `.*foo`, `^\./r`) turns learning off. **Prefix and regex
  path** fingerprints are evaluated directly on the exe path (exact, so no
  literal-prefix approximation is needed) and keep matching paths pending, as do
  the tag-claimable paths (interpreters, `/app/`, `/snap/`, `/tmp/.mount_*`).
  Unknown executables stay pending in the kernel as before; the daemon simply
  refuses to learn claimed ones. Exactness is checked by
  `TestExecLearningDifferential`: 3,000 generated fingerprint sets × 8 exes
  (with symlink aliases) × argv[0] forms (path, base name, `./name`, alias path
  and name) × argument tails × environments; whenever learning is allowed,
  `MatchFingerprints` resolution (highest score, first of equals) gives one
  profile for every combination — 9,531 learnable / 14,469 refused pairs, about
  1.09 M agreeing resolutions; it fails when the alias walk or the absolute-path
  claim is removed. **Caveat (as upstream Portmaster):** argv[0] is caller-chosen,
  so a disguised argv[0] (or a symlink outside the searched directories, or an
  invocation through a relative directory whose name matches a cmdline prefix)
  can make the daemon resolve a cmdline profile the exe's label does not follow;
  for a learned exe the kernel label follows the exe. Likewise a caller-set
  `APPIMAGE`/`APPDIR`/`SNAP` environment that tags an ordinary binary is not
  anticipated.
- **Bounded label wait (`label.rs` `wait_resolved`, `decide.rs` `with_wait`,
  `bpflsm/wait.go`).** A structural hook first decides as before. If that denies
  because the caller is pending (`label-pending`), it spins once in a `bpf_loop`
  polling `PROCS`/`RESOLVED` with a `bpf_ktime_get_ns` deadline (`WAIT_CAP_NS` =
  50 ms), then decides the **whole** operation again with the resolved label —
  again, because the daemon may have flipped the active bank to publish the new
  label's policy, which also invalidates the first walks. A timeout denies (fail
  closed) under its own reason, `label-wait-timeout`. Rename and link wait at
  most once. Only enforce waits: audit never adds latency, so a pending caller's
  would-deny is recorded at once as `label-pending` (owner decision; see "As
  built: the per-CPU state race", below). The
  wait is skipped (immediate deny) when: the `WAIT` map's `enabled` is off; the
  daemon's heartbeat (CLOCK_MONOTONIC, rewritten every second with the online-CPU
  cap) is older than 3 s; or `WAITERS` (a global atomic count: add, read back,
  read first and skip if full, else fetch-add and undo if the count before the
  add was full — a spinner's add always saw fewer than the cap, so at most the
  cap spin, while the count can pass it for the instant before an undo; no path
  leaks a claim, verified back at 0 after every burst) already holds
  `max_waiters` = online CPUs − 1 (0 on one CPU). (A compare-and-swap would keep
  the count itself under the cap, but bpf-linker 0.11 cannot read the bitcode
  rustc emits for `cmpxchg`: "Invalid br record".) Counters: `LABEL_COUNTERS`
  slots 3–8 (waits, resolved, timed out, skipped stale, skipped busy, waited ns).
  **Self-test, per generation:** the daemon makes itself a pending caller in a
  private tmpfs, unlinks a pending-denied file on one thread and resolves its
  label 5 ms later from a second thread pinned to the **same CPU**; only a
  preemptible spinner lets the resolver run. Pass → wait enabled; a timed-out
  wait → off with the diagnostics warning `bpf-lsm-label-wait-unavailable`
  ("Label wait unavailable: kernel preemption mode does not allow it").
  **Config:** `fileaccess/structuralLabelWait` (bool, default on), applied live
  through the heartbeat; diagnostics show `Labelling.Wait.State`: `on`,
  `off: disabled by configuration`, `off: kernel preemption mode does not allow
  it`, `off: only one CPU is online`.
- **Verifier budget.** Deciding twice in-line tripled `inode_link` to 814 k
  instructions on 7.1. The matcher run is now a **global** BPF function
  (`filemaster_evaluate`, BTF linkage global), which the verifier checks once per
  program instead of once per call, so the doubled decisions cost less than M3:
  Arch 7.1 — unlink 19 004, rmdir 18 700, mkdir 17 977, link 116 975, rename
  79 302; Debian 6.12 — unlink 24 848, rmdir 24 331, mkdir 22 967, link 182 370,
  rename 131 585 (labelling programs unchanged; stacks unchanged at 272 B for the
  largest frame). Everything is far under the 1,000,000 limit.
- **Measured (real daemon, `bpflsm-live` wait matrix, 50 runs each, 8 vCPUs).**
  Arch 7.1 (preempt full), btrfs and tmpfs scopes: (a) no cmdline/env profile —
  system `rm`/`mv` 50/50 allowed, 0 waits; fresh copies 47–50/50 allowed, wait
  median 25–31 ms, p90 32–37 ms (a never-seen exe is a new profile whose label
  publish recompiles the table); (b) an unrelated `^python3 -c` profile — system
  `rm`/`mv` 50/50, **0 waits**; fresh copies 44–50/50 (timeouts at the 50 ms cap,
  median 36–41 ms); (c) a cmdline profile for `rm` (`^rm --interactive=never `,
  deny) beside the `rm` path profile (allow) — `rm -f` 50/50 allowed and
  `rm --interactive=never` 0/50, every run waiting, median 3.4–4.9 ms, p90
  5.0–6.9 ms, max ≤ 9.2 ms; `mv` unclaimed, 0 waits; (d) an env profile — all
  pending, `rm`/`mv` 50/50 after waits (median 3–5 ms), `FM_LIVE_DENY=1 rm` 0/50;
  a burst of 32 pending `rm` at once: peak waiters 7 = cap, 14–15 waited (2
  resolved, the rest timed out: the single resolver goroutine with one free CPU
  cannot label 32 processes in 50 ms), 17–18 skipped busy, all done in ~120 ms,
  `WAITERS` back to 0; (e) wait off by config — (c)/(d) deny at once, 0 waits;
  back on — 47–50/50 (up to 3 timeouts); (f) daemon SIGKILLed — for the first ~3 s each
  pending `rm` waits out the cap and is denied; after the heartbeat goes stale
  every one is denied at once (rm runs 2.6–3.0 ms median), counted as skipped
  stale. The M3 PENDING-window case "first exec of a new native binary" went from
  0/50 to 50/50 allowed. **Debian 6.12 default (`preempt=voluntary`):** the
  self-test reports `off: kernel preemption mode does not allow it` and the
  `bpf-lsm-label-wait-unavailable` warning is raised; narrowed PENDING still
  helps — (a)/(b) system `rm`/`mv` 50/50 allowed with no wait, (c) `mv` 50/50 —
  while every still-pending case denies as in M3 (fresh copies, (c) `rm`, (d)
  0/50). With `preempt=full` set through `/sys/kernel/debug/sched/preempt`, a
  new generation's self-test passes and the matrix matches Arch: (c) 50/50 and
  0/50 with waits median 3.9 ms, (d) median 3–4 ms, burst peak 7 = cap, (e) and
  (f) as on Arch. Both kernels pass the full regression set again: the exit
  tests, map-full, lifecycle, handover, the differential (8 × 505, 0 mismatches),
  live enforce/off and the M3 live test on btrfs and tmpfs.
- **Known gaps.** The 50 ms cap can be outlasted by a never-seen executable's
  first resolution (profile creation plus table publish) and by bursts larger
  than the resolver's throughput; both fail closed. The spinner holds the
  parent directory's `i_rwsem`; inferred from the lock order, not observed, a
  daemon resolution that must look up a path in that same directory (e.g. a
  fresh binary deleting next to itself) would block until the cap. Exe-only learning remains unsound against disguised argv[0]
  (caveat above). The per-CPU state race found here is fixed in the next
  section.

**As built: the per-CPU state race.**

The structural programs kept their walk and matcher state in per-CPU maps
(`SCRATCH`, `EVAL`) on the assumption that they could not be preempted. That
was wrong. Verified in the v6.12.107 and v7.1.9 sources: an LSM program enters
through `__bpf_prog_enter`, which takes only `rcu_read_lock()` and
`migrate_disable()` (`rcu_read_lock_dont_migrate()` on 7.1), and
`bpf_prog_check_recur` is false for LSM programs, so there is no recursion guard
either. With `PREEMPT_RCU` (both test kernels) and full or lazy preemption
(Arch's default; Debian's with `preempt=full`), task A's hook can be preempted
mid-evaluation, task B's hook runs on the same CPU and overwrites A's state, and
A resumes with B's verdict.

- **Reproduced before the fix** by `TestStructuralBPFContention`
  (`service/fileaccess/structural_contention_linux_test.go`): 17 threads pinned
  to CPU 0 — 10 `SCHED_OTHER` workers at mixed nice values, 4 `SCHED_FIFO`
  threads that wake every 0.2–2 ms and mutate, 3 `sched_yield` loops — each
  mutating its own allow or deny folder 40 levels deep, behind 100 non-matching
  glob rules that share the whole path prefix (so one evaluation takes about a
  millisecond), with unlink, mkdir/rmdir, rename and hard link checked against
  `DecideOperation`/`DecideRename`/`DecideHardLink`. With the previous
  object, 30 s each: Arch 7.1 — 8,422 operations, **311 allowed against a deny
  reference, 375 denied against an allow reference**; Debian 6.12 with
  `preempt=full` — 9,203 operations, **372 and 412**; Debian 6.12 default
  (`preempt=voluntary`, no kernel preemption) — 8,639 operations, 0 and 0.
- **The fix (`decide.rs`; its sequence ticket is replaced in M5, below).** Each decision is a global BPF function
  (`filemaster_remove`, `filemaster_mkdir`, `filemaster_hard_link`,
  `filemaster_rename`) wrapped in `owned`: it takes a ticket by atomically
  incrementing this CPU's `STATE_SEQUENCE` before its first walk, runs the whole
  operation (walks plus every evaluation), packs the verdict into a returned
  `u64`, and re-reads the sequence; a changed sequence means another hook used
  the state, and the attempt reports contention. The hook retries up to 4 times,
  then denies (fail closed; audit records it and allows) under a new counted
  reason, `state-contention` (`REASON_STATE_CONTENTION`, diagnostics warning
  `bpf-lsm-undecided-state-contention`). The increment must be atomic: with a
  plain read-modify-write, two interleaved hooks could take the same ticket. It
  covers all five hooks, every evaluation inside rename and link, and the
  re-decision after a label wait (each is a fresh owned decision). Making the
  decisions global functions keeps the retries cheap for the verifier, and a
  global function only takes scalars, so hook arguments are now probe-read from
  the context instead of loaded as BTF pointers. `bpf_preempt_disable` was not
  an option: the 6.12 verifier rejects global function calls with preemption
  disabled, and the label wait must stay preemptible.
- **Counters.** `COUNTERS`, `AUDIT` and `LABEL_COUNTERS` were per-CPU plain
  read-modify-writes, which lose counts when preempted between read and write;
  they are now atomic adds.
- **Labelling programs (found while checking every per-CPU buffer).** On 7.1,
  tracepoints run under SRCU instead of with preemption disabled
  (`__DECLARE_TRACE`: `guard(srcu_fast_notrace)`; 6.12 still calls
  `preempt_disable_notrace()`), so the `tp_btf` programs are preemptible there,
  and `__bpf_trace_run` skips a program that is already running on that CPU (a
  per-CPU recursion counter; the skip only increments the program's
  `recursion_misses`). Two consequences, both fixed:
  1. `RECORD_BUF` was shared by the fork and exec programs; it now has one slot
     per program, and the recursion guard keeps each program's own slot
     unshared.
  2. A skipped `sched_process_exec` left the child the label fork had copied
     from its parent — **fail open**. `TestLabelExecUnderContention`
     (`bpflsm/label_contention_linux_test.go`) shows it: an allow-labelled shell
     on CPU 0 execs a never-seen `rm` copy 3,000 times next to 8 processes
     exec'ing with 24 KiB of argv/envp; every delete must be denied as pending.
     Before (Arch 7.1): **50 of 3,000 deletes allowed**, 3,359
     `sched_process_exec` recursion misses. Debian 6.12 had 0 misses, voluntary
     or full, as its tracepoints disable preemption. The relabel now happens in a new LSM program on
     `bprm_committed_creds` (no recursion guard; runs after `de_thread`,
     `set_mm_exe_file` and `exec_mmap`, verified in both `fs/exec.c` sources),
     and `sched_process_exec` only emits the pending record. A skipped exec
     program now leaves the process pending without a record, which denies.
     After: 0 of 3,000 allowed (3,902 misses). A skipped fork program leaves the
     child unlabelled (denied) and a skipped exit program leaks one `PROCS`
     entry until its tgid is reused; both fail closed.
- **Audit never waits (owner decision).** The label wait applies only in
  enforce. In audit, a pending caller's would-deny is counted as `label-pending`
  and the operation proceeds at once; `TestLabelWait` checks 5 pending audit
  `rm`s: allowed, none waited, `label-pending` and would-deny delete +5 each (a
  build that still waits in audit fails it at about 52 ms per `rm`).
- **Results after the fix.** The contention test passes when nothing is
  allowed against a deny reference and every denial against an allow reference
  is covered by a counted `state-contention` denial. Arch 7.1: 7,947 operations,
  0 allowed wrongly, 112 contention denials of allowed operations (261
  `state-contention` in all, about 3% under this deliberately extreme load of
  millisecond evaluations interrupted every 0.2–2 ms); Debian 6.12
  `preempt=full`: 8,578 operations, 0, 104 (261); Debian voluntary: 8,575
  operations, 0, 0 (0). The exec test: 0 of 3,000 deletes allowed on Arch and on
  Debian (voluntary; 0 of 1,000 with `preempt=full`). `TestLabelWait` (with the
  audit case) passes on Arch and on Debian `preempt=full` (on voluntary the
  wait is off, as before). The full regression set passes on both kernels: the
  `bpflsm` suite (exit tests, map-full, lifecycle, handover), the differential
  (8 × 505, 0 mismatches), live enforce/off, and `bpflsm-live` on btrfs and
  tmpfs (wait matrix as measured above).
- **Verifier cost (verified instructions).** The decisions are now global
  functions verified once per program, so the counts dropped: Arch 7.1 —
  unlink 6 025, rmdir 6 054, mkdir 5 846, link 10 543, rename 13 252,
  bprm_check 143, bprm_committed_creds 395, fork 232, exec 1 247, exit 205;
  Debian 6.12 — unlink 6 114, rmdir 6 153, mkdir 5 854, link 11 820, rename
  16 148, bprm_check 146, bprm_committed_creds 417, fork 273, exec 1 245, exit
  188. The largest single frame is 264 B.
- **Known limits (until M5).** Under sustained contention a decision could lose
  its state on all 4 attempts and deny; that is a local denial-of-service of structural
  operations on one CPU, never an allow. Events counted from a run that later
  lost its state (budget, overflow) can be over-counted.

**As built in M5: claimed decision states.**

The sequence ticket above detected a hook that *started* after mine, not one
that *wrote* after mine. Hook A takes ticket n+1 and is preempted; B takes
n+2 and is preempted; A resumes, writes the shared state and is preempted
before its check; B resumes, finishes on A's state, and its check passes (the
sequence is still n+2). A's last failed attempt also took no new ticket.

- **Reproduced before the fix.** `TestStructuralBPFContention` gained
  `FM_BPF_CONTENTION_PREEMPTORS` (default 4 SCHED_FIFO threads). On Arch 7.1
  with the M4 object: with 0 preemptors (10 SCHED_OTHER workers and 3
  yielders), 45 s, **3 allowed against a deny reference** in 10,243
  operations. With the default 4, the second of a series of 40 s runs had
  **2** (9,085 operations). An instrumented build (a randomized 4 ms spin
  before the sequence check) showed 2 in each of two 45 s runs. Debian 6.12
  `preempt=full`: one 45 s run with 0 preemptors had none (12,212
  operations).
- **Task-local storage was not workable.** The state a decision writes is about
  41 KiB (`SCRATCH` 2 × 20,480 B, plus `WALKS` and `EVAL`). On 7.1,
  `bpf_selem_alloc` allocates task-storage elements with
  `bpf_map_kmalloc_nolock`, and `kmalloc_nolock` returns NULL for any size above
  `KMALLOC_MAX_CACHE_SIZE` (8 KiB with 4 KiB pages; `mm/slub.c` v7.1.9), so
  every `bpf_task_storage_get(F_CREATE)` would fail. 6.12 takes elements from
  a per-CPU `bpf_mem_alloc` cache that irq_work refills (`memalloc.c`), so it
  would work there until a burst empties the cache. The 8,192-byte relative-path
  buffer alone exceeds the 7.1 limit, so task storage was dropped for both kernels.
- **The fix: claimed decision states (`decide.rs` `owned`,
  `filemaster_claim_state`).** `EVAL` has `STATE_SLOTS` = 8 entries per CPU,
  and `SCRATCH` and `WALKS` have two per state. Before its first walk, each
  decision claims a state through the per-CPU `STATE_CLAIMS` words. It skips
  non-zero words, and a claim succeeds when its atomic add returns 0. An add
  that saw a claimed word is undone. The decision then walks, evaluates, and
  records only in that state's entries, and releases the claim (atomic
  subtract) after its record is out. **Why this is sound:** an LSM program
  runs with migration disabled, so all of its per-CPU lookups resolve to one
  CPU. Only structural decisions on that CPU touch these entries, and the
  daemon never writes them. A word is non-zero while its owner holds it, so a
  second add cannot return 0 until the owner's release. Two decisions
  therefore never own one state, and a decision writes only to the state it
  owns. A stale writer is impossible, because a decision stops writing before it releases. Preemption
  at any point, including between an add and its undo, makes a free state look
  claimed only for a moment (fail closed). It cannot hand an owned state to a
  second decision. A program always runs to its end, so a claim is always
  released. A leaked claim would only shrink the pool. With no free state, the
  decision denies at once under `state-contention`, which now means "every
  decision state on this CPU is held by an interrupted decision"; audit counts
  it and allows. Retrying would not help, because nothing on this CPU releases
  while the hook runs. `STATE_SEQUENCE`, the 4-attempt retry loop, and the
  record's two sequence checks are gone, and a record is always copied from
  the walks that decided it. The claim is a global function (verified once).
  Inlining its loop cost about 1,000–9,000 extra verified instructions per
  hook.
- **Memory.** Per possible CPU: 8 × (2 × 20,480 + 2 × 56 + `EvalState`) ≈
  330 KiB, up from about 41 KiB. With 4 states (≈165 KiB), the stress test
  on Arch wrongly denied 8–12 % of operations with 4 preemptors and about 2 %
  with none. With 8, it denied 2–4 % with 4 preemptors and almost none with
  none (the old ticket: about 1.7 % with 4). Nothing is allocated per task or
  per decision.
- **Test harness hang (pre-existing, fixed).** Repeated stress runs hung the
  VM about once in 3–10 runs with 4 or 12 preemptors, with the M4 object too.
  The RCU stall (`P…/1:b..l`, `rcub/0` blocked) showed a worker preempted
  inside `eval_step` that never ran again while every SCHED_FIFO test thread
  stayed runnable on CPU 0 in user space (Go runtime). RCU boosting runs at
  FIFO priority 1, below the preemptors. Two causes in the test, both fixed:
  the FIFO threads unlocked their OS threads on exit and returned to the Go
  runtime still SCHED_FIFO on CPU 0; and a garbage collection's
  stop-the-world started on a FIFO thread spins waiting for goroutines whose
  CPU 0 threads it starves. The threads now exit locked (the runtime
  terminates them), and the test turns GC off while they run. With `GOGC=off`
  alone, 14 consecutive 30 s runs with 12 and 4 preemptors completed. The
  same starvation would stall RCU behind any FIFO hog. The claimed states
  neither cause nor change it.
- **Results.** The contention test passes when nothing is allowed against a
  deny reference and every wrong denial is covered by a counted
  `state-contention` denial.

  | Kernel | Preemptors | Operations | Wrong allows | Wrong denials | `state-contention` |
  |---|---:|---:|---:|---:|---:|
  | Arch 7.1 | 4 | 9,045 | 0 | 205 | 354 |
  | Arch 7.1 | 0 | 8,336 | 0 | 0 | 3 |
  | Arch 7.1 | 12 | 9,568 | 0 | 76 | 123 |
  | Debian 6.12, voluntary | 4 | 9,130 | 0 | 0 | 0 |
  | Debian 6.12, `preempt=full` | 4 | 9,198 | 0 | 349 | 622 |
  | Debian 6.12, `preempt=full` | 0 | 8,761 | 0 | 1 | 1 |
  | Debian 6.12, `preempt=full` | 12 | 9,627 | 0 | 191 | 538 |

  The Arch runs with 4 preemptors are from the full regression set. On Arch,
  14 further runs of 30 s, alternating 12 and 4 preemptors, had no wrong
  allows. Exec labelling stress: 3,000 execs with 0 deletes on Arch (4,409
  recursion misses) and on Debian voluntary, and 1,000 with 0 deletes on
  Debian `preempt=full`. `TestLabelWait` passed on Arch and on Debian
  `preempt=full`. The full regression set passed on both kernels: the
  `bpflsm` suite (exit tests, map-full, lifecycle, handover, self-test), the
  differential (8 × 505, 0 mismatches), live enforce/off, the M3/wait
  `bpflsm-live` matrix and the M4 matrix on btrfs and tmpfs. Both M4 bursts
  stayed within their budgets: 8,080–8,304 of 10,000 records were dropped,
  and the `suppressed` totals equalled the drops (for example, 18,144 of
  18,144). On Debian `preempt=full`, the M3/wait and M4 matrices passed on
  btrfs.

  Verified instructions (labelling programs unchanged):

  | Hook | Arch 7.1.9 | Debian 6.12.107 | Arch M4 | Debian M4 |
  |---|---:|---:|---:|---:|
  | `inode_unlink` | 6,679 | 6,242 | 6,587 | 6,224 |
  | `inode_rmdir` | 6,723 | 6,248 | 6,617 | 6,227 |
  | `inode_mkdir` | 6,361 | 5,881 | 6,344 | 5,989 |
  | `inode_link` | 10,668 | 10,188 | 10,507 | 10,344 |
  | `inode_rename` | 15,533 | 15,045 | 14,592 | 14,778 |

  The largest structural frame is still 184 B (link).
- **Known limits.** A CPU has at most 8 decisions in progress. A ninth
  structural operation that starts while eight are preempted on that CPU is
  denied and counted. That is a local denial of service, never an allow.

**As built in M5: subvolume-aware object identity.**

Objects were keyed by `(s_dev, ino)`. btrfs keeps one superblock (one `s_dev`)
for all its subvolumes, every subvolume root is inode 256, the first directory
made in a fresh subvolume is 257 in each, and a snapshot repeats its source's
numbers. A walk could therefore stop at another subvolume's object and decide
the target under that object's path. (btrfs gives userspace a different
`st_dev` per subvolume, the root's anonymous device, but the daemon never used
`st_dev`: both sides already agreed on `i_sb->s_dev` through mountinfo.)

- **Reproduced before the fix.** `TestStructuralBPFSubvolumes`
  (`structural_subvolume_linux_test.go`) loop-mounts a fresh btrfs with
  subvolumes `a` and `b`, a snapshot `a-snap` of `a`, and `b` mounted a second
  time; it checks 22 unlink/mkdir verdicts against the engine (a target is
  decided at each path it is reachable at). With the previous object on Arch
  7.1: 12 mismatches, 2 wrong allows (an allow rule on `a/d` let deletes
  through in `a-snap/d` and `b/x`) and 10 wrong denies (watching `a` denied in
  `b` and `a-snap`; a deny rule on `a/d` denied in the snapshot). The real
  daemon (`bpflsm-live -subvol-only`, whole btrfs watched, one app with
  `+ a/d/**` and a block default, one with `- a/d/**` and a permit default)
  failed 18 checks: 5 wrong allows (delete in `b/x`, `a-snap/d` and through
  the second mount, mkdir in `a-snap/d`, rename in `b/x`), 5 wrong denies, and
  their records.
- **The key.** `ObjectId { dev, ino, subvol }` (24 bytes; `ObjectKey` 32,
  `DecisionRecord` 16,496). `subvol` is the btrfs root objectid,
  `BTRFS_I(inode)->root->root_key.objectid`, and 0 on every other filesystem.
  The daemon gets it from `statx(STATX_SUBVOL)`, which btrfs's `getattr` fills
  from exactly that field (v6.12.107 and v7.1.9 `fs/btrfs/inode.c`; the flag
  exists since 6.10). The kernel reads the same field: a walk reads its
  superblock's `s_magic` once (a walk never leaves its superblock), and on
  `BTRFS_SUPER_MAGIC` each directory it checks costs two more probe reads
  (`inode + delta → root`, `root + objectid offset`). rustc emits no CO-RE
  relocations, so the offsets come from BTF as all others do: `s_magic` joins
  `OFFSETS` (vmlinux), and the btrfs layout — `btrfs_inode.root` relative to
  `btrfs_inode.vfs_inode`, and `btrfs_root.root_key.objectid` — is resolved by
  the daemon from vmlinux BTF when btrfs is built in (Arch) or from the btrfs
  module's split BTF `/sys/kernel/btf/btrfs` (Debian), with the member types
  checked (struct inode, a pointer, a 64-bit integer). The layout is not in
  `.rodata`: a module loaded after the generation would never get it. It is in
  `SETTINGS` (`SETTINGS_BTRFS`, `btrfs_root`, `btrfs_root_id`), carried by the
  compiled table and written in the same map update as the bank flip, so a
  bank is always read with the layout its keys were computed with. A table
  with no btrfs mount leaves the flag off and the kernel never reads `s_magic`.
- **btrfs placeholders.** A snapshot shows each subvolume nested in its source
  as an empty directory, inode 2 (`BTRFS_EMPTY_SUBVOL_DIR_OBJECTID`) of the
  snapshot's own root, so placeholders collide even with the subvolume. Nothing
  can be created below one, so the compiler never makes a placeholder an
  object; a walk passes through it to its parent's object.
- **When the kernel cannot tell subvolumes apart: fail closed.** That is btrfs
  without a readable layout (no BTF, a changed struct) or without
  `STATX_SUBVOL`, and any other filesystem that reports `STATX_SUBVOL`
  (bcachefs, a module on Debian 6.12). Its objects are keyed with subvolume 0,
  as the kernel computes, and if the filesystem is covered — a scope or rule
  anchors on it, or one of its mounts lies inside a scope or below a rule's
  literal prefix — every context on it carries `CONTEXT_SUBVOLUME` and denies
  under the new counted reason `subvolume-identity` (`REASON_SUBVOLUME` = 6;
  the later reasons and the record reasons moved up by one). The compile
  warning `subvolume-identity-unknown` (diagnostics error) names the mounts and
  the layout error. An uncovered such filesystem is unaffected.
  `TestSubvolumeIdentityUnknownFailsClosed` forces an unreadable layout: a
  covered btrfs denies in `a`, `b` and the top level (counted), a tmpfs and an
  uncovered btrfs allow, and the readable layout then allows again.
- **After.** `TestStructuralBPFSubvolumes`: 22/22 agree; `bpflsm-live
  -subvol-only`: every verdict right and every record names the exact path
  (a target in `b` is recorded under its object's first context, the second
  mount). Both on Arch 7.1 and Debian 6.12.

  Verified instructions (labelling programs unchanged):

  | Hook | Arch 7.1.9 | Debian 6.12.107 | Arch before | Debian before |
  |---|---:|---:|---:|---:|
  | `inode_unlink` | 6,996 | 6,559 | 6,679 | 6,242 |
  | `inode_rmdir` | 7,040 | 6,565 | 6,723 | 6,248 |
  | `inode_mkdir` | 6,555 | 6,073 | 6,361 | 5,881 |
  | `inode_link` | 12,039 | 11,288 | 10,668 | 10,188 |
  | `inode_rename` | 18,857 | 18,361 | 15,533 | 15,045 |

  The full regression set passed on both kernels: the `bpflsm` suite (exit
  tests, map-full, lifecycle, handover, self-test, label wait), the
  differential (8 × 505, 0 mismatches), structural contention (Arch, 4
  preemptors: 8,992 operations, 0 wrong allows, 353 wrong denials ≤ 614
  `state-contention`; Debian voluntary: 8,859, 0, 0, 0; Debian `preempt=full`, 4/0/12 preemptors: 9,252/8,651/9,559 operations, 0 wrong allows, 345/0/386 wrong denials ≤ 626/4/764), exec-label contention (3,000 execs, 0
  deletes on each kernel; 1,000 with Debian `preempt=full`), live enforce/off, and the M3/wait and M4
  `bpflsm-live` matrices on btrfs and tmpfs (Arch bursts: 8,208 and 8,326 of
  10,000 records dropped, `suppressed` equal to the drops; Debian 8,080 and 8,147, equal again; with `preempt=full` the label-wait test, the M3/wait and M4 matrices on btrfs and both subvolume tests passed too).
- **Known limits.** Executable labels (`EXEC_LABELS`) are still keyed by
  `(s_dev, ino, generation)`, so an executable in a snapshot shares the label
  learned for its source (the profile is still resolved by path when the label
  is learned). A covered filesystem whose subvolumes the kernel cannot tell
  apart denies every structural operation on it.

### 2.7 Events, feedback and status

- **Records.** The ring buffer carries fixed-size `DecisionRecord`s for allow,
  deny, and audit would-deny decisions: operation, verdict, reason, process and
  label, the active table bank, source and target object/context IDs, and
  object-relative paths. The daemon validates each object/context against the
  published table, reconstructs both paths, attributes the mount when known,
  and emits `filequery.FileAccessRecord` with `DestPath` for rename and link.
  Recent bank snapshots cover records queued across a rapid re-publish.
- **Volume.** A bounded in-kernel suppressor admits the first 64 records per
  `(label, operation, verdict)` — per app — in each one-second window. Further
  records increment a per-CPU drop counter exposed in structural status.
- **Deny notice.** A deduplicated informational notification shows the app,
  operation, path, and plain-language reason for an enforced denial. **Allow**
  appends literal `+ <path>` Write rules to that app's profile (both paths for
  rename/link), persists and re-publishes the profile, and asks the user to
  retry. Audit would-denies create Monitor rows without notices.
- **Rule model.** `CurrentRuleModel` reports Write as active in structural
  `enforce` mode and explanatory in `audit`/`off`. The app settings expose the
  Write rule list. Monitor filters and rows show Delete/Create/Rename/Link and
  `would-deny`, including source and destination paths where applicable.
- **Status.** Coverage and degraded warnings flow through
  `diagnosticsWarnings` (`diagnostics_linux.go:159`):
  - BPF LSM unavailable;
  - per-hook attach failure;
  - mode;
  - glob degradation;
  - label map full / `PENDING` denials count;
  - an orphaned older generation.

**As built in M4.** The ring ABI now has a 16,480-byte decision record. It
carries the operation, verdict, reason, tgid/start time, label, table bank,
source and target object/context IDs, and up to 8,192 bytes of relative path
for each side. Kernel hooks emit records for covered allow, deny, and audit
would-deny decisions. Recording an allow makes Monitor useful for comparison;
the same bounded suppressor keeps the added volume affordable. The first 64
records per `(label, operation, verdict)` in a one-second window are emitted;
later records increment a per-CPU drop counter, and the key's next emitted
record carries the previous window's drop count (`suppressed`). Failed ring
reservations and records discarded for state contention increment the counter
too. The daemon exposes the sum as `DecisionDrops` and the reported
`suppressed` total as `DecisionSuppressed`.

The daemon validates object/context references before joining a context base
with each relative path. It retains eight prior snapshots per bank to resolve
records that were queued before a rapid rule publication. Filequery stores
`dest_path`, and Monitor shows Delete, Create, Rename, Link and audit's
`would-deny`, with both rename/link paths in the row and details. The app view
uses the same rows. The Write rule list is editable in app settings and active
in enforce mode; audit/off explain their status in the rule model.

An enforced denial creates one informational notice per app/operation/path
pair. It names the app and reason in plain words. If the app has a local
profile, **Allow** appends literal Write allow rules for the source and, when
present, destination, persists the profile, invalidates its active cache, and
re-publishes the table. The user then retries. Audit would-denies never create
a notice. For an unresolved kernel label, the daemon also tries the live
process profile before deciding whether Allow can be offered.

**As built in the M4 fix-up.** Two problems in the first M4 recording, and one
check:

- **Verifier cost.** The first M4 build recorded from each hook after the
  decision, in `decide::record`: a static (not global) BPF function that walked
  the source and target again inside a 4-attempt retry loop. A static function
  is verified in its caller's context for every state that reaches it, so the
  walks were re-verified per attempt, per call path and per hook, and every
  recorded operation walked twice at runtime. Measured on Arch 7.1: the same
  build with those two walks removed verified unlink in 10,318 instructions
  instead of 72,553. Now a decision records itself from its own walks: the
  global decision functions take a record request (the `DECISION_*` operation,
  and whether the decision is final), and a covered decision that stands calls
  the global `filemaster_record(decision, ticket)` with its label, reason,
  verdict and bank packed into scalars. The walks moved from the stack to a
  per-CPU `WALKS` map (two slots, beside `SCRATCH`): copying them through the
  decision's return on the stack had doubled the decision's own verification
  (about 12,000 for unlink), while map memory is tracked loosely, as `EVAL`
  is. Both are shared per-CPU state, so the decision's sequence ticket guards
  them (M5 replaced the ticket with claimed decision states, §2.6): a decision that lost the state before recording runs again and records
  then; a sequence change while the paths are copied discards the ring
  reservation and counts a drop, so no record is ever submitted with another
  hook's path. A submitted record confirms the decision. A pending caller's
  enforced denial that will wait for its label records nothing; the decision
  after the wait (resolved, timed out, or skipped) is final and records, with
  the timed-out reason `label-wait-timeout`. With the wait off, the first
  decision is final. A decision that loses its state on all 4 attempts denies
  without a record and counts a drop.
- **Suppressor key.** It was `(tgid, operation, verdict)`, so a burst spread
  over many processes (`find … -exec rm {} \;`, `xargs -n1 rm`) gave every
  process a fresh budget and was never suppressed. It is now
  `(label, operation, verdict)`: one budget per app. Pending callers
  (`LABEL_PENDING`) share one bucket and unidentified ones (label 0) another;
  that bounds a flood of unresolved processes as a whole, at the cost that one
  noisy unresolved app can use up the 64 records per second that another
  unresolved app's denials would have had in the same window (drops are still
  counted, and denials are still enforced).
- **Profile-default denials (checked, no change).** `Decision::finish` denies
  only when some evaluation is covered (a rule matched or the object is in a
  watch scope), and every covered decision records, so no denial goes
  unrecorded. An in-scope target with no matching rule under a block default
  is denied with reason `default`, recorded, and noticed (the matrix's denied
  app). An operation that touches only objects outside every scope is allowed
  ("not covered → allow") and, correctly, records nothing. A rename by an app
  whose Write rule allows the source, into a folder outside every scope under a
  block default, is denied by the destination's `NOMATCH` default; the record
  has both full paths and the denial raises a notice.

Verifier results (verified instructions, stock kernels):

| Hook | Arch 7.1.9 | Debian 6.12.107 | Arch first M4 | Debian first M4 | Arch pre-M4 | Debian pre-M4 |
|---|---:|---:|---:|---:|---:|---:|
| `inode_unlink` | 6,587 | 6,224 | 72,553 | 51,730 | 6,025 | 6,114 |
| `inode_rmdir` | 6,617 | 6,227 | 72,688 | 51,739 | 6,054 | 6,153 |
| `inode_mkdir` | 6,344 | 5,989 | 137,896 | 93,775 | 5,846 | 5,854 |
| `inode_link` | 10,507 | 10,344 | 473,433 | 176,332 | 10,543 | 11,820 |
| `inode_rename` | 14,592 | 14,778 | 480,294 | 186,689 | 13,252 | 16,148 |
| `bprm_check_security` | 143 | 146 | | | | |
| `bprm_committed_creds` | 395 | 417 | | | | |
| `sched_process_fork` | 232 | 273 | | | | |
| `sched_process_exec` | 1,247 | 1,245 | | | | |
| `sched_process_exit` | 205 | 188 | | | | |

The largest structural frame is now 184 B (link; it was 264 B).

On Arch 7.1.9, the full `bpflsm` and `fileaccess` suites passed; the 8 × 505
generated-rule differential had zero mismatches, structural contention had
7,411 operations with zero fail-open verdicts, and the exec-label race stress
completed 3,000 child execs with zero unintended deletes. The live daemon
enforce/off and 50-run label-wait matrix passed. On Debian 6.12.107, the same
suites and differential passed (4,040 cases, zero mismatches); the explicit
label-wait test passed with `preempt=full`, structural contention had 8,512
operations with zero fail-open verdicts, and 3,000 child execs had zero
unintended deletes. Its live enforce/off and 50-run label-wait matrix passed.

On both kernels the real-daemon M4 harness observed allow and deny rows for
delete/create/rename/link with the correct app and both full paths where
needed. It verified a deduplicated deny notice, **Allow** followed by a
successful retry, an audit would-deny with no notice, and a healthy daemon
after 10,000 allowed deletes. The suppressor counted 9,872 drops on Arch and
9,936 on Debian. Browser inspection covered dashboard, Monitor, settings,
the app's file events, and its editable Write list; the Monitor screenshot
also shows an expanded rename with both paths.

After the fix-up the harness also deletes 10,000 files with
one helper process each (four at a time), about 360 per second: 8,080–8,336
of the 10,000 records were dropped per run (Arch btrfs 8,208, tmpfs 8,336;
Debian 8,080 and 8,208), within one 64-record budget per started second, and
the `suppressed` totals reported on later records equalled every counted drop
(e.g. 18,080 of 18,080 on Arch btrfs, both bursts together); the daemon stayed
healthy. The fix-up regression set passed on both kernels: the `bpflsm` suite,
the differential (8 × 505, 0 mismatches), structural contention (Arch: 7,435
operations, 0 fail-open, 129 fail-closed ≤ 251 `state-contention`; Debian
voluntary: 8,484, 0, 0; Debian `preempt=full`: 8,405, 0, 106 ≤ 272), the exec
labelling stress (3,000 execs, 0 deletes on each kernel), `TestLabelWait`
(Arch, Debian `preempt=full`), live enforce/off, the M3/wait `bpflsm-live`
matrix and the M4 matrix on btrfs and tmpfs.

Known limits: the suppressor deliberately omits records beyond its per-app
window while counting every omission. Records queued across more than eight
reuses of a bank can outlive the retained path snapshots. A short-lived
process that exits before its profile is resolved can leave a deny notice
without an **Allow** action, because there is no app profile to edit.

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
| M3 ✅ | Labelling: fork/exec/exit programs, argv/envp capture, `EXE_LABEL`/`SCRIPT_LABEL`, `process` boundary override, script-open labelling, `PENDING` deny, `(tgid, start_time)` self-bypass, `/proc` seeding, per-label kernel rule lookup | Observed on Arch 7.1 and Debian 6.12, tmpfs and btrfs: `python a.py` (allow) vs `python b.py` (deny) get distinct verdicts; `./x.py`, `./s.sh`, `./s.js`, `./s.pl` env-shebang scripts labelled by their script arg; `python -m fmmod` resolves to the module profile and `python -c` to the interpreter profile; a child `rm` spawned by a deny-profile script gets `rm`'s allow label; an unresolved process stays `PENDING` and denies; a fork storm against an 8-entry label map denies and increments the map-full counter; argv rewrite after start does not change the label. The real daemon (`cmds/bpflsm-live`: profiles via the database API, real processes) reproduces the distinct verdicts, scripts, `-m`/`-c`, child `rm` and a live rule edit, and the PENDING window is measured (see As built in M3). No regressions: self-test, lifecycle, handover, the Gate B/differential (8×505, 0 mismatches) and live-daemon enforce/off all pass on both kernels and filesystems | 2–2.5 |
| M4 ✅ | Decision records for covered allow/deny/audit would-deny; bounded suppressor and drop count; filequery paths/app/mount; informational deny notice with Allow-and-retry; active Write list and structural Monitor UI | Observed on Arch 7.1 and Debian 6.12: all four operations allowed/denied with full source/destination paths and app; deduplicated notice and successful Allow/retry; audit would-deny without notice; 10,000-delete burst with counted drops and healthy daemon. Full regression matrix passes on both kernels; verifier counts remain below 1,000,000 (see As built in M4). Dashboard, Monitor, settings, and app Write-list screenshots inspected; file-access Playwright E2E 2/2 passed with system Chromium | 1.5–2 |
| M5 | Hardening matrix (§4) and fixes; **btrfs subvolume/snapshot identity** (risk 7) — key objects by a subvolume-aware id, not just `(s_dev, ino)`. Stage 1 ✅: claimed per-CPU decision states replace the sequence ticket, closing the preempted-writer gap (see As built in M5). Stage 2 ✅: objects keyed by `(s_dev, ino, btrfs subvolume)`, fail closed where the kernel cannot read the subvolume (see As built in M5: subvolume-aware object identity) | §4 matrix green; coverage warnings correct for every injected failure; multi-subvolume btrfs no longer collides objects. Stage 1: the gap reproduced on the M4 object (wrong allows under stress); after it 0 wrong allows on Arch 7.1 and Debian 6.12, full regression set passes on both. Stage 2: 12 wrong verdicts (2 wrong allows) on the kernel object and 18 failed real-daemon checks before; 0 after on Arch 7.1 and Debian 6.12, full regression set passes on both | 1–1.5 |
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
7. **btrfs subvolume identity collision (RESOLVED, M5 stage 2).** Objects were
   keyed by `(mountinfo s_dev, ino)`. That pair is **not** unique across btrfs
   subvolumes and snapshots: every subvolume root is inode 256, and a snapshot
   repeats the inode numbers (and generations) of its source. Two different
   files in two subvolumes of one filesystem could therefore collide on
   `(s_dev, ino)` and share an object, so a rule on one wrongly applied to the
   other (reproduced in both directions). Objects are now keyed by
   `(s_dev, ino, subvolume)`, with the btrfs root objectid read by both sides;
   a filesystem whose subvolumes the kernel cannot tell apart fails closed
   with a warning (see "As built in M5: subvolume-aware object identity").
   Executable labels (`EXEC_LABELS`) are still keyed by
   `(s_dev, ino, generation)`, so a snapshot's copy of a learned executable
   shares its label (a known limit of that section).

## Estimate check

The plan sums to **8.5–11.5** against the 8–11 budget. Three code findings push
toward the top end:

- **Cordon's decision logic is replaced, not trimmed** (§2.4). The re-cost
  assumed 150–250 changed BPF lines; the decision table and its differential
  test are closer to 300–450.
- **At planning time, the Write list was hidden and the default mapped to
  Deny.** That motivated `audit` mode, UI exposure of the Write list and the
  deny notice. M4 delivered those surfaces; this re-cost predates them.
- **Identity reads `/proc` today.** Feeding captured argv/envp needs a
  boundary change in the ported `process` package. Also, fanotify script-open
  labelling only applies inside watched mounts.

Untested assumptions are marked inline; none has been exercised on Filemaster
code yet.
