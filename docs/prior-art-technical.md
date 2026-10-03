# Prior art survey — technical note

> **Status: the significant items are now verified.** AppArmor prompting — the
> last major unverified entry — was verified on 2026-09-01 and found **not
> reusable**; see below. What remains reported-only is Landlock Supervise,
> KubeArmor/Tetragon, Talpa/Dazuko, `klp-build` and the Flatpak portal, none of
> which bear on the expensive layer.
>
> **Original status note:** This records existing work relevant
> to the backend options so it is not rediscovered. One item — Amir Goldstein's
> `fan_pre_modify-wip` — has been fetched and read; that analysis lives in
> [Fanotify extension in a custom kernel](update-option-fanotify-extension-technical.md#prior-art--a-substantive-prototype-exists-with-a-security-model-mismatch).
> Everything else here is **reported** from a secondary summary and has **not**
> been checked against source. Treat the links as leads, not evidence.

## Why this exists

The option evaluation was carried out largely from first principles. That was a
gap: several of the problems treated as Filemaster-specific have existing
implementations or upstream prototypes. This note is the index.

## Landscape

| Filemaster option | Closest existing work | Status here |
|---|---|---|
| BPF LSM | **Cordon**; KubeArmor, Tetragon, BPFContain | Cordon **verified**; others reported |
| Native LSM only | AppArmor, SELinux, TOMOYO, Landlock | Reported |
| LSM + DKMS (kernel asks userspace and waits) | **seccomp user notify** (mainline), **AppArmor prompting + snapd** (Ubuntu-only), TOMOYO (mainline), Landlock Supervise RFC | seccomp, TOMOYO and **AppArmor all verified**; Landlock reported |
| Custom fanotify extension | **`amir73il/linux`** — `fan_pre_modify-wip` (2023), **`fan_pre_dir_access` (2025)**, `fan_vfs_filter`, `fan_pre_vfs`; 2022 Xiaomi unlink/rmdir patch | `fan_pre_modify-wip` **read in full**; `fan_pre_dir_access` **branch survey + 4 commits verified** |
| DKMS only / runtime hooking | Sophos Talpa, Dazuko/DazukoFS; `klp-build` | Reported |
| Custom kernel, userspace decides | RSBAC UDF | Verified — not reusable |
| Fanotify Open prompt (already built) | Bulwark | Verified |
| FUSE (dropped option) | Flatpak / XDG Document Portal | Reported |

## The wait/queue/response layer — where the remaining cost actually is

The dominant term in [LSM module sizing](lsm-module-sizing-technical.md) is not
the kernel diff (P1 measured 16 lines for `rmdir`). It is the module's wait,
queue, cancellation, response handling and daemon-death behaviour, plus a
500–850 line daemon protocol. Four bodies of code address that layer. **Two are
already in the kernel being built and need no fork.**

### seccomp user notify — mainline, verified, best-tested

**Verified from source (v7.1).** `kernel/seccomp.c:1202` waits with
`wait_for_completion_interruptible(&n.ready)` — **untimed**. Around it:
`struct seccomp_knotif` with a documented three-state lifecycle
(INIT → SENT → REPLIED, comment at `kernel/seccomp.c:77`), a `notify_lock`
(`:233`), correlation via notification IDs,
`SECCOMP_IOCTL_NOTIF_ID_VALID` for detecting a dead or recycled request, and
`SECCOMP_IOCTL_NOTIF_ADDFD` for returning descriptors.

**Judged.** This is the best-exercised in-tree implementation of exactly the
layer Filemaster must build, with a stable UAPI and container runtimes
hammering it in production.

**Judged — not usable as a backend.** It intercepts syscall arguments, not
resolved VFS paths, so path-based decisions over it carry the well-known
seccomp TOCTOU problem. It is a code and design source, not an architecture.

### AppArmor prompting — verified 2026-09-01. Not reusable; two designs worth copying.

**Verified — it exists and is Ubuntu-only.** `security/apparmor/notify.c` is
absent from mainline (`torvalds/linux` at `v6.17` returns 404; mainline's
`security/apparmor/Makefile` has no `notify.o`). Ubuntu's tree carries it:

| Artifact | Noble 6.8.12 | Plucky 6.14.11 | Questing 6.17.13 |
|---|---:|---:|---:|
| `security/apparmor/notify.c` | 1,062 | 1,059 | **1,370** |
| `security/apparmor/include/notify.h` | 98 | — | 113 |

Kernel total ≈**1,890** lines including `apparmorfs.c` listener fops/ioctl/poll
(~361) and the `file.c` upcall glue (~45). Userspace: snapd
`sandbox/apparmor/notify/` **2,448** non-test lines, plus
`interfaces/prompting/` 5,980 and `overlord/ifacestate/apparmorprompting/`
1,308; the desktop UI is a separate Canonical repo. Wire protocol versions 3
and 5.

*Method note:* measure against `?h=master-next`. A new series' `master` is
stale — questing's `master` still serves 6.8.

**Verified — the wait is timeout-bounded at 60 seconds, and has been for six
years.** `notify.c:553-565`, `handle_synchronous_notif()`:

```c
if (knotif->ad->subj_label->flags & FLAG_INTERRUPTIBLE)
        werr = wait_for_completion_interruptible_timeout(&knotif->ready,
                                         msecs_to_jiffies(60000));
else
        werr = (long) wait_for_completion_timeout(&knotif->ready,
                                           msecs_to_jiffies(60000));
```

Both branches bounded. **Byte-identical across 6.8, 6.14 and 6.17.** On expiry
`err = 0`, immediately above a surviving `//err = -1; // TODO: ???;`. snapd
stacks further timeouts above it (`requestprompts.go:50-59`: 5 s ready, 10 s
initial, 10 m activity).

**Verified — and this is the discouraging part: AppArmor is not TOMOYO.**
`aa_do_notification()` (`notify.c:609-661`) drops `listener->lock` and
`ns->listener_lock` before waiting. It holds **nothing**. TOMOYO's timeout was
*forced* by asking with locks held; AppArmor's is a free design choice that was
made once and never revisited. The closest product match to Filemaster could
have waited indefinitely and chose not to.

**Verified — cancellation is declared but not implemented.** snapd's enum has
`APPARMOR_NOTIF_CANCEL` (`ntype.go:12`), but kernel-side `notify.h:62` is
`#define KNOTIF_CANCELLED` — a **valueless** macro, alongside `KNOTIF_PULSE` and
`KNOTIF_PENDING`. `CANCEL` appears nowhere else in `notify.c`, `notify.h` or
`apparmorfs.c`. These would not compile if used.

**Verified — correlation.** Per-listener monotonic `u64`,
`knotif->id = ++listener->last_id` (`notify.c:538`), linear-list lookup, an
`APPARMOR_NOTIF_IS_ID_VALID` ioctl for liveness. **No generation counter and no
reuse detection.** IDs survive resend rather than being reminted.

**Verified — listener death is fail-closed, and the design is good.** Checked at
the call site, not inferred: `security/apparmor/file.c:138-178` pre-seeds the
denial *before* the upcall —

```c
node->data.denied = ad->request & ~perms->allow;   /* :158 */
err = aa_do_notification(APPARMOR_NOTIF_OP, node); /* :160 */
...
perms->deny  = node->data.denied;                   /* :171 */
perms->allow = node->data.request & ~node->data.denied;
```

A dead listener, a 60 s timeout, or no listener at all each leave `node->data`
untouched, so the policy denial applies verbatim. Around it: `listener_release`
schedules `aa_delayed_free_listener_proxy` **30 s** later (`notify.c:264-275`,
comment "delay putting the listener giving a chance to reclaim"); a restarting
daemon re-attaches with a persisted listener ID via
`APPARMOR_NOTIF_REGISTER`/`aa_register_listener_id`; `APPARMOR_NOTIF_RESEND`
replays outstanding requests flagged `UNOTIF_RESENT`; and snapd counts them down
to a readiness barrier before declaring itself live.

*Caveats:* fail-closed here is *by omission* — there is no distinct "listener
died" signal, and a dead listener is indistinguishable at the waiter from a
response that changed nothing. The 30 s reclaim is also capped by the request's
own 60 s clock.

**Judged — entanglement is high; there is no seam to cut along.** `notify.c`
contains `aa_free_ruleset`/`aa_new_ruleset`/`aa_clone_ruleset` (`:877-909`),
because the `RESP_NAME` response lets userspace answer a prompt by *installing a
policy rule*. The request filter is a DFA matched on the label name; reclaim
authorisation *is* the label check (`-EPERM` unless
`tmp->label == begin_current_label_crit_section()`); even interruptibility is a
label flag. Of `notify.c`'s 1,370 lines: ~590–650 genuinely generic, ~440
response-validation and policy mutation, ~310 AppArmor-specific marshalling —
**interleaved function-by-function, not layered.**

**Verified — licence split matters.** Kernel side **GPL-2.0-only** (SPDX on
`notify.c`/`notify.h`, "Copyright 2019 Canonical Ltd."). But snapd is
**GPL-3.0** and prompting-client is **GPL-3.0** — and the 2,448-line userspace
protocol layer is the part that would actually be tempting to lift. Filemaster
is a Portmaster fork; check the licence question before copying any of it.

**Judged — code-maturity signals.** The `TODO: ???` on the central timeout
decision; three valueless flag macros; and `aa_listener_unotif_resend()` taking
`listener->ns->listener_lock` to splice lists while all seven
`lockdep_assert_held` sites in the file assert `listener->lock` — an apparent
locking inconsistency in the daemon-restart path, the one part we would most
want to trust.

**Verdict — design-only inspiration.** Reuse fails on three independent grounds,
any one sufficient: timeout-bounded where Filemaster requires untimed;
cancellation unimplemented; and extraction drags in `aa_label`, `aa_profile`,
`aa_ruleset`, `aa_dfa`, `aa_ns` and `apparmor_audit_data`.

**Two designs are worth copying outright:**

1. **Listener-death survival** — persisted listener ID, a kernel-side reclaim
   grace period, explicit RESEND with a `RESENT` flag, and a userspace readiness
   barrier that counts replayed requests down before going live. A
   production-proven answer to Filemaster's hardest failure case.
2. **Pre-seed the default verdict at dispatch time**, not at response time. This
   is what makes fail-closed the structural default rather than a case to handle.

**Not verified by running it.** No AppArmor on this machine. An Ubuntu 24.04+ VM
with `snap set system experimental.apparmor-prompting=true` would settle both
behaviours: hold a prompt past 60 s and observe the denial; `kill -9` snapd with
a prompt outstanding and time the 30 s reclaim. The `include/uapi/linux/apparmor.h`
wire format could not be retrieved (launchpad cgit 500s) and rests on snapd's
`message.go`, which quotes the kernel structs verbatim.

### TOMOYO — mainline, verified, smallest example

**Verified from source (v7.1).** `security/tomoyo/common.c:1971,1973` declare
paired `tomoyo_query_wait` / `tomoyo_answer_wait` queues; `tomoyo_supervisor()`
(`:2194`) wakes the query queue and waits at `:2260` with
`wait_event_interruptible_timeout`. Serial-number correlation and a `poll_wait`
interface (`:2326`) are present. The whole LSM is ~11,286 lines of `.c`.

**Verified — the existing rejection stands.** The wait is timeout-bounded
because TOMOYO asks with locks held. That disqualifies it as an *architecture*,
which the option docs already record. It remains the **smallest readable
in-tree example of the ask-userspace pattern**.

### Licence

**Judged.** Filemaster's LSM is GPL kernel code, as are seccomp, TOMOYO and
AppArmor. This is potentially genuine code reuse of the queue and response
machinery, not only design inspiration — which is the difference between a
marginal and a material saving on this layer.

### What this is and is not worth — REVISED 2026-09-01

> **The earlier judgement had this backwards.** It said the return from prior art
> would be *failure semantics, not line count*. Verifying AppArmor prompting
> reversed both halves.

**Line count — corroborated, and the estimate holds.** An independent production
implementation of exactly this layer lands at **≈1,890 kernel lines**, near the
floor of the 1,760–2,830 range. That is good external evidence the range is real
and not padded. But it lands there **without** an untimed wait and **without**
cancellation. Adding both, the honest read of our own range is **mid, not
bottom**.

**The userspace figure is worse than projected — and this is the finding that
moves money.** snapd's protocol layer is **2,448 non-test lines** against the
500–850 in [LSM module sizing](lsm-module-sizing-technical.md). Not
apples-to-apples — snapd carries multi-version negotiation we would not need
initially, and Filemaster reuses 2,082 existing generic Go lines snapd had to
build — but the daemon-restart reclaim logic we *do* need is a substantial part
of that gap. **The daemon row should be revised upward**; see
[Daemon protocol row revised upward](update-options-cost-technical.md#daemon-protocol-row-revised-upward-2026-09-01).

**Failure semantics — refuted.** AppArmor's failure semantics are the *weakest
and least finished part of it*. The exact question Filemaster cares about — what
happens when nobody answers — is answered by an unexplained hardcoded 60 s and a
`TODO: ???` that has survived unchanged across three shipping kernel series and
roughly six years, in a product with a real desktop consumer. Cancellation is
declared and never built. Fail-closed emerges from a pre-seeded field rather
than deliberate design.

**So the inference reverses.** The reason to read this code is not to inherit
failure semantics; it is to learn that **the untimed wait is the part everyone
skips**. Every prior-art implementation surveyed either bounds the wait
(AppArmor by choice, TOMOYO by necessity) or intercepts at the wrong layer
(seccomp). That makes an untimed, cancellable, fail-closed wait Filemaster's
**genuine unknown**, not a solved problem to be lifted — and it is the same
unknown under either architecture.

**Restated.** Prior art confirms the kernel line-count estimate and supplies a
restart-reclaim design, but supplies **no** failure semantics for untimed
waiting: the closest product match declined to solve that, and its userspace
protocol came in 3–5× our estimate.

## Cordon — verified 2026-10-03, an independent BPF LSM implementation of our row

**Verified from source.** `github.com/nikicat/cordon` at `b40a8c7`, Apache-2.0,
Rust/Aya, ~6,300 production lines, 125 commits from 2026-06-23 to 2026-08-05,
nearly all co-authored by Claude. In-kernel static enforcement on `file_open`,
`inode_link`, `inode_rename`, `inode_unlink`, `inode_rmdir`, `inode_mkdir` and
`bprm_check_security` (`crates/bpf/src/main.rs:134-187`). It cannot prompt: all
decisions are made in the kernel.

What it solves that our BPF docs still list as open:

- **Atomic policy publication:** banked rule maps, with the inactive bank seeded
  and then `Settings.active_bank` flipped in one write.
- **Daemon-crash behaviour:** the LSM links are pinned to bpffs, so enforcement
  survives SIGKILL. The handover order is attach → self-test → seed → pin →
  sweep the old generation. Smoke scenario 28 covers it.
- **Rename over an existing destination:** classified off the destination
  dentry, because `inode_rename` is the only hook that fires
  (`main.rs` doc comment on `decide_reparent`). It also covers hard-link and
  rename escape out of a protected directory.
- **6.12 verifier:** LSM return values must be provably in `[-4095, 0]`. See
  `clamped()`, `main.rs:127`.
- **Overlayfs on `file_open`:** measured; it sees the real underlying dentry
  chain (`STATUS.md:241`). Not measured on the mutation hooks.

Mismatches: fail-**open** on unreadable fields (`main.rs:26`, `:128`); no
regular-file create, truncate or list hook; identity is exe plus cgroup class,
not Filemaster profiles. Cost effect:
[Cordon as an external measurement](update-options-cost-technical.md#bpf-lsm--cordon-as-an-external-measurement-2026-10-03).

## Bulwark — verified 2026-10-03, nothing to take

`github.com/obstalabs/bulwark`, **AGPL-3.0**, Rust. A `FAN_OPEN_PERM` gate
(`src/gate.rs`) with cgroup-v2 process-tree attribution. Its consent trait
*requires* a deadline and a timeout-deny (`src/consent.rs:95-97`), which is the
opposite of our untimed Prompt. Filemaster already has a working fanotify Open
prompt, so Bulwark duplicates built work. The cgroup-scope attribution is a
design idea at most.

## RSBAC UDF — verified 2026-10-03, nothing to take

**Verified from source:** `git://rsbac.org/linux-6.18.y` at `2c31d25ca`
(2026-09-11), on kernel 6.18.54. The licence is GPL-2.0-only through the kernel
tree; `udf_main.c` carries no SPDX header of its own. The project is actively
maintained but no longer publishes formal releases.

**UDF is a malware-scanner hook, not a prompt channel.** Each cache miss spawns
the configured checker with `call_usermodehelper` (`rsbac/adf/udf/udf_main.c:363`).
The checker gets only the path in `argv[1]`, and its exit code is the decision.
It has no persistent daemon, no request IDs and no cancellation.

- **Wait:** untimed, `UMH_WAIT_PROC | UMH_KILLABLE` (`:50`).
- **Failure:** fails closed when the checker errors or is killed (`:367-385`).
  Exit code 254 is a deliberate "temporary failure, allow" (`:426`).
- **Cache:** results are cached per dev/inode with a TTL. Concurrent callers for
  the same file poll with `msleep_interruptible(500)` (`:698-717`).
- **Coverage:** only `EXECUTE`, `READ_OPEN` and `READ_WRITE_OPEN` on regular
  files reach the checker (`include/rsbac/adf_main.h:327-334`,
  `udf_main.c:549-561`). Write-only opens are not checked, there is no
  namespace operation, and never a second object.

**Hook placement is the one useful fact, and it argues against copying it.**
The UDF open hook sits in `do_open` (`fs/namei.c:4386-4416`), after the parent
`i_rwsem` is dropped. RSBAC's general ADF hooks are different:

- create, mknod, mkdir, rmdir and link run under the parent lock.
- unlink runs under the target lock as well.
- rename runs inside `lock_rename`.
- readdir and truncate run before their locks are taken.

That placement suits instant in-kernel policy, but an untimed wait inside those
locks is exactly what Filemaster must avoid.

**Size:** UDF is ~990 lines; RSBAC overall is ~108,000 lines plus hooks in 85
core-kernel files.

## Other leads

**Landlock Supervise** (RFC, March 2025, nine patches). *Reported.* An
interactive permission-request mechanism with an Allow-once / Allow-always /
Deny model — close to Filemaster's UX. Discussion reportedly covers where an
interactive event must sit relative to VFS locking, and Amir Goldstein pointed
at his pre-lock fanotify work in that thread. Still RFC as of 2026, so it is
architectural validation rather than an available API.

**KubeArmor / Tetragon.** *Reported.* Production BPF-LSM enforcement with
userspace daemons. Relevant lessons are lifecycle, map replacement, fail-safe
behaviour and enforcement surviving daemon restart — not basic feasibility,
which the BPF proof already established. Consistent with keeping BPF LSM ranked
where it is.

**Sophos Talpa, Dazuko/DazukoFS.** *Reported.* Out-of-tree modules intercepting
file access and vetting via userspace — commercial precedent for the DKMS-only
approach. Both reportedly required per-kernel-version interface modules and
were abandoned in favour of fanotify. This **supports lowering** DKMS-only
runtime hooking rather than raising it: it proves the approach works and that
its maintenance cost is what [DKMS only](update-option-dkms-only-technical.md) feared.

**`klp-build`.** *Reported.* SUSE tooling for generating livepatches from source
diffs. Tooling precedent only — no mature security product appears to use
generated livepatches as a permanent access-control architecture.

**Flatpak / XDG Document Portal.** *Reported.* FUSE-mediated per-application
file access with a permission store. Good evidence that FUSE plus per-app
permissions is production-sound, but it relies on sandboxed applications seeing
only the portal's exported view. It does not address Filemaster's requirement of
transparently mediating arbitrary applications against the real filesystem, which
is the objection [FUSE backend](dropped/update-option-fuse-technical.md) already records.

**A newer Amir branch supersedes the one we read as the port base.** **Verified
from the remote (2026-08-30).** `fan_pre_dir_access` is dated 2025-07-08 on
v6.16-rc5, against `fan_pre_modify-wip`'s 2023-06-27 on v6.4. Its feature —
pre-content events on directories for lookup and readdir — is not Filemaster's,
but two of its patches solve the Gate 1 item 1 blocker outright: a
**variable-length permission event carrying fid + name**
(`FANOTIFY_EVENT_TYPE_FID_NAME_PERM`, 68+/20−) and the removal of the
class restriction that forbade fid info in a permission group
(`FAN_CLASS_PRE_CONTENT_FID`, 59+/15−). Full detail:
[cost technical — port base](update-options-cost-technical.md#port-base--there-is-a-much-newer-branch-and-it-is-not-the-one-we-read-2026-08-30).
This is the concrete answer to the outstanding "which branch is the better port
base" question: **neither alone** — event format from the 2025 branch,
structural hooks from the 2023 one.

**2022 Xiaomi unlink/rmdir permission patch.** *Reported.* Single-object
blocking fsnotify events for delete. Superseded in scope by the Amir branch,
which covers rename.

## What this changed

- The fanotify option's prior-art section was **corrected**; see the link at the
  top. An earlier claim that the prior art "stops before the hard part" was wrong.
- The endpoint decision is **not** reopened — see the cost reasoning in that
  section.
- A new, unevaluated technique is on record: **pre-lock ask placement**, which is
  orthogonal to the LSM-versus-fanotify endpoint choice.
- The wait/queue/response layer has **four** prior-art sources, not one. The two
  best-verified are mainline and need no fork: seccomp user notify and TOMOYO.
- ~~Expected return there is failure semantics, not a smaller estimate.~~
  **Reversed 2026-09-01.** The kernel line count is corroborated; the failure
  semantics are not available from prior art at all. An untimed, cancellable,
  fail-closed wait is Filemaster's genuine unknown under either architecture.
- **The daemon protocol estimate is too low** — snapd's equivalent is 2,448
  lines against 500–850. Revised in the cost model.
