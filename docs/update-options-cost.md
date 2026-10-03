# Backend option cost estimates

What implementing the backend options would cost, measured against the work
already done forking Portmaster into Filemaster.

| | Code, excluding tests and docs | Claude API tokens (billed) |
|---|---|---|
| Filemaster so far (already done) | ~20,000 lines | ~1 billion |
| ~~[Second fanotify group](dropped/update-option-2ndfanotify.md)~~ *(dropped)* | ~2,000 lines | ~150 million |
| [BPF LSM](update-option-bpf.md) *(as a port of Cordon)* | ~2,200–3,150 lines in tree, ~1,550–2,450 written | ~125–170 million |
| [LSM + DKMS](update-option-lsm-dkms-technical.md) | ~2,950–4,800 lines | ~260–395 million |
| [Fanotify extension in a custom kernel](update-option-fanotify-extension.md) | ~2,600–4,450 lines | ~275–455 million |
| [BPF + DKMS — full BPF variant](update-option-bpf-dkms-technical.md) *(add-on to a finished BPF LSM)* | +~2,400–3,900 lines | +~234–365 million |
| [FUSE backend](dropped/update-option-fuse-technical.md) | ~4,600–7,400 lines | 280–410 million |
| [DKMS only — standalone module](update-option-dkms-only-technical.md) | **Not costed** — see below | **Not costed** |

The lines column is production code only, the token column should be all work (tests, debug, etc.)

BPF LSM covers only static, existing-hook scope.

**BPF LSM re-costed as a port of an existing project (2026-10-03)**, down from
~1,450–2,450 lines / 120–180M. Cordon is an independent, Claude-built BPF LSM
with almost the same scope, written in Rust. A spike showed our Go daemon can
load its BPF program directly and enforce delete and rmdir, so no C is needed.

- **We'd lift** its BPF program and map layouts.
- **We'd write** the loader and policy publishing in Go, reusing its designs for
  atomic policy swap, surviving a daemon crash, and rename over an existing file.

More code ends up in the tree, because the old figure was low and the lifted
Rust is verbose. Less has to be written or debugged. The biggest open risk:
Cordon's link and rename programs fail the kernel verifier and need
restructuring. **Since fixed (one line):** link and rename now enforce on 7.1 and 6.18.

It includes process labelling, so per-script, cmdline and env profiles work. Labels come from the script file the interpreter actually opens, and from a kernel copy of the command line that the process can't fake. Working:
[BPF LSM re-costed as a Cordon port](update-options-cost-technical.md#bpf-lsm-re-costed-as-a-cordon-port-2026-10-03).

**LSM only and its migration row were dropped (2026-08-27)** to [dropped/](dropped/update-option-lsm-only.md). It was a native LSM *built into a custom kernel* using existing hooks, so BPF LSM delivered the same static, existing-hook capability for less (~1,450–2,450 against ~1,800–3,150) and without requiring a custom kernel at all. Staging through it also made the remaining work larger, not smaller: the recorded increment after LSM only was **4,000–6,500 lines / 350–526M**, against **3,800–6,300 / 335–510M** for the same-scope increment after BPF. Its remaining purpose was de-risking whether existing hooks carried enough context before committing to VFS changes, and [P1](p1-rmdir-technical.md) settled that.

**DKMS only lost two of its three approaches (2026-08-30), and with them its number.** The 4,200–7,100 line / 510M–1.1B figure this row used to carry was the *generated-livepatch* estimate. That route is deleted: both stock Arch kernels tested have `CONFIG_LIVEPATCH` unset and distro headers lack the exact source `klp-build` needs (verified by running it, 2026-08-17), and livepatch's own restrictions — no resizing a live struct, no `__init` code — mean it could carry neither the fanotify-extension design nor the LSM design. The runtime-fanotify-extension approach is deleted too: it is dominated by the standalone module, which reaches exported VFS symbols where the extension must reach ~90 unexported file-local functions inside fanotify. What survives is the **hand-written standalone module**, whose kernel-side estimate the technical note says is "different, likely larger" and which has never been sized. **Do not reuse the old figure for it.**

Every row is an add-on to **today's tree**, not a system total. The one
exception is marked in the row itself: the full-BPF variant is an add-on to a
finished BPF LSM, so it is the only row you cannot read on its own.

**The full-BPF row's figure is an increment, derived by row-level subtraction** from its 2,985–4,835 from-today sizing, taking off the 550–980 lines a finished BPF LSM already pays for. Working: [`+ DKMS` increment after a finished BPF LSM](update-options-cost-technical.md#-dkms-increment-after-a-finished-bpf-lsm-2026-08-27). Only about **40%** of BPF LSM carries over, because its static-policy compiler and map schema are architecturally wrong for the destination — the custom-kernel design keeps the rule engine in the daemon.

**The staging premium this implies:** straight to pure native is 16–24 sessions, straight to full-BPF is 19–29, and BPF LSM first then upgrading is **24–37**. So going via BPF costs roughly **5–8 extra sessions, a ~26–28% premium**. *(With the 2026-10-03 BPF LSM re-cost this is roughly 5–7 sessions. That is an approximate substitution, not re-derived.)* That buys stock-kernel structural visibility years earlier and defers the custom-kernel decision — a schedule and reach purchase, not a saving.

**The fanotify extension now carries a number (2026-08-30).** It was reopened
uncosted; an estimate is now entered by the same row-subtraction method, and it
is the closest thing to a surprise in this table. Working:
[Fanotify extension — estimate entered](update-options-cost-technical.md#fanotify-extension-in-a-custom-kernel--estimate-entered-2026-08-30).

The saving over LSM + DKMS turns out to be **on the module, not on the option**.
Letting fanotify supply the queue, the waiting and the marks removes about a
third of the kernel module — but the module is only about two thirds of the
work, and the daemon, the build integration and the kernel edit barely move. Net
line saving is roughly **11%**. Once you add the cost of porting a 24-patch 2023
branch forward five kernel releases, re-verifying the Open prompts it would be
editing underneath, and solving a security hole the prototype does not solve,
the token bands **overlap, with this option slightly worse at the top end**
(245–400M against 234–350M).

**Revised upward 2026-08-30**, from ~2,100–3,700 / ~225–380M. The feature sweep
verified that fanotify **refuses directory-entry events on mount marks** — and
mount marks are the only kind filemaster uses. Most of the saving credited to
"fanotify already does the folder-watching" therefore does not exist: you would
have to plumb the mount information through every hook site first.

**So on cost these two are a tie**, and cost should not be what picks between
them. Pick on blast radius and regression risk instead: LSM + DKMS adds new code
beside a working system, the fanotify route edits the working system itself.
This estimate is superseded the moment someone ports the patch and counts.

**Both custom-kernel rows were revised upward on 2026-09-01**, by the same
amount and for the same reason, so nothing reordered. Verifying AppArmor's
prompting code gave the first outside measurement of the userspace half of this
problem: Canonical's equivalent is 2,448 lines where we had budgeted 500–850.
Most of that gap is work we genuinely do not need — but one part is: surviving
a daemon restart with prompts outstanding, which we had never costed at all.
Working: [Daemon protocol row revised upward](update-options-cost-technical.md#daemon-protocol-row-revised-upward-2026-09-01).

**The other thing that check settled:** there is no existing code to borrow for
the hard part. AppArmor is the closest product to what Filemaster is building,
and it gives up on the central problem — it waits **60 seconds and then gives
up**, with an unexplained `TODO` next to the decision, unchanged for six years.
Its cancellation support is declared and never implemented. So an untimed,
cancellable prompt that fails safely is genuinely ours to solve, under either
option. Two of its designs are worth copying outright, both about surviving a
daemon restart.

Note that the [LSM + DKMS](update-option-lsm-dkms-technical.md) row starts from **today's tree**, not from a finished LSM-only backend. They are complete custom-kernel backends, not a later phase bolted onto a first one. There is no honest "delta on top of LSM-only" figure — [LSM module sizing](lsm-module-sizing-technical.md) refuses to give one, because retained artifacts can only be subtracted once the code exists. The practical consequence runs the opposite way to intuition: **building LSM only first and upgrading later costs more than going straight to the custom kernel**, because the LSM-only row is paid in full first and the upgrade is not free.
