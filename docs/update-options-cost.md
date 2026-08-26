# Backend option cost estimates

What implementing the backend options would cost, measured against the work
already done forking Portmaster into Filemaster.

|  | Code, excluding tests and docs | Claude API tokens (billed) |
|---|---|---|
| Filemaster so far | ~20,000 lines | ~1 billion |
| Second fanotify group | ~2,000 lines | ~150 million |
| [BPF LSM](update-option-bpf-lsm.md) | ~1,450–2,450 lines | 120–180 million |
| [BPF LSM + DKMS](update-option-+dkms.md) | +~3,800–6,300 lines | +335–510 million |
| [LSM only](update-option-lsm-only.md) | ~1,800–3,150 lines | 150–225 million |
| [BPF LSM → LSM only](update-option-lsm-only-technical.md#bpf-lsm-to-lsm-only-migration) | +~1,000–1,700 lines | +75–120 million |
| [LSM + DKMS](update-option-+dkms.md) | +~3,800–6,200 lines | +350–510 million |
| [DKMS only — generated livepatch (Route A)](update-option-dkms-only.md) | ~2,500–3,600 lines | 400–900 million |
| [FUSE backend](update-option-fuse.md) | ~4,600–7,400 lines | 280–410 million |

The known sources of error are in
[Backend option cost estimates — technical detail](update-options-cost-technical.md).
The migration row is additional work after a completed BPF backend, not the
cost of direct LSM-only implementation. BPF LSM and BPF LSM → LSM only cover
only static, existing-hook scope. The two `+ DKMS` rows are **only the
incremental later targeted-kernel phase**, after their named BPF LSM or LSM-only
backend already exists. They do not include that first backend, and BPF LSM +
DKMS does not include a BPF LSM → LSM-only migration. In direct mode, the
temporary BPF or LSM structural policy cache is not retained. Distribution of
added kernel changes and the separate second-fanotify origin-tracking option
are outside these estimates.
