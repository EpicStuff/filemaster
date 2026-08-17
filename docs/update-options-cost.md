# Backend option cost estimates

What implementing the backend options would cost, measured against the work
already done forking Portmaster into Filemaster.

|  | Code, excluding tests and docs | Claude API tokens (billed) |
|---|---|---|
| Filemaster so far | ~20,000 lines | ~1 billion |
| Second fanotify group | ~2,000 lines | ~150 million |
| LSM only | ~3,200–5,000 lines | 350–660 million |
| [DKMS livepatch (Route A)](update-option-dkms.md) | ~2,500–3,600 lines | 400–900 million |
| [FUSE backend](update-option-fuse.md) | ~4,600–7,400 lines | 280–410 million |

The known sources of error are in
[Backend option cost estimates — technical detail](update-options-cost-technical.md).
