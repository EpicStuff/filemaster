// Ported from cordon crates/bpf-common/src/lib.rs @ b40a8c7 (Apache-2.0) — renamed the crate; Filemaster adds
// `decision_maps` and `label_maps`.
//! Layout shared, byte-for-byte, between the eBPF data plane (`crates/bpf`) and
//! the userspace control plane (`crates/daemon`, `bpf-lsm` feature).
//!
//! The eBPF program is the boundary: it reads policy from BPF maps and returns a
//! verdict in-kernel (DESIGN §4, "BPF-LSM"). The daemon fills those maps from the
//! SQLite store and drains the ring buffer. For that to work the two sides must
//! agree exactly on every key, value, and record — so they live here, once:
//!
//! - [`ids`] — the scalar domain newtypes (`Dev`, `Ino`, `Pid`, `Decision`, `Bank`).
//! - [`maps`] — the map names and the POD key/value/record types.
//! - [`offsets`] — the running-kernel field offsets the daemon resolves from BTF
//!   and injects into the program's `.rodata` (the CO-RE-substitute portability
//!   shim).
//!
//! `#![no_std]` with no `aya` dependency by default, so the eBPF crate consumes it
//! cleanly. The userspace loader turns on `features = ["user"]`, which adds the
//! `aya::Pod` marker impls (required to use a type as a map key/value or global).

#![no_std]

// Defines `padded_pod!`; `#[macro_use]` + declaration-before-use makes it visible to the
// `maps`/`policy_maps` modules below (textual macro scoping).
#[macro_use]
mod layout;

pub mod decision_maps;
pub mod ids;
pub mod label_maps;
pub mod maps;
pub mod offsets;
pub mod policy_maps;

pub use decision_maps::{
    Arena, Chunk, Context, DecisionOp, ObjectKey, ObjectValue, Pattern, Range, RuleRef, Scratch,
    ScopeRef, TargetKind, Token, Verdict,
};
pub use label_maps::{
    ExecFile, ExecLabelKey, PolicyListKey, ProcValue, RecordBuf, RecordHeader, Resolved, RuleList,
    Settings,
};
pub use ids::{
    Bank, CgroupId, Decision, Dev, Ino, Nanos, Opens, Pid, Suppressed, SuppressedTotal, Uid,
};
pub use maps::{
    DecisionEvent, FileId, MAP_EVENTS, MAP_SUPPRESS, PATH_MAX_DEPTH, PATH_NAME_MAX, PathComp,
    SuppressKey, SuppressVal,
};
pub use offsets::Offsets;
pub use policy_maps::{Action, ClassId, ObjId, Policy, SubjectFlags, SubjectMatch};
