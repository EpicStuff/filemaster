//! Filemaster's process-labelling ABI (M3).
//!
//! A label is a daemon-assigned profile number, stable for the daemon's
//! lifetime. Policies are the per-bank, de-duplicated rule sets the labels map
//! to, so a profile edit re-publishes a policy without relabelling processes.
//! Policy 0 of every bank is the pending policy: every rule of every policy as
//! a deny, plus every watch scope under a deny default.

use crate::decision_maps::{CONTEXT_RULES, NUM_BANKS, RuleRef};

pub const MAP_SETTINGS: &str = "SETTINGS";
pub const MAP_PROCS: &str = "PROCS";
pub const MAP_RESOLVED: &str = "RESOLVED";
pub const MAP_EXEC_LABELS: &str = "EXEC_LABELS";
pub const MAP_EXEC_SCRATCH: &str = "EXEC_SCRATCH";
pub const MAP_LABEL_POLICY: &str = "LABEL_POLICY";
pub const MAP_POLICY_LISTS: &str = "POLICY_LISTS";
pub const MAP_RULELISTS: &str = "RULELISTS";
pub const MAP_RECORDS: &str = "RECORDS";
pub const MAP_LABEL_COUNTERS: &str = "LABEL_COUNTERS";
pub const MAP_WAIT: &str = "WAIT";
pub const MAP_WAITERS: &str = "WAITERS";

/// Labels per daemon lifetime; label 0 is the unidentified profile.
pub const MAX_LABELS: usize = 16384;
pub const LABEL_MASK: u32 = (MAX_LABELS - 1) as u32;
pub const LABEL_UNIDENTIFIED: u32 = 0;
/// A process whose label the daemon has not resolved yet.
pub const LABEL_PENDING: u32 = u32::MAX;
/// Distinct policies per bank, including the pending policy 0.
pub const MAX_POLICIES: usize = 1024;
pub const POLICY_PENDING: u32 = 0;
/// Distinct rule lists per bank.
pub const MAX_RULELISTS: usize = 2048;
/// `(bank, policy, context)` entries with a non-empty rule list, both banks.
pub const MAX_POLICY_LISTS: usize = 65536;
/// Live thread groups the kernel can label. A fork past this is counted, and
/// the unlabelled child is denied like a pending one.
pub const MAX_PROCS: usize = 65536;
pub const MAX_EXEC_LABELS: usize = 65536;
/// In-flight execs between `bprm_check_security` and `sched_process_exec`.
pub const EXEC_SCRATCH_ENTRIES: usize = 4096;
pub const RECORDS_SIZE: usize = 8 << 20;

/// `Settings::flags`: fork/exec labelling is on and unlabelled processes are
/// pending. Off, every process uses label 0 (the M2 behaviour).
pub const SETTINGS_LABELLING: u32 = 1;

/// `RuleList::flags`: the list overflowed its array; the context denies.
pub const RULELIST_OVERFLOW: u32 = 1;

/// Ring-buffer record kinds.
pub const RECORD_EXEC: u32 = 1;
pub const RECORD_FORK: u32 = 2;
/// `RecordHeader::flags`.
pub const RECORD_ARGS_TRUNCATED: u32 = 1;
pub const RECORD_ENV_TRUNCATED: u32 = 2;
/// Captured argv and envp caps; the masks bound the verifier's view of them.
pub const ARGS_MAX: u32 = 8191;
pub const ARGS_MASK: u32 = 0x1FFF;
pub const ENV_MAX: u32 = 16383;
pub const ENV_MASK: u32 = 0x3FFF;
/// The exec path cap, including its NUL.
pub const PATH_MAX_RECORD: u32 = 1024;
pub const PATH_MASK: u32 = 0x3FF;
pub const RECORD_BUF_SIZE: usize = 32768;
pub const RECORD_SIZE_MASK: u32 = 0x7FFF;

/// Labelling counters (per CPU).
pub const LABEL_COUNTER_FULL: u32 = 0;
pub const LABEL_COUNTER_RECORD_DROP: u32 = 1;
pub const LABEL_COUNTER_UNREADABLE: u32 = 2;
/// Label waits started, and how each ended: resolved, timed out.
pub const LABEL_COUNTER_WAIT: u32 = 3;
pub const LABEL_COUNTER_WAIT_RESOLVED: u32 = 4;
pub const LABEL_COUNTER_WAIT_TIMEOUT: u32 = 5;
/// Waits skipped because the daemon's heartbeat is stale, or because
/// `max_waiters` callers were already waiting.
pub const LABEL_COUNTER_WAIT_STALE: u32 = 6;
pub const LABEL_COUNTER_WAIT_BUSY: u32 = 7;
/// Nanoseconds spent waiting, summed.
pub const LABEL_COUNTER_WAIT_NS: u32 = 8;
pub const LABEL_COUNTERS: usize = 9;

/// A pending caller in a covered scope waits at most this long for its label.
pub const WAIT_CAP_NS: u64 = 50_000_000;
/// A heartbeat older than this means the daemon is gone, so nothing waits.
pub const WAIT_STALE_NS: u64 = 3_000_000_000;
/// The wait loop's iteration bound; the deadline ends it far sooner.
pub const WAIT_LOOPS: u32 = 1 << 23;

pub const NOMATCH_ENTRIES: usize = NUM_BANKS * MAX_POLICIES * 10;

/// The control record. The daemon's own operations bypass enforcement when
/// the caller's thread group and its leader's `start_boottime` match;
/// `daemon_span` is the start-time tolerance, because `/proc` reports start
/// time in clock ticks.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Settings {
	pub daemon_start: u64,
	pub daemon_tgid: u32,
	pub daemon_span: u32,
	pub active_bank: u32,
	pub audit: u32,
	pub flags: u32,
	pub _pad: u32,
}

/// The label-wait control record. `heartbeat` is the daemon's last
/// `CLOCK_MONOTONIC` refresh (`bpf_ktime_get_ns`'s clock); `max_waiters` bounds
/// the callers spinning at once; `enabled` is the configured and self-tested
/// switch.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WaitSettings {
	pub heartbeat: u64,
	pub max_waiters: u32,
	pub enabled: u32,
}

/// A file identity with the inode generation, so a recycled inode number does
/// not inherit a label.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExecFile {
	pub dev: u64,
	pub ino: u64,
	pub generation: u32,
	pub _pad: u32,
}

/// `{exe, zero}` labels an executable by itself; `{interpreter, script}` a
/// script run through its `#!` line.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExecLabelKey {
	pub exe: ExecFile,
	pub script: ExecFile,
}

/// The kernel's per-thread-group record, keyed by tgid. `start` is the group
/// leader's `start_boottime`; a seeded entry matches within `span`
/// nanoseconds. `seq` changes at every fork and exec.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcValue {
	pub start: u64,
	pub seq: u64,
	pub span: u32,
	pub label: u32,
}

/// The daemon's resolution of one pending `(tgid, start, seq)`. Only the
/// daemon writes it, so a late answer for an older exec is ignored rather
/// than overwriting the kernel's newer state.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Resolved {
	pub start: u64,
	pub seq: u64,
	pub label: u32,
	pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PolicyListKey {
	pub bank: u32,
	pub policy: u32,
	pub context: u32,
}

/// One policy's ordered rules for one context.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleList {
	pub rule_count: u32,
	pub flags: u32,
	pub rules: [RuleRef; CONTEXT_RULES],
}

/// The fixed head of a ring-buffer record; `args_len` bytes of argv then
/// `env_len` bytes of envp follow, each as the NUL-separated strings of the
/// new image's stack, then `path_len` bytes of the path the kernel loaded the
/// final binary from (`bprm->interp`), so the daemon can identify a process
/// that exits before it is resolved. A fork record carries the parent and no
/// strings.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RecordHeader {
	pub kind: u32,
	pub tgid: u32,
	pub start: u64,
	pub seq: u64,
	pub exe: ExecFile,
	pub script: ExecFile,
	pub parent_seq: u64,
	pub parent_tgid: u32,
	pub flags: u32,
	pub args_len: u32,
	pub env_len: u32,
	pub path_len: u32,
	pub _pad: u32,
}

/// The per-CPU record assembly buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecordBuf(pub [u8; RECORD_BUF_SIZE]);

#[cfg(feature = "user")]
mod user {
	use super::*;

	// SAFETY: repr(C) integer aggregates with explicit padding.
	unsafe impl aya::Pod for Settings {}
	unsafe impl aya::Pod for WaitSettings {}
	unsafe impl aya::Pod for ExecFile {}
	unsafe impl aya::Pod for ExecLabelKey {}
	unsafe impl aya::Pod for ProcValue {}
	unsafe impl aya::Pod for Resolved {}
	unsafe impl aya::Pod for PolicyListKey {}
	unsafe impl aya::Pod for RuleList {}
}
