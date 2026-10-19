//! Filemaster's structural-decision maps. Shared by the production object and
//! the matcher test object, so both see one layout.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf};
use filemaster_lsm_common::decision_maps::{
	AUDIT_COUNTERS, COUNTERS as COUNTER_SLOTS, MAX_CHUNKS, MAX_CONTEXTS, MAX_OBJECTS, MAX_PATTERNS,
	MAX_RANGES, MAX_TOKENS, NUM_BANKS, SCRATCH_SLOTS,
};
use filemaster_lsm_common::label_maps::{
	EXEC_SCRATCH_ENTRIES, LABEL_COUNTERS as LABEL_COUNTER_SLOTS, MAX_EXEC_LABELS, MAX_LABELS,
	MAX_POLICY_LISTS, MAX_PROCS, MAX_RULELISTS, NOMATCH_ENTRIES, RECORDS_SIZE,
};
use filemaster_lsm_common::{
	Arena, Chunk, Context, ExecFile, ExecLabelKey, ObjectKey, ObjectValue, Pattern, PolicyListKey,
	ProcValue, Range, RecordBuf, Resolved, RuleList, Scratch, Settings, Token,
};

use crate::matcher::EvalState;

#[map]
pub static OBJECTS: HashMap<ObjectKey, ObjectValue> =
	HashMap::with_max_entries((NUM_BANKS * MAX_OBJECTS) as u32, 0);
#[map]
pub static CONTEXTS: Array<Context> = Array::with_max_entries((NUM_BANKS * MAX_CONTEXTS) as u32, 0);
#[map]
pub static PATTERNS: Array<Pattern> = Array::with_max_entries((NUM_BANKS * MAX_PATTERNS) as u32, 0);
#[map]
pub static CHUNKS: Array<Chunk> = Array::with_max_entries((NUM_BANKS * MAX_CHUNKS) as u32, 0);
#[map]
pub static TOKENS: Array<Token> = Array::with_max_entries((NUM_BANKS * MAX_TOKENS) as u32, 0);
#[map]
pub static RANGES: Array<Range> = Array::with_max_entries((NUM_BANKS * MAX_RANGES) as u32, 0);
#[map]
pub static ARENA: Array<Arena> = Array::with_max_entries(NUM_BANKS as u32, 0);
/// The profile default for an unmatched in-scope target, by bank, policy,
/// operation and kind.
#[map]
pub static NOMATCH: Array<u32> = Array::with_max_entries(NOMATCH_ENTRIES as u32, 0);
/// One would-deny counter per Filemaster decision operation, per CPU.
#[map]
pub static AUDIT: PerCpuArray<u64> = PerCpuArray::with_max_entries(AUDIT_COUNTERS as u32, 0);
/// Undecidable cases, by reason and hook, per CPU.
#[map]
pub static COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(COUNTER_SLOTS as u32, 0);
#[map]
pub static SCRATCH: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(SCRATCH_SLOTS as u32, 0);
/// The whole evaluation state lives here, not on the stack: the verifier does
/// not track map-value contents precisely, so the `bpf_loop` callback's state
/// converges in a few passes instead of exploding past the instruction limit.
#[map]
pub static EVAL: PerCpuArray<EvalState> = PerCpuArray::with_max_entries(1, 0);
/// The one-element control record (daemon identity, active bank, audit mode).
#[map]
pub static SETTINGS: Array<Settings> = Array::with_max_entries(1, 0);
/// Each policy's rule list for one context, by `(bank, policy, context)`.
#[map]
pub static POLICY_LISTS: HashMap<PolicyListKey, u32> = HashMap::with_max_entries(MAX_POLICY_LISTS as u32, 0);
#[map]
pub static RULELISTS: Array<RuleList> = Array::with_max_entries((NUM_BANKS * MAX_RULELISTS) as u32, 0);
/// A label's policy in each bank; 0 (never published) is the pending policy.
#[map]
pub static LABEL_POLICY: Array<u32> = Array::with_max_entries((NUM_BANKS * MAX_LABELS) as u32, 0);
/// Kernel-written process labels, by tgid.
#[map]
pub static PROCS: HashMap<u32, ProcValue> = HashMap::with_max_entries(MAX_PROCS as u32, 0);
/// Daemon-written resolutions of pending processes, by tgid.
#[map]
pub static RESOLVED: HashMap<u32, Resolved> = HashMap::with_max_entries(MAX_PROCS as u32, 0);
#[map]
pub static EXEC_LABELS: HashMap<ExecLabelKey, u32> = HashMap::with_max_entries(MAX_EXEC_LABELS as u32, 0);
/// The first binfmt pass's file, by `linux_binprm` address. LRU: a failed
/// exec leaves its entry behind, and losing one only makes a script pending.
#[map]
pub static EXEC_SCRATCH: LruHashMap<u64, ExecFile> = LruHashMap::with_max_entries(EXEC_SCRATCH_ENTRIES as u32, 0);
#[map]
pub static RECORDS: RingBuf = RingBuf::with_byte_size(RECORDS_SIZE as u32, 0);
#[map]
pub static RECORD_BUF: PerCpuArray<RecordBuf> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub static LABEL_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(LABEL_COUNTER_SLOTS as u32, 0);
