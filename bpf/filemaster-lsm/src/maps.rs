//! Filemaster's structural-decision maps. Shared by the production object and
//! the matcher test object, so both see one layout.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use filemaster_lsm_common::decision_maps::{
	AUDIT_COUNTERS, COUNTERS as COUNTER_SLOTS, MAX_CHUNKS, MAX_CONTEXTS, MAX_OBJECTS, MAX_PATTERNS,
	MAX_RANGES, MAX_TOKENS, NOMATCH_ENTRIES, NUM_BANKS, SCRATCH_SLOTS,
};
use filemaster_lsm_common::{
	Arena, Chunk, Context, ObjectKey, ObjectValue, Pattern, Range, Scratch, Settings, Token,
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
/// The profile default for an unmatched in-scope target, by bank, operation and kind.
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
