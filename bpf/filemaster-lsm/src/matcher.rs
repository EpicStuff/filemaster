// The control flow is a port of Go 1.27 src/path/filepath/match.go (Match,
// matchChunk) and src/unicode/utf8/utf8.go (DecodeRuneInString), Copyright 2010
// The Go Authors, BSD-3-Clause (bpf/LICENSE-go). Pattern parsing — scanChunk,
// getEsc, class syntax and bad-pattern detection — is done at compile time in
// Go (service/fileaccess/bpflsm/tokens.go); the kernel executes only Match's
// control flow over the flat token program that produces. Every piece of
// mutable evaluation state lives in the per-CPU `EVAL` map value, not on the
// stack, so the `bpf_loop` callback's state converges for the verifier.

use core::ffi::c_void;

use aya_ebpf::helpers::r#gen::bpf_probe_read_kernel;
use filemaster_lsm_common::decision_maps::{
	ARENA_MASK, CONTEXT_OVERFLOW, CONTEXT_RULES, CONTEXT_SCOPES, MAX_CHUNKS, MAX_PATTERNS,
	MAX_RANGES, MAX_STRING, MAX_TOKENS, REL_END, RULE_ALLOW, RULE_KIND_MASK, RULE_KIND_SHIFT,
	SCRATCH_MASK, TOKEN_CLASS, TOKEN_LITERAL, TOKEN_QUESTION,
};
use filemaster_lsm_common::label_maps::{MAX_RULELISTS, RULELIST_OVERFLOW};
use filemaster_lsm_common::PolicyListKey;

use crate::maps::{ARENA, CHUNKS, CONTEXTS, PATTERNS, POLICY_LISTS, RANGES, RULELISTS, SCRATCH, TOKENS};

// Eval-level phases.
const E_CONTEXT: u32 = 0;
const E_RULE: u32 = 1;
const E_PARENT: u32 = 2;
const E_SCOPE: u32 = 3;
const E_DONE: u32 = 4;
/// The terminal eval phase, read by decide.rs to detect budget exhaustion.
#[allow(dead_code)]
pub const E_DONE_PUB: u32 = E_DONE;
// Matcher-level phases (token interpreter and containment).
const MM_CHUNK: u32 = 10;
const MM_TOKEN: u32 = 11;
const MM_CLASS: u32 = 12;
const MM_CHUNKDONE: u32 = 13;
const MM_SKIP: u32 = 14;
const MM_TRAILING: u32 = 15;
const RC_START: u32 = 16;
const RC_COMPARE: u32 = 17;

// Which caller a finished match returns to.
const RET_SELF: u32 = 0;
const RET_PARENT: u32 = 1;
const RET_SCOPE: u32 = 2;
/// A test-only match driver: on finish, record the result in `covered` and stop.
#[allow(dead_code)]
pub const RET_TEST: u32 = 3;

const KIND_ANY: u8 = 0;
const KIND_FOLDER: u32 = 2;

const RUNE_ERROR: u32 = 0xFFFD;

/// Side results of one evaluation (an operation on one walked target).
#[allow(dead_code)]
pub const SIDE_NOT_COVERED: u32 = 0;
#[allow(dead_code)]
pub const SIDE_ALLOW: u32 = 1;
#[allow(dead_code)]
pub const SIDE_DENY: u32 = 2;

/// Every mutable evaluation and matcher field, held in a per-CPU map value.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EvalState {
	// Target and policy.
	pub bank: u32,
	pub slot: u32,
	pub rel: u32,
	pub leaf: u32,
	pub list: u32,
	pub kind: u32,
	pub entry: u32,
	pub nomatch_allows: u32,
	pub policy: u32,
	// The current context's rule list in RULELISTS.
	pub rulelist: u32,
	// Outer iteration.
	pub phase: u32,
	pub context: u32,
	pub context_end: u32,
	pub rule: u32,
	pub rule_count: u32,
	pub scope: u32,
	pub scope_count: u32,
	// Current context's resolved name window in scratch.
	pub name_base: u32,
	pub name_end: u32,
	pub parent_end: u32,
	// Current rule.
	pub rule_pattern: u32,
	pub rule_flags: u32,
	pub ret: u32,
	pub scope_exclude: u32,
	// Match window for the current attempt (self = full path, parent = folder).
	pub win_base: u32,
	pub win_end: u32,
	// Token matcher.
	pub m_chunk: u32,
	pub m_chunk_end: u32,
	pub m_star: u32,
	pub m_tok: u32,
	pub m_tok_end: u32,
	pub m_s: u32,
	pub m_base: u32,
	pub m_skip: u32,
	pub m_last: u32,
	pub m_attempt: u32,
	pub m_ok: u32,
	pub m_rng: u32,
	pub m_rng_end: u32,
	pub m_class_match: u32,
	pub m_negated: u32,
	pub m_rune: u32,
	pub m_s_after: u32,
	// Containment matcher (recursive rules and scopes).
	pub c_pat: u32,
	pub c_pat_end: u32,
	pub c_i: u32,
	// Results.
	pub denied: u32,
	pub covered: u32,
	pub overflow: u32,
}

impl EvalState {
	/// Zeroes the state through volatile word stores, so LLVM emits no `memset`
	/// call (the BPF verifier rejects the linker's global `memset`). Every field
	/// is a `u32`, so the size is a multiple of 4.
	#[inline(always)]
	pub fn reset(&mut self) {
		let words = self as *mut EvalState as *mut u32;
		let mut i = 0;
		while i < core::mem::size_of::<EvalState>() / 4 {
			// SAFETY: in bounds of `self`.
			unsafe { core::ptr::write_volatile(words.add(i), 0) };
			i += 1;
		}
	}
}

#[inline(always)]
fn byte_at(base: *const u8, pos: u32, mask: u32) -> u8 {
	// SAFETY: `base` is a map value of at least `mask + 1` bytes.
	unsafe { *base.add((pos & mask) as usize) }
}

/// One step of the evaluation+matcher state machine. The `bpf_loop` callback.
/// All persistent state is in the `EVAL` map value, looked up here.
#[inline(never)]
pub unsafe extern "C" fn eval_step(_index: u64, _ctx: *mut c_void) -> i64 {
	let Some(e) = crate::maps::EVAL.get_ptr_mut(0) else {
		return 1;
	};
	// SAFETY: this CPU's slot; the BPF program is non-preemptible here.
	let e = unsafe { &mut *e };
	let (Some(arena), Some(scratch)) = (ARENA.get_ptr(e.bank), SCRATCH.get_ptr(e.slot)) else {
		e.denied = 1;
		e.phase = E_DONE;
		return 1;
	};
	let arena = arena as *const u8;
	let scratch = scratch as *const u8;
	match e.phase {
		E_CONTEXT => step_context(e, arena, scratch),
		E_RULE => step_rule(e, arena, scratch),
		E_PARENT => step_parent(e),
		E_SCOPE => step_scope(e),
		MM_CHUNK => step_mm_chunk(e, scratch),
		MM_TOKEN => step_mm_token(e, arena, scratch),
		MM_CLASS => step_mm_class(e, arena),
		MM_CHUNKDONE => step_mm_chunkdone(e),
		MM_SKIP => step_mm_skip(e, scratch),
		MM_TRAILING => step_mm_trailing(e, scratch),
		RC_START => step_rc_start(e),
		RC_COMPARE => step_rc_compare(e, arena, scratch),
		_ => 1,
	}
}

#[inline(always)]
fn ctx_index(e: &EvalState) -> u32 {
	e.bank.wrapping_mul(filemaster_lsm_common::decision_maps::MAX_CONTEXTS as u32).wrapping_add(e.context)
}

fn step_context(e: &mut EvalState, arena: *const u8, scratch: *const u8) -> i64 {
	if e.context >= e.context_end {
		e.phase = E_DONE;
		return 1;
	}
	let Some(context) = CONTEXTS.get(ctx_index(e)) else {
		e.denied = 1;
		e.phase = E_DONE;
		return 1;
	};
	if context.flags & CONTEXT_OVERFLOW != 0 || context.scope_count > CONTEXT_SCOPES as u32 {
		e.overflow = 1;
		e.denied = 1;
		e.covered = 1;
		e.context += 1;
		return 0;
	}
	let path_len = context.path_len;
	if path_len > MAX_STRING as u32 {
		e.overflow = 1;
		e.denied = 1;
		e.covered = 1;
		e.context += 1;
		return 0;
	}
	// Build the full path = context path + the relative path the walk wrote.
	let start = if path_len > 0 {
		let start = e.rel.wrapping_sub(path_len);
		// SAFETY: masked offsets plus at most MAX_STRING bytes stay in slack.
		let read = unsafe {
			bpf_probe_read_kernel(
				scratch.add((start & SCRATCH_MASK) as usize) as *mut c_void,
				path_len & MAX_STRING as u32,
				arena.add((context.path_off & ARENA_MASK) as usize) as *const c_void,
			)
		};
		if read != 0 {
			e.overflow = 1;
			e.denied = 1;
			e.covered = 1;
			e.context += 1;
			return 0;
		}
		start
	} else if e.rel >= REL_END {
		// The object itself at "/": one slash.
		write_byte(scratch, REL_END - 1, b'/');
		REL_END - 1
	} else {
		e.rel
	};
	e.name_base = start;
	e.name_end = REL_END;
	e.parent_end = if e.rel < REL_END {
		if e.leaf > start {
			e.leaf
		} else {
			start + 1
		}
	} else {
		start + context.parent_len
	};
	e.rule = 0;
	e.rule_count = 0;
	e.scope_count = context.scope_count;
	e.phase = E_RULE;
	let key = PolicyListKey { bank: e.bank, policy: e.policy, context: e.context };
	// SAFETY: copied immediately.
	if let Some(list) = unsafe { POLICY_LISTS.get(&key) }.copied() {
		let index = e.bank.wrapping_mul(MAX_RULELISTS as u32).wrapping_add(list);
		let Some(rules) = RULELISTS.get(index) else {
			e.denied = 1;
			e.phase = E_DONE;
			return 1;
		};
		if rules.flags & RULELIST_OVERFLOW != 0 || rules.rule_count > CONTEXT_RULES as u32 {
			e.overflow = 1;
			e.denied = 1;
			e.covered = 1;
			e.context += 1;
			e.phase = E_CONTEXT;
			return 0;
		}
		e.rulelist = index;
		e.rule_count = rules.rule_count;
	}
	0
}

fn step_rule(e: &mut EvalState, _arena: *const u8, _scratch: *const u8) -> i64 {
	if e.rule >= e.rule_count {
		e.scope = 0;
		e.phase = E_SCOPE;
		return 0;
	}
	let Some(rules) = RULELISTS.get(e.rulelist) else {
		e.denied = 1;
		e.phase = E_DONE;
		return 1;
	};
	let rule = rules.rules[(e.rule as usize) & (CONTEXT_RULES - 1)];
	if rule.list as u32 != e.list {
		e.rule += 1;
		return 0;
	}
	e.rule_pattern = e.bank.wrapping_mul(MAX_PATTERNS as u32).wrapping_add(rule.pattern as u32);
	e.rule_flags = rule.flags as u32;
	if kind_applies(rule.flags, e.kind) {
		e.ret = RET_SELF;
		start_match(e, e.name_base, e.name_end);
	} else {
		e.phase = E_PARENT;
	}
	0
}

fn step_parent(e: &mut EvalState) -> i64 {
	if e.entry != 0 && kind_applies(e.rule_flags as u8, KIND_FOLDER) {
		e.ret = RET_PARENT;
		start_match(e, e.name_base, e.parent_end);
	} else {
		e.rule += 1;
		e.phase = E_RULE;
	}
	0
}

fn step_scope(e: &mut EvalState) -> i64 {
	if e.scope >= e.scope_count {
		// No rule applied and not in any scope: this context does not cover it.
		e.context += 1;
		e.phase = E_CONTEXT;
		return 0;
	}
	let Some(context) = CONTEXTS.get(ctx_index(e)) else {
		e.denied = 1;
		e.phase = E_DONE;
		return 1;
	};
	let scope = context.scopes[(e.scope as usize) & (CONTEXT_SCOPES - 1)];
	e.scope_exclude = scope.exclude;
	e.ret = RET_SCOPE;
	start_contains(e, scope.off, scope.len, e.name_base, e.name_end);
	0
}

/// Begins matching the current rule's pattern against `base..end`.
#[inline(always)]
fn start_match(e: &mut EvalState, base: u32, end: u32) {
	let Some(pattern) = PATTERNS.get(e.rule_pattern) else {
		// A missing pattern cannot match.
		finish(e, false);
		return;
	};
	e.win_base = base;
	e.win_end = end;
	if pattern.recursive != 0 {
		start_contains(e, pattern.off, pattern.len, base, end);
		return;
	}
	e.m_chunk = e.bank.wrapping_mul(MAX_CHUNKS as u32).wrapping_add(pattern.chunk_off);
	e.m_chunk_end = e.m_chunk.wrapping_add(pattern.chunk_len);
	e.m_s = base;
	e.phase = MM_CHUNK;
}

/// Begins a `pathContains(prefix, base..end)` match (recursive rule or scope).
#[inline(always)]
fn start_contains(e: &mut EvalState, prefix_off: u32, prefix_len: u32, base: u32, end: u32) {
	e.win_base = base;
	e.win_end = end;
	e.c_pat = prefix_off;
	e.c_pat_end = prefix_off.wrapping_add(prefix_len);
	e.c_i = 0;
	e.phase = RC_START;
}

fn step_mm_chunk(e: &mut EvalState, scratch: *const u8) -> i64 {
	if e.m_chunk >= e.m_chunk_end || e.m_chunk >= (filemaster_lsm_common::decision_maps::NUM_BANKS * MAX_CHUNKS) as u32 {
		// All chunks consumed: match iff the name is exhausted.
		finish(e, e.m_s >= e.win_end);
		return 0;
	}
	let Some(chunk) = CHUNKS.get(e.m_chunk) else {
		finish(e, false);
		return 0;
	};
	e.m_star = chunk.star;
	e.m_tok = e.bank.wrapping_mul(MAX_TOKENS as u32).wrapping_add(chunk.token_off);
	e.m_tok_end = e.m_tok.wrapping_add(chunk.token_len);
	e.m_last = (e.m_chunk + 1 >= e.m_chunk_end) as u32;
	if e.m_star != 0 && chunk.token_len == 0 {
		// Trailing star: matches the rest unless it has a separator.
		e.phase = MM_TRAILING;
		return 0;
	}
	e.m_base = e.m_s;
	e.m_attempt = 0;
	begin_attempt(e, e.m_s);
	let _ = scratch;
	0
}

/// Starts one matchChunk attempt at name position `s0`.
#[inline(always)]
fn begin_attempt(e: &mut EvalState, s0: u32) {
	let Some(chunk) = CHUNKS.get(e.m_chunk) else {
		finish(e, false);
		return;
	};
	e.m_tok = e.bank.wrapping_mul(MAX_TOKENS as u32).wrapping_add(chunk.token_off);
	e.m_tok_end = e.m_tok.wrapping_add(chunk.token_len);
	e.m_s = s0;
	e.phase = MM_TOKEN;
}

fn step_mm_token(e: &mut EvalState, arena: *const u8, scratch: *const u8) -> i64 {
	if e.m_tok >= e.m_tok_end || e.m_tok >= (filemaster_lsm_common::decision_maps::NUM_BANKS * MAX_TOKENS) as u32 {
		// Whole chunk matched; the rest of the name begins at m_s.
		e.m_ok = 1;
		e.phase = MM_CHUNKDONE;
		return 0;
	}
	if e.m_s >= e.win_end {
		e.m_ok = 0;
		e.phase = MM_CHUNKDONE;
		return 0;
	}
	let Some(token) = TOKENS.get(e.m_tok) else {
		finish(e, false);
		return 0;
	};
	match token.kind {
		TOKEN_LITERAL => {
			if byte_at(scratch, e.m_s, SCRATCH_MASK) != token.byte {
				e.m_ok = 0;
				e.phase = MM_CHUNKDONE;
				return 0;
			}
			e.m_s += 1;
			e.m_tok += 1;
		}
		TOKEN_QUESTION => {
			if byte_at(scratch, e.m_s, SCRATCH_MASK) == b'/' {
				e.m_ok = 0;
				e.phase = MM_CHUNKDONE;
				return 0;
			}
			let (_, n) = decode_rune(scratch, e.m_s, e.win_end, SCRATCH_MASK);
			e.m_s += n;
			e.m_tok += 1;
		}
		TOKEN_CLASS => {
			let (r, n) = decode_rune(scratch, e.m_s, e.win_end, SCRATCH_MASK);
			e.m_rune = r;
			e.m_s_after = e.m_s + n;
			e.m_rng = e.bank.wrapping_mul(MAX_RANGES as u32).wrapping_add(token.range_off);
			e.m_rng_end = e.m_rng.wrapping_add(token.range_len);
			e.m_class_match = 0;
			e.m_negated = token.negated as u32;
			e.phase = MM_CLASS;
		}
		_ => {
			finish(e, false);
		}
	}
	let _ = arena;
	0
}

fn step_mm_class(e: &mut EvalState, _arena: *const u8) -> i64 {
	if e.m_rng >= e.m_rng_end || e.m_rng >= (filemaster_lsm_common::decision_maps::NUM_BANKS * MAX_RANGES) as u32 {
		// Go: failed = (match == negated).
		if (e.m_class_match != 0) == (e.m_negated != 0) {
			e.m_ok = 0;
			e.phase = MM_CHUNKDONE;
		} else {
			e.m_s = e.m_s_after;
			e.m_tok += 1;
			e.phase = MM_TOKEN;
		}
		return 0;
	}
	let Some(range) = RANGES.get(e.m_rng) else {
		finish(e, false);
		return 0;
	};
	if range.lo <= e.m_rune && e.m_rune <= range.hi {
		e.m_class_match = 1;
	}
	e.m_rng += 1;
	0
}

fn step_mm_chunkdone(e: &mut EvalState) -> i64 {
	let ok = e.m_ok != 0;
	let t = e.m_s;
	if e.m_attempt == 0 {
		if ok && (t >= e.win_end || e.m_last == 0) {
			e.m_s = t;
			e.m_chunk += 1;
			e.phase = MM_CHUNK;
		} else if e.m_star != 0 {
			e.m_skip = 0;
			e.phase = MM_SKIP;
		} else {
			finish(e, false);
		}
		return 0;
	}
	if ok {
		if e.m_last != 0 && t < e.win_end {
			e.m_skip += 1;
			e.phase = MM_SKIP;
		} else {
			e.m_s = t;
			e.m_chunk += 1;
			e.phase = MM_CHUNK;
		}
	} else {
		e.m_skip += 1;
		e.phase = MM_SKIP;
	}
	0
}

fn step_mm_skip(e: &mut EvalState, scratch: *const u8) -> i64 {
	let i = e.m_base + e.m_skip;
	if i < e.win_end && byte_at(scratch, i, SCRATCH_MASK) != b'/' {
		e.m_attempt = 1;
		begin_attempt(e, i + 1);
		return 0;
	}
	finish(e, false);
	0
}

fn step_mm_trailing(e: &mut EvalState, scratch: *const u8) -> i64 {
	if e.m_s >= e.win_end {
		finish(e, true);
		return 0;
	}
	if byte_at(scratch, e.m_s, SCRATCH_MASK) == b'/' {
		finish(e, false);
		return 0;
	}
	e.m_s += 1;
	0
}

fn step_rc_start(e: &mut EvalState) -> i64 {
	let plen = e.c_pat_end.wrapping_sub(e.c_pat);
	let nlen = e.win_end.wrapping_sub(e.win_base);
	// "/" prefix contains everything.
	if plen == 1 {
		// A one-byte prefix is "/", which contains every absolute path.
		finish(e, true);
		return 0;
	}
	if nlen < plen {
		finish(e, false);
		return 0;
	}
	e.c_i = 0;
	e.phase = RC_COMPARE;
	0
}

fn step_rc_compare(e: &mut EvalState, arena: *const u8, scratch: *const u8) -> i64 {
	let plen = e.c_pat_end.wrapping_sub(e.c_pat);
	if e.c_i >= plen {
		// prefix matched; path == prefix, or the next name byte is '/'.
		let matched = e.win_end.wrapping_sub(e.win_base) == plen
			|| byte_at(scratch, e.win_base + plen, SCRATCH_MASK) == b'/';
		finish(e, matched);
		return 0;
	}
	if byte_at(arena, e.c_pat + e.c_i, ARENA_MASK) != byte_at(scratch, e.win_base + e.c_i, SCRATCH_MASK) {
		finish(e, false);
		return 0;
	}
	e.c_i += 1;
	0
}

/// Dispatches a finished match (matched/unmatched) back to its caller.
#[inline(always)]
fn finish(e: &mut EvalState, matched: bool) {
	match e.ret {
		RET_SELF => {
			if matched {
				rule_applies(e);
			} else {
				e.phase = E_PARENT;
			}
		}
		RET_PARENT => {
			if matched {
				rule_applies(e);
			} else {
				e.rule += 1;
				e.phase = E_RULE;
			}
		}
		RET_SCOPE => {
			if matched {
				if e.scope_exclude == 0 {
					if e.nomatch_allows != 0 {
						e.covered = 1;
					} else {
						e.denied = 1;
					}
				}
				// Either way, the first containing scope decides this context.
				e.context += 1;
				e.phase = E_CONTEXT;
			} else {
				e.scope += 1;
				e.phase = E_SCOPE;
			}
		}
		_ => {
			e.covered = matched as u32;
			e.phase = E_DONE;
		}
	}
}

/// Test-only: set up a single self-match of pattern `pattern_idx` (within
/// `bank`) against the scratch window `[base, end)`, driven by `eval_step` with
/// the `RET_TEST` terminal. Gate B populates the pattern tables and the scratch
/// name, then runs `eval_step` to completion and reads `covered`.
#[inline(always)]
#[allow(dead_code)]
pub fn setup_self_match(e: &mut EvalState, bank: u32, pattern_idx: u32, base: u32, end: u32) {
	e.bank = bank;
	e.rule_pattern = bank.wrapping_mul(MAX_PATTERNS as u32).wrapping_add(pattern_idx);
	e.ret = RET_TEST;
	start_match(e, base, end);
}

/// The current rule applies: its verdict decides this context (first match).
#[inline(always)]
fn rule_applies(e: &mut EvalState) {
	if e.rule_flags as u8 & RULE_ALLOW != 0 {
		e.covered = 1;
	} else {
		e.denied = 1;
	}
	e.context += 1;
	e.phase = E_CONTEXT;
}

#[inline(always)]
fn kind_applies(flags: u8, kind: u32) -> bool {
	let rule_kind = (flags >> RULE_KIND_SHIFT) & RULE_KIND_MASK;
	rule_kind == KIND_ANY || rule_kind as u32 == kind
}

#[inline(always)]
fn write_byte(scratch: *const u8, pos: u32, value: u8) {
	// SAFETY: masked offset into the per-CPU scratch map value.
	unsafe { *(scratch as *mut u8).add((pos & SCRATCH_MASK) as usize) = value };
}

/// utf8.DecodeRuneInString over the scratch window `[pos, end)`.
#[inline(always)]
fn decode_rune(base: *const u8, pos: u32, end: u32, mask: u32) -> (u32, u32) {
	let n = end.wrapping_sub(pos);
	let s0 = byte_at(base, pos, mask) as u32;
	if s0 < 0x80 {
		return (s0, 1);
	}
	let (size, lo, hi) = match s0 {
		0xC2..=0xDF => (2u32, 0x80u32, 0xBFu32),
		0xE0 => (3, 0xA0, 0xBF),
		0xE1..=0xEC | 0xEE..=0xEF => (3, 0x80, 0xBF),
		0xED => (3, 0x80, 0x9F),
		0xF0 => (4, 0x90, 0xBF),
		0xF1..=0xF3 => (4, 0x80, 0xBF),
		0xF4 => (4, 0x80, 0x8F),
		_ => return (RUNE_ERROR, 1),
	};
	if n < size {
		return (RUNE_ERROR, 1);
	}
	let s1 = byte_at(base, pos + 1, mask) as u32;
	if s1 < lo || hi < s1 {
		return (RUNE_ERROR, 1);
	}
	if size <= 2 {
		return ((s0 & 0x1F) << 6 | (s1 & 0x3F), 2);
	}
	let s2 = byte_at(base, pos + 2, mask) as u32;
	if !(0x80..=0xBF).contains(&s2) {
		return (RUNE_ERROR, 1);
	}
	if size <= 3 {
		return ((s0 & 0x0F) << 12 | (s1 & 0x3F) << 6 | (s2 & 0x3F), 3);
	}
	let s3 = byte_at(base, pos + 3, mask) as u32;
	if !(0x80..=0xBF).contains(&s3) {
		return (RUNE_ERROR, 1);
	}
	((s0 & 0x07) << 18 | (s1 & 0x3F) << 12 | (s2 & 0x3F) << 6 | (s3 & 0x3F), 4)
}
