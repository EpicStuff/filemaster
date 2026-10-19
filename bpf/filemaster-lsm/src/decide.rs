//! Filemaster's structural-decision data plane.
//!
//! Each hook walks from its target dentry up to the nearest registered object,
//! writing the names into a per-CPU path buffer back to front. Every context of
//! that object prefixes its absolute path, giving the exact path string the Go
//! engine decides, and the context's ordered rule list is matched against it
//! with the `matcher` port of `filepath.Match`. All loops run inside
//! `bpf_loop` callbacks.

use core::ffi::c_void;

use aya_ebpf::helpers::r#gen::{bpf_loop, bpf_probe_read_kernel};
use filemaster_lsm_common::decision_maps::{
	EVAL_BUDGET, HOOKS, LIST_EXECUTE, LIST_READ, LIST_WRITE, MAX_REL, REASON_BUDGET,
	REASON_CONTEXT_OVERFLOW, REASON_DEPTH, REASON_PATH_TOO_LONG, REASON_UNREADABLE,
	REASON_UNREGISTERED_ROOT, REL_END, SCRATCH_MASK, WALK_LIMIT,
};
use filemaster_lsm_common::label_maps::MAX_POLICIES;
use filemaster_lsm_common::{Bank, DecisionOp, FileId, ObjectKey, TargetKind, Verdict};

use crate::kernel;
use crate::label::{self, NO_REASON};
use crate::maps::{AUDIT, COUNTERS, EVAL, NOMATCH, OBJECTS, SCRATCH, SETTINGS};
use crate::matcher::{self, SIDE_ALLOW, SIDE_DENY, SIDE_NOT_COVERED};

const WALK_RUNNING: u32 = 0;
const WALK_FOUND: u32 = 1;
const WALK_UNREGISTERED: u32 = 2;
const WALK_TOO_LONG: u32 = 3;
const WALK_UNREADABLE: u32 = 4;
const WALK_DEPTH: u32 = 5;

const NO_LEAF: u32 = u32::MAX;

/// A walk from one target dentry to its object. `rel..REL_END` of the slot's
/// buffer holds the relative path, and `leaf` is the slash before the leaf name.
#[repr(C)]
#[derive(Clone, Copy)]
struct Walk {
	dentry: u64,
	bank: u32,
	policy: u32,
	slot: u32,
	rel: u32,
	leaf: u32,
	status: u32,
	first_context: u32,
	context_count: u32,
	depth: u32,
	_pad: u32,
}


/// An operation's raw verdict and the operation responsible for a possible
/// would-deny audit count.
#[derive(Clone, Copy)]
pub struct DecisionResult {
	verdict: Verdict,
	operation: DecisionOp,
	audit: bool,
	/// The labelling reason to count when this result denies.
	reason: u32,
	hook: u32,
}

/// Lower a result to a verifier-bounded LSM return. `None` means an unreadable
/// kernel value or the daemon's own I/O bypass, both deliberately fail open.
pub fn clamped(result: Option<DecisionResult>) -> i32 {
	let Some(result) = result else {
		return 0;
	};
	if result.verdict.allows() {
		return 0;
	}
	if result.reason != NO_REASON {
		count(result.reason, result.hook);
	}
	if result.audit {
		increment(&AUDIT, result.operation.0);
		return 0;
	}

	// Keep this branch visible to LLVM: the v6.12 verifier requires proof that
	// R0 is within the LSM errno range even though the source has only two
	// possible results.
	let ret = core::hint::black_box(-1i32);
	if ret == -1 { -1 } else { 0 }
}

/// `inode_unlink` and `inode_rmdir`: Filemaster's `DecisionDelete`.
pub fn remove(dentry: kernel::Dentry, folder: bool, hook: u32) -> Option<DecisionResult> {
	let (bank, policy, reason, audit) = live_settings(hook)?;
	let kind = if folder { TargetKind::FOLDER } else { positive_kind(dentry, hook)? };
	let target = walk(bank, policy, 0, dentry, hook)?;
	let mut decision = Decision::new(bank, policy, audit, reason, hook);
	decision.side(&target, DecisionOp::DELETE, kind, hook);
	Some(decision.finish())
}

/// `inode_mkdir`: Filemaster's `DecisionCreate` on a negative dentry.
pub fn mkdir(dentry: kernel::Dentry, hook: u32) -> Option<DecisionResult> {
	let (bank, policy, reason, audit) = live_settings(hook)?;
	let target = walk(bank, policy, 0, dentry, hook)?;
	let mut decision = Decision::new(bank, policy, audit, reason, hook);
	decision.side(&target, DecisionOp::CREATE, TargetKind::FOLDER, hook);
	Some(decision.finish())
}

/// `inode_link`: `DecisionSnapshot.DecideHardLink`'s source read/write/execute
/// order, then the destination delete/create order.
pub fn hard_link(source: kernel::Dentry, destination: kernel::Dentry, hook: u32) -> Option<DecisionResult> {
	let (bank, policy, reason, audit) = live_settings(hook)?;
	let kind = positive_kind(source, hook)?;
	let destination_exists = exists(destination, hook)?;
	let source_walk = walk(bank, policy, 0, source, hook)?;
	let destination_walk = walk(bank, policy, 1, destination, hook)?;
	let mut decision = Decision::new(bank, policy, audit, reason, hook);
	for operation in [DecisionOp::READ, DecisionOp::WRITE, DecisionOp::EXECUTE] {
		if decision.side(&source_walk, operation, kind, hook) {
			return Some(decision.finish());
		}
	}
	if destination_exists && decision.side(&destination_walk, DecisionOp::DELETE, kind, hook) {
		return Some(decision.finish());
	}
	decision.side(&destination_walk, DecisionOp::CREATE, kind, hook);
	Some(decision.finish())
}

/// `inode_rename`: `DecisionSnapshot.DecideRename`. `security_inode_rename`
/// calls the hook a second time with the sides swapped for `RENAME_EXCHANGE`,
/// so each call is one directed rename onto an existing destination.
pub fn rename(source: kernel::Dentry, destination: kernel::Dentry, hook: u32) -> Option<DecisionResult> {
	let (bank, policy, reason, audit) = live_settings(hook)?;
	let source_kind = positive_kind(source, hook)?;
	let destination_exists = exists(destination, hook)?;
	let destination_kind = if destination_exists { positive_kind(destination, hook)? } else { source_kind };
	let source_walk = walk(bank, policy, 0, source, hook)?;
	let destination_walk = walk(bank, policy, 1, destination, hook)?;
	let mut decision = Decision::new(bank, policy, audit, reason, hook);
	if decision.side(&source_walk, DecisionOp::DELETE, source_kind, hook) {
		return Some(decision.finish());
	}
	if !destination_exists {
		decision.side(&destination_walk, DecisionOp::CREATE, destination_kind, hook);
		return Some(decision.finish());
	}
	if decision.side(&destination_walk, DecisionOp::WRITE, destination_kind, hook) {
		return Some(decision.finish());
	}
	decision.side(&destination_walk, DecisionOp::DELETE, destination_kind, hook);
	Some(decision.finish())
}

/// The engine-order combination of an operation's evaluations. An operation
/// none of whose evaluations is covered is allowed; otherwise an uncovered
/// evaluation takes the profile default, and the first deny decides.
struct Decision {
	bank: u32,
	policy: u32,
	audit: bool,
	reason: u32,
	hook: u32,
	covered: bool,
	deny: Option<DecisionOp>,
	covered_deny: bool,
}

impl Decision {
	#[inline(always)]
	fn new(bank: u32, policy: u32, audit: bool, reason: u32, hook: u32) -> Decision {
		Decision { bank, policy, audit, reason, hook, covered: false, deny: None, covered_deny: false }
	}

	/// Adds one evaluation. Returns true once the verdict cannot change.
	#[inline(always)]
	fn side(&mut self, target: &Walk, operation: DecisionOp, kind: TargetKind, hook: u32) -> bool {
		let side = evaluate(target, operation, kind, hook);
		let denies = match side {
			SIDE_NOT_COVERED => !nomatch(self.bank, self.policy, operation, kind),
			SIDE_ALLOW => {
				self.covered = true;
				false
			}
			_ => {
				self.covered = true;
				self.covered_deny = true;
				true
			}
		};
		if denies && self.deny.is_none() {
			self.deny = Some(operation);
		}
		self.covered_deny
	}

	#[inline(always)]
	fn finish(&self) -> DecisionResult {
		match self.deny {
			Some(operation) if self.covered => {
				DecisionResult { verdict: Verdict::DENY, operation, audit: self.audit, reason: self.reason, hook: self.hook }
			}
			_ => DecisionResult {
				verdict: Verdict::ALLOW,
				operation: DecisionOp::READ,
				audit: self.audit,
				reason: self.reason,
				hook: self.hook,
			},
		}
	}
}

/// The active bank, the caller's policy and labelling reason, and audit mode.
/// `None` is the daemon's own bypass or an unreadable caller.
#[inline(always)]
fn live_settings(hook: u32) -> Option<(u32, u32, u32, bool)> {
	let settings = SETTINGS.get(0).copied()?;
	let bank = Bank(settings.active_bank).masked().0;
	let (policy, reason) = label::caller_policy(&settings, bank, hook)?;
	Some((bank, policy, reason, settings.audit != 0))
}

#[inline(always)]
fn positive_kind(dentry: kernel::Dentry, hook: u32) -> Option<TargetKind> {
	let Some(mode) = dentry.inode().and_then(|inode| inode.mode()) else {
		count(REASON_UNREADABLE, hook);
		return None;
	};
	Some(kind_of(mode))
}

#[inline(always)]
fn exists(dentry: kernel::Dentry, hook: u32) -> Option<bool> {
	let Some(inode) = dentry.inode_or_negative() else {
		count(REASON_UNREADABLE, hook);
		return None;
	};
	Some(inode.is_some())
}

#[inline(always)]
fn kind_of(mode: u16) -> TargetKind {
	if is_dir(mode) { TargetKind::FOLDER } else { TargetKind::FILE }
}

#[inline(always)]
fn is_dir(mode: u16) -> bool {
	const S_IFMT: u16 = 0o170000;
	const S_IFDIR: u16 = 0o040000;
	mode & S_IFMT == S_IFDIR
}

/// Walks from `dentry` to its object. `None` (counted) means a kernel value
/// was unreadable and the operation fails open.
#[inline(always)]
fn walk(bank: u32, policy: u32, slot: u32, dentry: kernel::Dentry, hook: u32) -> Option<Walk> {
	let mut storage = core::mem::MaybeUninit::<Walk>::uninit();
	// Volatile word stores, so LLVM emits no `memset` (the verifier rejects the
	// linker's global one). Walk is all integers, size a multiple of 4.
	let words = storage.as_mut_ptr() as *mut u32;
	let mut i = 0;
	while i < core::mem::size_of::<Walk>() / 4 {
		// SAFETY: in bounds of `storage`.
		unsafe { core::ptr::write_volatile(words.add(i), 0) };
		i += 1;
	}
	// SAFETY: fully initialized above.
	let state = unsafe { storage.assume_init_mut() };
	state.dentry = dentry.raw();
	state.bank = bank;
	state.policy = policy;
	state.slot = slot;
	state.rel = REL_END;
	state.leaf = NO_LEAF;
	state.status = WALK_RUNNING;
	// SAFETY: the callback only reads `state`, which outlives the call.
	unsafe {
		bpf_loop(WALK_LIMIT + 1, walk_step as *mut c_void, state as *mut Walk as *mut c_void, 0);
	}
	match state.status {
		WALK_RUNNING => {
			state.status = WALK_DEPTH;
			count(REASON_DEPTH, hook);
		}
		WALK_TOO_LONG => count(REASON_PATH_TOO_LONG, hook),
		WALK_UNREGISTERED => count(REASON_UNREGISTERED_ROOT, hook),
		WALK_UNREADABLE => {
			count(REASON_UNREADABLE, hook);
			return None;
		}
		_ => {}
	}
	Some(*state)
}

#[inline(never)]
unsafe extern "C" fn walk_step(_index: u64, ctx: *mut c_void) -> i64 {
	// SAFETY: `walk` passes its own stack state.
	let w = unsafe { &mut *(ctx as *mut Walk) };
	let dentry = kernel::Dentry::from_raw(w.dentry);
	let Some(inode) = dentry.inode_or_negative() else {
		w.status = WALK_UNREADABLE;
		return 1;
	};
	if let Some(inode) = inode {
		let Some(mode) = inode.mode() else {
			w.status = WALK_UNREADABLE;
			return 1;
		};
		if is_dir(mode) {
			let (Some(dev), Some(ino)) = (dentry.super_block().and_then(|sb| sb.dev()), inode.ino()) else {
				w.status = WALK_UNREADABLE;
				return 1;
			};
			let key = ObjectKey::new(Bank(w.bank), FileId::new(dev, ino));
			// SAFETY: copied immediately; a concurrent update cannot alias it.
			if let Some(object) = unsafe { OBJECTS.get(&key) }.copied() {
				w.first_context = object.first_context;
				w.context_count = object.context_count;
				w.status = WALK_FOUND;
				return 1;
			}
		}
	}
	let Some(parent) = dentry.parent() else {
		w.status = WALK_UNREADABLE;
		return 1;
	};
	if parent == dentry {
		w.status = WALK_UNREGISTERED;
		return 1;
	}
	let Some((name, len)) = dentry.name() else {
		w.status = WALK_UNREADABLE;
		return 1;
	};
	if len == 0 || len > 255 {
		w.status = WALK_UNREADABLE;
		return 1;
	}
	if w.rel < REL_END - MAX_REL + len + 1 {
		w.status = WALK_TOO_LONG;
		return 1;
	}
	let Some(buffer) = SCRATCH.get_ptr_mut(w.slot) else {
		w.status = WALK_UNREADABLE;
		return 1;
	};
	let buffer = buffer as *mut u8;
	let start = w.rel - len;
	// SAFETY: a masked offset plus at most 255 bytes stays inside the slack.
	let read = unsafe {
		bpf_probe_read_kernel(
			buffer.add((start & SCRATCH_MASK) as usize) as *mut c_void,
			len & 0xFF,
			name as *const c_void,
		)
	};
	if read != 0 {
		w.status = WALK_UNREADABLE;
		return 1;
	}
	// SAFETY: masked into the buffer.
	unsafe { *buffer.add(((start - 1) & SCRATCH_MASK) as usize) = b'/' };
	w.rel = start - 1;
	if w.leaf == NO_LEAF {
		w.leaf = w.rel;
	}
	w.depth += 1;
	w.dentry = parent.raw();
	0
}

/// Evaluates one operation on a walked target: `SIDE_ALLOW` or `SIDE_DENY` when
/// a rule matched or the target is in a watch scope, `SIDE_NOT_COVERED` when
/// neither holds in any context.
// A subprogram (not inlined): hooks call it up to five times, and inlining it
// would multiply the verifier's path exploration past the instruction limit.
#[inline(never)]
fn evaluate(target: &Walk, operation: DecisionOp, kind: TargetKind, hook: u32) -> u32 {
	match target.status {
		WALK_FOUND => {}
		WALK_TOO_LONG | WALK_DEPTH => return SIDE_DENY,
		_ => return SIDE_NOT_COVERED,
	}
	let list = match operation {
		DecisionOp::READ => LIST_READ,
		DecisionOp::EXECUTE => LIST_EXECUTE,
		_ => LIST_WRITE,
	};
	let entry = operation == DecisionOp::CREATE || operation == DecisionOp::DELETE;
	let Some(state) = EVAL.get_ptr_mut(0) else {
		count(REASON_UNREADABLE, hook);
		return SIDE_DENY;
	};
	// SAFETY: this CPU's slot; the program is non-preemptible while using it.
	let e = unsafe { &mut *state };
	e.reset();
	e.bank = target.bank;
	e.policy = target.policy;
	e.slot = target.slot;
	e.rel = target.rel;
	e.leaf = target.leaf;
	e.context = target.first_context;
	e.context_end = target.first_context.wrapping_add(target.context_count);
	e.list = list as u32;
	e.kind = kind.0;
	e.entry = entry as u32;
	e.nomatch_allows = nomatch(target.bank, target.policy, operation, kind) as u32;
	// SAFETY: the callback reads the EVAL map value, which outlives the call.
	unsafe {
		bpf_loop(EVAL_BUDGET, matcher::eval_step as *mut c_void, core::ptr::null_mut(), 0);
	}
	let Some(state) = EVAL.get_ptr_mut(0) else {
		count(REASON_UNREADABLE, hook);
		return SIDE_DENY;
	};
	// SAFETY: as above.
	let e = unsafe { &mut *state };
	if e.phase != matcher::E_DONE_PUB {
		count(REASON_BUDGET, hook);
		return SIDE_DENY;
	}
	if e.overflow != 0 {
		count(REASON_CONTEXT_OVERFLOW, hook);
	}
	if e.denied != 0 {
		SIDE_DENY
	} else if e.covered != 0 {
		SIDE_ALLOW
	} else {
		SIDE_NOT_COVERED
	}
}

#[inline(always)]
fn nomatch(bank: u32, policy: u32, operation: DecisionOp, kind: TargetKind) -> bool {
	let index = (bank * MAX_POLICIES as u32 + policy) * 10 + operation.0 * 2 + kind.0.wrapping_sub(1);
	NOMATCH.get(index).copied().unwrap_or(Verdict::DENY.0) == Verdict::ALLOW.0
}

#[inline(always)]
pub fn count(reason: u32, hook: u32) {
	increment(&COUNTERS, reason * HOOKS as u32 + hook);
}

#[inline(always)]
fn increment(map: &aya_ebpf::maps::PerCpuArray<u64>, index: u32) {
	let Some(counter) = map.get_ptr_mut(index) else {
		return;
	};
	// SAFETY: this CPU's slot of a per-CPU array.
	unsafe { *counter = (*counter).wrapping_add(1) };
}
