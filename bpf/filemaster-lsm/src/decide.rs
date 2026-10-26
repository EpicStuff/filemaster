//! Filemaster's structural-decision data plane.
//!
//! Each hook walks from its target dentry up to the nearest registered object,
//! writing the names into a per-CPU path buffer back to front. Every context of
//! that object prefixes its absolute path, giving the exact path string the Go
//! engine decides, and the context's ordered rule list is matched against it
//! with the `matcher` port of `filepath.Match`. All loops run inside
//! `bpf_loop` callbacks.

use core::ffi::c_void;
use core::intrinsics::{AtomicOrdering, atomic_xadd, atomic_xsub};

use aya_ebpf::helpers::r#gen::{bpf_ktime_get_ns, bpf_loop, bpf_probe_read_kernel};
use filemaster_lsm_common::decision_maps::{
	EVAL_BUDGET, HOOKS, HOOK_LINK, HOOK_MKDIR, LIST_EXECUTE, LIST_READ, LIST_WRITE, MAX_REL, REASON_BUDGET,
	REASON_CONTEXT_OVERFLOW, REASON_DEPTH, REASON_PATH_TOO_LONG, REASON_UNREADABLE,
	REASON_PENDING, REASON_STATE_CONTENTION, REASON_UNREGISTERED_ROOT, REASON_WAIT_TIMEOUT, REL_END, SCRATCH_MASK, SCRATCH_SLOTS,
	STATE_SLOTS, WALK_LIMIT,
};
use filemaster_lsm_common::label_maps::{
	MAX_POLICIES, RECORD_DECISION, DECISION_DELETE, DECISION_CREATE, DECISION_RENAME, DECISION_LINK, DECISION_REASON_DEFAULT, DECISION_REASON_NONE,
	DECISION_ALLOW, DECISION_DENY, DECISION_AUDIT, DECISION_SOURCE_VALID, DECISION_TARGET_VALID,
	DECISION_PATH_MAX, DECISION_SUPPRESS_LIMIT, DECISION_SUPPRESS_WINDOW_NS, DecisionRecord,
	DecisionSuppressKey, DecisionSuppressValue,
};
use filemaster_lsm_common::{Bank, DecisionOp, Dev, FileId, Ino, ObjectKey, TargetKind, Verdict};

use crate::kernel;
use crate::label::{self, NO_REASON};
use aya_ebpf::macros::map;
use aya_ebpf::maps::PerCpuArray;
use crate::maps::{AUDIT, COUNTERS, DECISION_DROPS, DECISION_SUPPRESS, DECISION_ZERO, EVAL, NOMATCH, OBJECTS, RECORDS, SCRATCH, SETTINGS, STATE_CLAIMS};
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
	object: FileId,
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
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DecisionResult {
	verdict: Verdict,
	operation: DecisionOp,
	audit: u32,
	covered: u32,
	/// The labelling reason to count when this result denies.
	reason: u32,
	hook: u32,
	/// The caller's label and the table bank, for the decision's own record.
	label: u32,
	bank: u32,
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
	if result.reason >= REASON_PENDING && result.reason < filemaster_lsm_common::decision_maps::REASONS as u32 {
		count(result.reason, result.hook);
	}
	if result.audit != 0 {
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
	with_wait(hook, |flags| filemaster_remove(dentry.raw(), folder as u32, hook, DECISION_DELETE | flags))
}

/// `inode_mkdir`: Filemaster's `DecisionCreate` on a negative dentry.
pub fn mkdir(dentry: kernel::Dentry, hook: u32) -> Option<DecisionResult> {
	with_wait(hook, |flags| filemaster_mkdir(dentry.raw(), hook, DECISION_CREATE | flags))
}

/// `inode_link`: `DecisionSnapshot.DecideHardLink`'s source read/write/execute
/// order, then the destination delete/create order.
pub fn hard_link(source: kernel::Dentry, destination: kernel::Dentry, hook: u32) -> Option<DecisionResult> {
	with_wait(hook, |flags| filemaster_hard_link(source.raw(), destination.raw(), hook, DECISION_LINK | flags))
}

/// `inode_rename`: `DecisionSnapshot.DecideRename`. `security_inode_rename`
/// calls the hook a second time with the sides swapped for `RENAME_EXCHANGE`,
/// so each call is one directed rename onto an existing destination.
pub fn rename(source: kernel::Dentry, destination: kernel::Dentry, hook: u32) -> Option<DecisionResult> {
	with_wait(hook, |flags| filemaster_rename(source.raw(), destination.raw(), hook, DECISION_RENAME | flags))
}

/// In enforce mode, a pending caller's denial waits once for the daemon's
/// label, and then the whole operation is decided again, because the daemon
/// may have flipped the active bank to publish the new label's policy; a caller
/// still pending after a timed-out wait denies under its own reason. Audit
/// never waits: it records the pending would-deny and allows at once. Only the
/// decision that stands records itself.
#[inline(always)]
fn with_wait(hook: u32, decide: impl Fn(u32) -> u64) -> Option<DecisionResult> {
	let first_flags = if label::wait_enabled() { 0 } else { RECORD_FINAL };
	let first = unpack(hook, decide(first_flags))?;
	if first_flags != 0 || !may_wait(&first) {
		return Some(first);
	}
	let start = kernel::Task::current().group_leader().and_then(|leader| leader.start_boottime());
	let flags = match start.map(|start| label::wait_resolved(kernel::current_pid().0, start)) {
		Some(label::WAIT_TIMED_OUT) => RECORD_FINAL | RECORD_TIMED_OUT,
		_ => RECORD_FINAL,
	};
	unpack(hook, decide(flags))
}

/// A pending caller's enforced denial, which waits for the caller's label.
#[inline(always)]
fn may_wait(result: &DecisionResult) -> bool {
	!result.verdict.allows() && result.reason == REASON_PENDING && result.audit == 0
}

/// A decision packed into the `u64` a global BPF function can return: decided
/// (else fail open), deny, audit, no free state, and covered flags, the
/// operation in bits 8..16 and the reason in bits 32..64.
const PACKED_DECIDED: u64 = 1;
const PACKED_DENY: u64 = 1 << 1;
const PACKED_AUDIT: u64 = 1 << 2;
const PACKED_NO_STATE: u64 = 1 << 3;
const PACKED_COVERED: u64 = 1 << 4;

/// A decision's record request: the `DECISION_*` operation in the low byte;
/// `RECORD_FINAL` when no label wait can follow, so even a pending denial
/// records; `RECORD_TIMED_OUT` after a timed-out wait.
const RECORD_OPERATION: u32 = 0xFF;
const RECORD_FINAL: u32 = 1 << 8;
const RECORD_TIMED_OUT: u32 = 1 << 9;

/// Unpacks a decision. One that found every decision state on this CPU claimed
/// denies (fail closed; audit counts it and allows) without a record.
#[inline(always)]
fn unpack(hook: u32, packed: u64) -> Option<DecisionResult> {
	if packed & PACKED_NO_STATE == 0 {
		if packed & PACKED_DECIDED == 0 {
			return None;
		}
		return Some(DecisionResult {
			verdict: if packed & PACKED_DENY != 0 { Verdict::DENY } else { Verdict::ALLOW },
			operation: DecisionOp((packed >> 8) as u32 & 0xFF),
			audit: (packed & PACKED_AUDIT != 0) as u32,
			covered: (packed & PACKED_COVERED != 0) as u32,
			reason: (packed >> 32) as u32,
			hook,
			label: 0,
			bank: 0,
		});
	}
	increment(&DECISION_DROPS, 0);
	Some(DecisionResult {
		verdict: Verdict::DENY,
		operation: if hook == HOOK_MKDIR || hook == HOOK_LINK { DecisionOp::CREATE } else { DecisionOp::DELETE },
		audit: SETTINGS.get(0).is_some_and(|settings| settings.audit != 0) as u32,
		covered: 1,
		reason: REASON_STATE_CONTENTION,
		hook,
		label: 0,
		bank: 0,
	})
}

/// Runs one decision on a decision state of its own. LSM programs run under
/// `rcu_read_lock` and `migrate_disable` only, so with a preemptible RCU a hook
/// can be preempted mid-decision and other hooks run on this CPU meanwhile;
/// each claims a different state, so none ever writes another's. The claim is
/// held from before the first walk until the record is out.
#[inline(always)]
fn owned(record: u32, once: impl FnOnce(&Owner) -> Option<DecisionResult>) -> u64 {
	let state = filemaster_claim_state();
	// `STATE_SLOTS` (none free) is past the end of `STATE_CLAIMS`.
	let Some(claim) = STATE_CLAIMS.get_ptr_mut(state) else {
		return PACKED_NO_STATE;
	};
	let packed = match once(&Owner { state, record }) {
		None => 0,
		Some(result) => {
			PACKED_DECIDED
				| if result.verdict.allows() { 0 } else { PACKED_DENY }
				| if result.audit != 0 { PACKED_AUDIT } else { 0 }
				| if result.covered != 0 { PACKED_COVERED } else { 0 }
				| ((result.operation.0 & 0xFF) as u64) << 8
				| (result.reason as u64) << 32
		}
	};
	// SAFETY: this CPU's claim word, taken by `filemaster_claim_state`.
	unsafe { atomic_xsub::<u64, u64, { AtomicOrdering::SeqCst }>(claim, 1) };
	packed
}

/// Claims a free decision state on this CPU. A claim is an atomic add whose
/// result is 0: the word is non-zero for as long as the owner holds it, so no
/// other add can see 0 until the owner releases. An add that saw a non-zero
/// word is undone; such a transient count only makes the state look claimed.
/// The adds are wrapping subtracts of u64::MAX (see `label::wait_resolved`).
/// Returns the claimed state, or `STATE_SLOTS` when every state is claimed.
/// A global function, verified once per program.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn filemaster_claim_state() -> u32 {
	for state in 0..STATE_SLOTS as u32 {
		let Some(claim) = STATE_CLAIMS.get_ptr_mut(state) else {
			continue;
		};
		// SAFETY: an aligned u64 in this CPU's slot of a per-CPU array.
		unsafe {
			if core::ptr::read_volatile(claim) != 0 {
				continue;
			}
			if atomic_xsub::<u64, u64, { AtomicOrdering::SeqCst }>(claim, u64::MAX) == 0 {
				return state;
			}
			atomic_xsub::<u64, u64, { AtomicOrdering::SeqCst }>(claim, 1);
		}
	}
	STATE_SLOTS as u32
}

/// A running decision's claimed state and its record request.
struct Owner {
	state: u32,
	record: u32,
}

impl Owner {
	/// Settles a decision's reason and records it if it is covered and stands:
	/// no label wait follows it.
	#[inline(always)]
	fn conclude(&self, mut result: DecisionResult, destination: bool) -> DecisionResult {
		if self.record & RECORD_TIMED_OUT != 0 && may_wait(&result) {
			result.reason = REASON_WAIT_TIMEOUT;
		}
		if result.covered == 0 || self.record & RECORD_FINAL == 0 && may_wait(&result) {
			return result;
		}
		let verdict = if result.verdict.allows() { DECISION_ALLOW } else if result.audit != 0 { DECISION_AUDIT } else { DECISION_DENY };
		filemaster_record(
			result.label as u64
				| ((result.reason & 0xFF) as u64) << 32
				| ((self.record & RECORD_OPERATION) as u64) << 40
				| (verdict as u64) << 48
				| (destination as u64) << 52
				| ((result.bank & 0xFF) as u64) << 56,
			self.state,
		);
		result
	}
}

// The decisions are global BPF functions, verified once per program although
// a label wait makes a hook call one twice.

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn filemaster_remove(dentry: u64, folder: u32, hook: u32, record: u32) -> u64 {
	owned(record, |owner| remove_once(owner, kernel::Dentry::from_raw(dentry), folder != 0, hook))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn filemaster_mkdir(dentry: u64, hook: u32, record: u32) -> u64 {
	owned(record, |owner| mkdir_once(owner, kernel::Dentry::from_raw(dentry), hook))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn filemaster_hard_link(source: u64, destination: u64, hook: u32, record: u32) -> u64 {
	owned(record, |owner| hard_link_once(owner, kernel::Dentry::from_raw(source), kernel::Dentry::from_raw(destination), hook))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn filemaster_rename(source: u64, destination: u64, hook: u32, record: u32) -> u64 {
	owned(record, |owner| rename_once(owner, kernel::Dentry::from_raw(source), kernel::Dentry::from_raw(destination), hook))
}

#[inline(always)]
fn remove_once(owner: &Owner, dentry: kernel::Dentry, folder: bool, hook: u32) -> Option<DecisionResult> {
	let (bank, caller, audit) = live_settings(hook)?;
	let kind = if folder { TargetKind::FOLDER } else { positive_kind(dentry, hook)? };
	let target = walk(bank, caller.policy, owner.state * 2, dentry, hook)?;
	let mut decision = Decision::new(owner.state, bank, caller, audit, hook);
	decision.side(&target, DecisionOp::DELETE, kind, hook);
	Some(owner.conclude(decision.finish(), false))
}

#[inline(always)]
fn mkdir_once(owner: &Owner, dentry: kernel::Dentry, hook: u32) -> Option<DecisionResult> {
	let (bank, caller, audit) = live_settings(hook)?;
	let target = walk(bank, caller.policy, owner.state * 2, dentry, hook)?;
	let mut decision = Decision::new(owner.state, bank, caller, audit, hook);
	decision.side(&target, DecisionOp::CREATE, TargetKind::FOLDER, hook);
	Some(owner.conclude(decision.finish(), false))
}

#[inline(always)]
fn hard_link_once(owner: &Owner, source: kernel::Dentry, destination: kernel::Dentry, hook: u32) -> Option<DecisionResult> {
	let (bank, caller, audit) = live_settings(hook)?;
	let kind = positive_kind(source, hook)?;
	let destination_exists = exists(destination, hook)?;
	let source_walk = walk(bank, caller.policy, owner.state * 2, source, hook)?;
	let destination_walk = walk(bank, caller.policy, owner.state * 2 + 1, destination, hook)?;
	let mut decision = Decision::new(owner.state, bank, caller, audit, hook);
	'decided: {
		for operation in [DecisionOp::READ, DecisionOp::WRITE, DecisionOp::EXECUTE] {
			if decision.side(&source_walk, operation, kind, hook) {
				break 'decided;
			}
		}
		if destination_exists && decision.side(&destination_walk, DecisionOp::DELETE, kind, hook) {
			break 'decided;
		}
		decision.side(&destination_walk, DecisionOp::CREATE, kind, hook);
	}
	Some(owner.conclude(decision.finish(), true))
}

#[inline(always)]
fn rename_once(owner: &Owner, source: kernel::Dentry, destination: kernel::Dentry, hook: u32) -> Option<DecisionResult> {
	let (bank, caller, audit) = live_settings(hook)?;
	let source_kind = positive_kind(source, hook)?;
	let destination_exists = exists(destination, hook)?;
	let destination_kind = if destination_exists { positive_kind(destination, hook)? } else { source_kind };
	let source_walk = walk(bank, caller.policy, owner.state * 2, source, hook)?;
	let destination_walk = walk(bank, caller.policy, owner.state * 2 + 1, destination, hook)?;
	let mut decision = Decision::new(owner.state, bank, caller, audit, hook);
	'decided: {
		if decision.side(&source_walk, DecisionOp::DELETE, source_kind, hook) {
			break 'decided;
		}
		if !destination_exists {
			decision.side(&destination_walk, DecisionOp::CREATE, destination_kind, hook);
			break 'decided;
		}
		if decision.side(&destination_walk, DecisionOp::WRITE, destination_kind, hook) {
			break 'decided;
		}
		decision.side(&destination_walk, DecisionOp::DELETE, destination_kind, hook);
	}
	Some(owner.conclude(decision.finish(), true))
}

/// The engine-order combination of an operation's evaluations. An operation
/// none of whose evaluations is covered is allowed; otherwise an uncovered
/// evaluation takes the profile default, and the first deny decides.
struct Decision {
	state: u32,
	bank: u32,
	caller: label::Caller,
	audit: bool,
	hook: u32,
	covered: bool,
	deny: Option<DecisionOp>,
	covered_deny: bool,
	deny_reason: u32,
}

impl Decision {
	#[inline(always)]
	fn new(state: u32, bank: u32, caller: label::Caller, audit: bool, hook: u32) -> Decision {
		Decision { state, bank, caller, audit, hook, covered: false, deny: None, covered_deny: false, deny_reason: DECISION_REASON_NONE }
	}

	/// Adds one evaluation. Returns true once the verdict cannot change.
	#[inline(always)]
	fn side(&mut self, target: &Walk, operation: DecisionOp, kind: TargetKind, hook: u32) -> bool {
		let side = evaluate(self.state, target, operation, kind, hook);
		let denies = match side & 0xFF {
			SIDE_NOT_COVERED => !nomatch(self.bank, self.caller.policy, operation, kind),
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
			self.deny_reason = if side & 0xFF == SIDE_NOT_COVERED { DECISION_REASON_DEFAULT } else { side >> 8 };
		}
		self.covered_deny
	}

	#[inline(always)]
	fn finish(&self) -> DecisionResult {
		let (verdict, operation) = match self.deny {
			Some(operation) if self.covered => (Verdict::DENY, operation),
			_ => (Verdict::ALLOW, DecisionOp::READ),
		};
		DecisionResult {
			verdict,
			operation,
			audit: self.audit as u32,
			covered: self.covered as u32,
			reason: if verdict.allows() { DECISION_REASON_NONE } else if self.deny_reason < REASON_PENDING { self.deny_reason } else if self.caller.reason != NO_REASON { self.caller.reason } else { self.deny_reason },
			hook: self.hook,
			label: self.caller.label,
			bank: self.bank,
		}
	}
}

/// The active bank, the caller, and audit mode. `None` is the daemon's own
/// bypass or an unreadable caller.
#[inline(always)]
fn live_settings(hook: u32) -> Option<(u32, label::Caller, bool)> {
	let settings = SETTINGS.get(0).copied()?;
	let bank = Bank(settings.active_bank).masked().0;
	let caller = label::caller_policy(&settings, bank, hook)?;
	Some((bank, caller, settings.audit != 0))
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
fn walk(bank: u32, policy: u32, slot: u32, dentry: kernel::Dentry, hook: u32) -> Option<&'static Walk> {
	let Some(state) = WALKS.get_ptr_mut(slot) else {
		count(REASON_UNREADABLE, hook);
		return None;
	};
	// SAFETY: a slot of this CPU's state that the decision claimed.
	let state = unsafe { &mut *state };
	// Volatile zero stores, so LLVM emits no `memset` (the verifier rejects the
	// linker's global one).
	// SAFETY: fields of this CPU's slot.
	unsafe {
		core::ptr::write_volatile(&mut state.object, FileId::new(Dev(0), Ino(0)));
		core::ptr::write_volatile(&mut state.first_context, 0);
		core::ptr::write_volatile(&mut state.context_count, 0);
		core::ptr::write_volatile(&mut state.depth, 0);
	}
	state.dentry = dentry.raw();
	state.bank = bank;
	state.policy = policy;
	state.slot = slot;
	state.rel = REL_END;
	state.leaf = NO_LEAF;
	state.status = WALK_RUNNING;
	let mut slot = slot;
	// SAFETY: the callback only reads `slot`, which outlives the call.
	unsafe {
		bpf_loop(WALK_LIMIT + 1, walk_step as *mut c_void, &mut slot as *mut u32 as *mut c_void, 0);
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
	Some(state)
}

#[inline(never)]
unsafe extern "C" fn walk_step(_index: u64, ctx: *mut c_void) -> i64 {
	// SAFETY: `walk` passes its slot, and this CPU's `WALKS` value outlives the loop.
	let Some(w) = WALKS.get_ptr_mut(unsafe { *(ctx as *const u32) }) else {
		return 1;
	};
	let w = unsafe { &mut *w };
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
				w.object = key.file;
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
fn evaluate(state: u32, target: &Walk, operation: DecisionOp, kind: TargetKind, hook: u32) -> u32 {
	match target.status {
		WALK_FOUND => {}
		WALK_TOO_LONG => return SIDE_DENY | (REASON_PATH_TOO_LONG << 8),
		WALK_DEPTH => return SIDE_DENY | (REASON_DEPTH << 8),
		_ => return SIDE_NOT_COVERED,
	}
	let list = match operation {
		DecisionOp::READ => LIST_READ,
		DecisionOp::EXECUTE => LIST_EXECUTE,
		_ => LIST_WRITE,
	};
	let entry = operation == DecisionOp::CREATE || operation == DecisionOp::DELETE;
	let Some(e) = EVAL.get_ptr_mut(state) else {
		count(REASON_UNREADABLE, hook);
		return SIDE_DENY | (REASON_UNREADABLE << 8);
	};
	// SAFETY: this CPU's state that the decision claimed.
	let e = unsafe { &mut *e };
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
	filemaster_evaluate(hook, state)
}

/// Runs the matcher once per program through a global function.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn filemaster_evaluate(hook: u32, state: u32) -> u32 {
	let mut index = state;
	// SAFETY: the callback only reads `index` and the EVAL map value, which
	// outlive the call.
	unsafe {
		bpf_loop(EVAL_BUDGET, matcher::eval_step as *mut c_void, &mut index as *mut u32 as *mut c_void, 0);
	}
	let Some(e) = EVAL.get_ptr_mut(state) else {
		count(REASON_UNREADABLE, hook);
		return SIDE_DENY | (REASON_UNREADABLE << 8);
	};
	// SAFETY: this CPU's state that the decision claimed.
	let e = unsafe { &mut *e };
	if e.phase != matcher::E_DONE_PUB {
		count(REASON_BUDGET, hook);
		return SIDE_DENY | (REASON_BUDGET << 8);
	}
	if e.overflow != 0 {
		count(REASON_CONTEXT_OVERFLOW, hook);
		return SIDE_DENY | (REASON_CONTEXT_OVERFLOW << 8);
	}
	if e.denied != 0 {
		SIDE_DENY | (e.deny_reason << 8)
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
	// Atomic: a preempted read-modify-write would lose another hook's count.
	// SAFETY: this CPU's slot of a per-CPU array.
	unsafe { atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(counter, 1) };
}

#[inline(always)]
fn suppress(key: DecisionSuppressKey, now: u64) -> Option<u32> {
	// SAFETY: the value is read or updated before the hook returns.
	if let Some(value) = DECISION_SUPPRESS.get_ptr_mut(&key) {
		// SAFETY: a live map value; concurrent updates may reduce suppression,
		// but cannot change a decision.
		let value = unsafe { &mut *value };
		if now.wrapping_sub(value.window_start) >= DECISION_SUPPRESS_WINDOW_NS {
			let dropped = value.dropped;
			value.window_start = now;
			value.emitted = 1;
			value.dropped = 0;
			return Some(dropped.min(u32::MAX as u64) as u32);
		}
		// SAFETY: aligned fields in a map value shared across CPUs.
		let prior = unsafe { atomic_xsub::<u64, u64, { AtomicOrdering::SeqCst }>(&mut value.emitted, u64::MAX) };
		if prior >= DECISION_SUPPRESS_LIMIT as u64 {
			unsafe { atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(&mut value.dropped, 1) };
			increment(&DECISION_DROPS, 0);
			return None;
		}
		return Some(0);
	}
	let value = DecisionSuppressValue { window_start: now, emitted: 1, dropped: 0 };
	let _ = DECISION_SUPPRESS.insert(&key, &value, 0);
	Some(0)
}

#[inline(always)]
fn record_path(walk: &Walk, to: *mut u8) -> Option<(FileId, u32, u32)> {
	if walk.status != WALK_FOUND || walk.rel > REL_END {
		return None;
	}
	let raw = REL_END - walk.rel;
	let buffer = SCRATCH.get_ptr_mut(walk.slot)? as *const u8;
	let from = unsafe { buffer.add((walk.rel & SCRATCH_MASK) as usize) };
	if raw == MAX_REL {
		// SAFETY: the walk bounded this exact-size path in its scratch slot.
		if unsafe { bpf_probe_read_kernel(to as *mut c_void, MAX_REL, from as *const c_void) } != 0 {
			return None;
		}
		return Some((walk.object, walk.first_context, raw));
	}
	let len = raw & (MAX_REL - 1);
	if raw != len {
		return None;
	}
	if len != 0 {
		// SAFETY: the mask bounds the source length below DECISION_PATH_MAX.
		if unsafe { bpf_probe_read_kernel(to as *mut c_void, len, from as *const c_void) } != 0 {
			return None;
		}
	}
	Some((walk.object, walk.first_context, len))
}

/// This CPU's walks, one per scratch slot, so two per decision state. In map
/// memory, the verifier tracks them loosely, as it does `EVAL`.
#[map]
static WALKS: PerCpuArray<Walk> = PerCpuArray::with_max_entries(SCRATCH_SLOTS as u32, 0);

/// Emits a covered decision that stands, from the `WALKS` of the decision
/// state that decided it, which the decision still holds. `decision` packs the
/// label (bits 0..32), reason (32..40), `DECISION_*` operation (40..48), record
/// verdict (48..52), whether the state's second walk is a destination (52)
/// and bank (56..64). Returns 1 once a record is submitted. A global function,
/// so it is verified once per program rather than once per decision path.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn filemaster_record(decision: u64, state: u32) -> u64 {
	let label = decision as u32;
	let reason = (decision >> 32) as u32 & 0xFF;
	let operation = (decision >> 40) as u32 & 0xFF;
	let verdict = (decision >> 48) as u32 & 0xF;
	let destination = decision & (1 << 52) != 0;
	let bank = (decision >> 56) as u32;
	let (Some(source), Some(target)) = (WALKS.get_ptr(state * 2), WALKS.get_ptr(state * 2 + 1)) else {
		increment(&DECISION_DROPS, 0);
		return 0;
	};
	// SAFETY: helper returns CLOCK_MONOTONIC nanoseconds.
	let now = unsafe { bpf_ktime_get_ns() };
	let Some(suppressed) = suppress(DecisionSuppressKey { label, operation, verdict }, now) else {
		return 0;
	};
	let Some(zero) = DECISION_ZERO.get(0) else {
		increment(&DECISION_DROPS, 0);
		return 0;
	};
	let Some(mut entry) = RECORDS.reserve::<DecisionRecord>(0) else {
		increment(&DECISION_DROPS, 0);
		return 0;
	};
	let tgid = kernel::current_pid().0;
	let start = kernel::Task::current().group_leader().and_then(|leader| leader.start_boottime()).unwrap_or(0);
	let record = entry.as_mut_ptr();
	// SAFETY: this is a private ring reservation of exactly DecisionRecord
	// bytes. Every header field and both path arrays are initialized before
	// it can be submitted.
	unsafe {
		(*record).kind = RECORD_DECISION;
		(*record).operation = operation;
		(*record).verdict = verdict;
		(*record).reason = if verdict == DECISION_ALLOW { DECISION_REASON_NONE } else { reason };
		(*record).tgid = tgid;
		(*record).label = label;
		(*record).bank = bank;
		core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).flags), 0);
		(*record).start = start;
		core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).source.dev), Dev(0));
		core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).source.ino), Ino(0));
		core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).target.dev), Dev(0));
		core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).target.ino), Ino(0));
		core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).source_context), 0);
		core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).target_context), 0);
		core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).source_len), 0);
		core::ptr::write_volatile(core::ptr::addr_of_mut!((*record).target_len), 0);
		(*record).suppressed = suppressed;
		core::ptr::write_volatile(core::ptr::addr_of_mut!((*record)._pad), 0);
	}
	let source_bytes = unsafe { core::ptr::addr_of_mut!((*record).source_path) as *mut u8 };
	let target_bytes = unsafe { core::ptr::addr_of_mut!((*record).target_path) as *mut u8 };
	let zero_bytes = zero.0.as_ptr();
	// SAFETY: the zero map value and each reserved path array have exactly
	// DECISION_PATH_MAX bytes.
	let (clear_source, clear_target) = unsafe {
		(
			bpf_probe_read_kernel(source_bytes as *mut c_void, DECISION_PATH_MAX as u32, zero_bytes as *const c_void),
			bpf_probe_read_kernel(target_bytes as *mut c_void, DECISION_PATH_MAX as u32, zero_bytes as *const c_void),
		)
	};
	if clear_source != 0 || clear_target != 0 {
		entry.discard(0);
		increment(&DECISION_DROPS, 0);
		return 0;
	}
	// SAFETY: the walks of this CPU's state that the decision claimed.
	let (source, target) = unsafe { (&*source, &*target) };
	if let Some((id, context, len)) = record_path(source, source_bytes) {
		unsafe {
			(*record).source = id;
			(*record).source_context = context;
			(*record).source_len = len;
			(*record).flags |= DECISION_SOURCE_VALID;
		}
	}
	if let Some((id, context, len)) = if destination { record_path(target, target_bytes) } else { None } {
		unsafe {
			(*record).target = id;
			(*record).target_context = context;
			(*record).target_len = len;
			(*record).flags |= DECISION_TARGET_VALID;
		}
	}
	entry.submit(0);
	1
}
