//! Process labelling (M3). Fork copies the parent's label, exec recomputes it
//! from `EXEC_LABELS` or leaves the process pending and records its argv and
//! envp for the daemon, and the last thread's exit deletes it. The structural
//! hooks turn the caller's label into a policy with `caller_policy`.
//!
//! The record path runs only in `tp_btf` programs, which run with preemption
//! disabled, so the per-CPU record buffer is never shared by two programs.

use core::ffi::c_void;

use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::helpers::r#gen::bpf_probe_read_user;
use filemaster_lsm_common::decision_maps::{REASON_PENDING, REASON_UNLABELLED, REASON_UNREADABLE};
use filemaster_lsm_common::label_maps::{
	ARGS_MASK, ARGS_MAX, ENV_MASK, ENV_MAX, LABEL_COUNTER_FULL, LABEL_COUNTER_RECORD_DROP,
	LABEL_COUNTER_UNREADABLE, LABEL_MASK, LABEL_PENDING, LABEL_UNIDENTIFIED, MAX_LABELS,
	POLICY_PENDING, RECORD_ARGS_TRUNCATED, RECORD_ENV_TRUNCATED, RECORD_EXEC, RECORD_FORK,
	RECORD_SIZE_MASK, SETTINGS_LABELLING,
};
use filemaster_lsm_common::{ExecFile, ExecLabelKey, ProcValue, RecordHeader, Settings};

use crate::kernel::{self, Binprm, Mm, Task};
use crate::maps::{
	EXEC_LABELS, EXEC_SCRATCH, LABEL_COUNTERS, LABEL_POLICY, PROCS, RECORDS, RECORD_BUF, RESOLVED,
	SETTINGS,
};

/// No labelling reason to count.
pub const NO_REASON: u32 = u32::MAX;
const NO_FILE: ExecFile = ExecFile { dev: 0, ino: 0, generation: 0, _pad: 0 };
const HEADER: u32 = core::mem::size_of::<RecordHeader>() as u32;

/// The caller's policy in `bank`, and the reason to count if it denies.
/// `None` is the daemon's own bypass or an unreadable caller (fail open).
#[inline(always)]
pub fn caller_policy(settings: &Settings, bank: u32, hook: u32) -> Option<(u32, u32)> {
	let task = Task::current();
	let tgid = kernel::current_pid().0;
	let Some(start) = task.group_leader().and_then(|leader| leader.start_boottime()) else {
		crate::decide::count(REASON_UNREADABLE, hook);
		return None;
	};
	if tgid == settings.daemon_tgid && start.wrapping_sub(settings.daemon_start) <= settings.daemon_span as u64 {
		return None;
	}
	let label = if settings.flags & SETTINGS_LABELLING == 0 {
		LABEL_UNIDENTIFIED
	} else {
		match task.mm() {
			Some(None) => LABEL_UNIDENTIFIED,
			Some(Some(_)) => match effective(tgid, start) {
				Some((label, _)) => label,
				None => return Some((POLICY_PENDING, REASON_UNLABELLED)),
			},
			None => {
				crate::decide::count(REASON_UNREADABLE, hook);
				return None;
			}
		}
	};
	if label == LABEL_PENDING {
		return Some((POLICY_PENDING, REASON_PENDING));
	}
	if label > LABEL_MASK {
		return Some((POLICY_PENDING, REASON_UNLABELLED));
	}
	match LABEL_POLICY.get(bank * MAX_LABELS as u32 + (label & LABEL_MASK)).copied() {
		Some(policy) if policy != POLICY_PENDING => Some((policy, NO_REASON)),
		_ => Some((POLICY_PENDING, REASON_UNLABELLED)),
	}
}

/// The label of `tgid` whose leader started at `start`, with its record's
/// sequence; a pending record resolved by the daemon for the same sequence
/// yields the resolved label. `None` when the process has no record.
#[inline(always)]
fn effective(tgid: u32, start: u64) -> Option<(u32, u64)> {
	// SAFETY: copied immediately.
	let proc = unsafe { PROCS.get(&tgid) }.copied()?;
	if start.wrapping_sub(proc.start) > proc.span as u64 {
		return None;
	}
	if proc.label != LABEL_PENDING {
		return Some((proc.label, proc.seq));
	}
	// SAFETY: copied immediately.
	match unsafe { RESOLVED.get(&tgid) }.copied() {
		Some(resolved) if resolved.seq == proc.seq && resolved.start == proc.start => Some((resolved.label, proc.seq)),
		_ => Some((LABEL_PENDING, proc.seq)),
	}
}

#[inline(always)]
fn labelling() -> bool {
	SETTINGS.get(0).is_some_and(|settings| settings.flags & SETTINGS_LABELLING != 0)
}

/// `sched_process_fork`: a new thread group inherits its parent's label.
pub fn fork(parent: Task, child: Task) {
	if !labelling() {
		return;
	}
	let (Some(parent_tgid), Some(child_tgid)) = (parent.tgid(), child.tgid()) else {
		increment(LABEL_COUNTER_UNREADABLE);
		return;
	};
	if parent_tgid == child_tgid {
		return;
	}
	let (Some(mm), Some(child_start), Some(parent_start)) = (
		child.mm(),
		child.start_boottime(),
		parent.group_leader().and_then(|leader| leader.start_boottime()),
	) else {
		increment(LABEL_COUNTER_UNREADABLE);
		return;
	};
	if mm.is_none() {
		return;
	}
	// A parent without a record is unseeded; the daemon's /proc seed walk,
	// which starts after labelling is on, covers its children too.
	let Some((label, parent_seq)) = effective(parent_tgid, parent_start) else {
		return;
	};
	let seq = unsafe { bpf_ktime_get_ns() };
	let value = ProcValue { start: child_start, seq, span: 0, label };
	if PROCS.insert(&child_tgid, &value, 0).is_err() {
		increment(LABEL_COUNTER_FULL);
		return;
	}
	if label == LABEL_PENDING {
		emit(RECORD_FORK, child_tgid, child_start, seq, NO_FILE, NO_FILE, parent_tgid, parent_seq, None);
	}
}

/// `bprm_check_security`: remember the first binfmt pass's file, which is the
/// script when a later pass substitutes an interpreter.
pub fn bprm_check(bprm: Binprm) {
	if !labelling() {
		return;
	}
	if bprm.first_pass() != Some(true) {
		return;
	}
	let Some(file) = bprm.file().and_then(|file| file.exec_file()) else {
		increment(LABEL_COUNTER_UNREADABLE);
		return;
	};
	let _ = EXEC_SCRATCH.insert(&bprm.raw(), &file, 0);
}

/// `sched_process_exec`: the new image's label, before any of its code runs.
pub fn exec(task: Task, bprm: Binprm) {
	let key = bprm.raw();
	// Stored field by field: an `Option<ExecFile>` leaves its payload registers
	// undefined on `None`, and the verifier rejects spilling them.
	let mut first = NO_FILE;
	// SAFETY: copied immediately.
	if let Some(file) = unsafe { EXEC_SCRATCH.get(&key) } {
		put_file(&mut first, *file);
	}
	let _ = EXEC_SCRATCH.remove(&key);
	if !labelling() {
		return;
	}
	let (Some(tgid), Some(start), Some(Some(mm))) =
		(task.tgid(), task.group_leader().and_then(|leader| leader.start_boottime()), task.mm())
	else {
		increment(LABEL_COUNTER_UNREADABLE);
		return;
	};
	let Some(exe) = mm.exe_file().and_then(|file| file.exec_file()) else {
		increment(LABEL_COUNTER_UNREADABLE);
		return;
	};
	let script = if first != exe { first } else { NO_FILE };
	let label = exec_label(exe, script);
	let seq = unsafe { bpf_ktime_get_ns() };
	let value = ProcValue { start, seq, span: 0, label };
	if PROCS.insert(&tgid, &value, 0).is_err() {
		increment(LABEL_COUNTER_FULL);
		return;
	}
	if label == LABEL_PENDING {
		emit(RECORD_EXEC, tgid, start, seq, exe, script, 0, 0, Some(mm));
	}
}

#[inline(always)]
fn exec_label(exe: ExecFile, script: ExecFile) -> u32 {
	let mut key = core::mem::MaybeUninit::<ExecLabelKey>::uninit();
	// SAFETY: both fields are fully written before the key is read.
	let key = unsafe {
		put_file(&mut (*key.as_mut_ptr()).exe, exe);
		put_file(&mut (*key.as_mut_ptr()).script, NO_FILE);
		key.assume_init_mut()
	};
	// SAFETY: copied immediately.
	if let Some(label) = unsafe { EXEC_LABELS.get(key) }.copied() {
		return label;
	}
	if script.ino != 0 {
		put_file(&mut key.script, script);
		// SAFETY: copied immediately.
		if let Some(label) = unsafe { EXEC_LABELS.get(key) }.copied() {
			return label;
		}
	}
	LABEL_PENDING
}

/// `sched_process_exit`: the last thread's exit removes the thread group.
pub fn exit(task: Task) {
	let (Some(live), Some(tgid), Some(start)) =
		(task.live_threads(), task.tgid(), task.group_leader().and_then(|leader| leader.start_boottime()))
	else {
		increment(LABEL_COUNTER_UNREADABLE);
		return;
	};
	if live != 0 {
		return;
	}
	// SAFETY: copied immediately.
	if let Some(proc) = unsafe { PROCS.get(&tgid) }.copied() {
		if start.wrapping_sub(proc.start) <= proc.span as u64 {
			let _ = PROCS.remove(&tgid);
			let _ = RESOLVED.remove(&tgid);
		}
	}
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn emit(
	kind: u32,
	tgid: u32,
	start: u64,
	seq: u64,
	exe: ExecFile,
	script: ExecFile,
	parent_tgid: u32,
	parent_seq: u64,
	mm: Option<Mm>,
) {
	let Some(buffer) = RECORD_BUF.get_ptr_mut(0) else {
		increment(LABEL_COUNTER_RECORD_DROP);
		return;
	};
	let base = buffer as *mut u8;
	// SAFETY: the header fits the per-CPU buffer, which is 8-byte aligned.
	let header = unsafe { &mut *(base as *mut RecordHeader) };
	header.kind = kind;
	header.tgid = tgid;
	header.start = start;
	header.seq = seq;
	put_file(&mut header.exe, exe);
	put_file(&mut header.script, script);
	header.parent_seq = parent_seq;
	header.parent_tgid = parent_tgid;
	let mut flags = 0;
	let mut args_len = 0u32;
	let mut env_len = 0u32;
	if let Some(mm) = mm {
		if let Some((from, to)) = mm.args() {
			let len = to.wrapping_sub(from);
			args_len = if len > ARGS_MAX as u64 {
				flags |= RECORD_ARGS_TRUNCATED;
				ARGS_MAX
			} else {
				len as u32
			};
			// SAFETY: a masked length at a fixed offset stays inside the buffer.
			let read = unsafe {
				bpf_probe_read_user(base.add(HEADER as usize) as *mut c_void, args_len & ARGS_MASK, from as *const c_void)
			};
			if read != 0 {
				args_len = 0;
				flags |= RECORD_ARGS_TRUNCATED;
			}
		}
		if let Some((from, to)) = mm.env() {
			let len = to.wrapping_sub(from);
			env_len = if len > ENV_MAX as u64 {
				flags |= RECORD_ENV_TRUNCATED;
				ENV_MAX
			} else {
				len as u32
			};
			// SAFETY: masked offset plus masked length stay inside the buffer.
			let read = unsafe {
				bpf_probe_read_user(
					base.add((HEADER + (args_len & ARGS_MASK)) as usize) as *mut c_void,
					env_len & ENV_MASK,
					from as *const c_void,
				)
			};
			if read != 0 {
				env_len = 0;
				flags |= RECORD_ENV_TRUNCATED;
			}
		}
	}
	header.flags = flags;
	header.args_len = args_len & ARGS_MASK;
	header.env_len = env_len & ENV_MASK;
	let size = (HEADER + (args_len & ARGS_MASK) + (env_len & ENV_MASK)) & RECORD_SIZE_MASK;
	// SAFETY: `size` is masked below the buffer's length.
	let record = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };
	if RECORDS.output(record, 0).is_err() {
		increment(LABEL_COUNTER_RECORD_DROP);
	}
}

/// Volatile stores, so LLVM merges no zero fields into a `memset` call, which
/// the verifier rejects.
#[inline(always)]
fn put_file(to: &mut ExecFile, from: ExecFile) {
	// SAFETY: plain stores into a valid reference.
	unsafe {
		core::ptr::write_volatile(&mut to.dev, from.dev);
		core::ptr::write_volatile(&mut to.ino, from.ino);
		core::ptr::write_volatile(&mut to.generation, from.generation);
		core::ptr::write_volatile(&mut to._pad, 0);
	}
}

#[inline(always)]
fn increment(index: u32) {
	let Some(counter) = LABEL_COUNTERS.get_ptr_mut(index) else {
		return;
	};
	// SAFETY: this CPU's slot of a per-CPU array.
	unsafe { *counter = (*counter).wrapping_add(1) };
}
