//! Filemaster's structural-decision ABI.
//!
//! This is deliberately separate from the vendored Cordon rule-table types in
//! `policy_maps`. Userspace compiles Filemaster's ordered rule lists into
//! per-object path contexts; the kernel rebuilds each target's full path and
//! evaluates those lists with a port of Go's `path/filepath.Match`.

use crate::ids::Bank;
use crate::maps::FileId;

pub const MAP_OBJECTS: &str = "OBJECTS";
pub const MAP_CONTEXTS: &str = "CONTEXTS";
pub const MAP_PATTERNS: &str = "PATTERNS";
pub const MAP_CHUNKS: &str = "CHUNKS";
pub const MAP_TOKENS: &str = "TOKENS";
pub const MAP_RANGES: &str = "RANGES";
pub const MAP_ARENA: &str = "ARENA";
pub const MAP_NOMATCH: &str = "NOMATCH";
pub const MAP_AUDIT: &str = "AUDIT";
pub const MAP_COUNTERS: &str = "COUNTERS";
pub const MAP_SCRATCH: &str = "SCRATCH";

/// The two generations used for atomic table publication.
pub const NUM_BANKS: usize = 2;
/// Inode-keyed walk stops (scope roots, rule anchors, mount roots) per bank.
pub const MAX_OBJECTS: usize = 1024;
/// Absolute paths at which those objects are reachable, per bank.
pub const MAX_CONTEXTS: usize = 1024;
/// Distinct rule patterns per bank.
pub const MAX_PATTERNS: usize = 1024;
/// Tokenized-chunk, token and class-range table sizes per bank. A pattern that
/// would overflow these is left out and its context denies, like a rule cap.
pub const MAX_CHUNKS: usize = 8192;
pub const MAX_TOKENS: usize = 32768;
pub const MAX_RANGES: usize = 16384;

/// Token kinds in a tokenized `filepath.Match` chunk.
pub const TOKEN_LITERAL: u8 = 0;
pub const TOKEN_QUESTION: u8 = 1;
pub const TOKEN_CLASS: u8 = 2;
/// Rule references one policy's list for one context can hold before it denies.
pub const CONTEXT_RULES: usize = 256;
/// Watch-scope entries one context can hold before its object denies.
pub const CONTEXT_SCOPES: usize = 32;

/// Per-bank string arena: context paths, scope paths and patterns.
pub const ARENA_SIZE: usize = 1 << 20;
pub const ARENA_MASK: u32 = (ARENA_SIZE - 1) as u32;
/// Every arena string is shorter than this, so a masked offset plus a string
/// length stays inside the value.
pub const ARENA_SLACK: usize = 4096;
pub const MAX_STRING: usize = ARENA_SLACK - 1;

/// One per-CPU path buffer. Names are written backwards so the relative path
/// ends at [`REL_END`]; the context path is copied in front of it.
pub const SCRATCH_SIZE: usize = 16384;
pub const SCRATCH_MASK: u32 = (SCRATCH_SIZE - 1) as u32;
pub const SCRATCH_SLACK: usize = 4096;
pub const REL_END: u32 = 12288;
/// Longest relative path (target below its object) the buffer accepts.
pub const MAX_REL: u32 = 8192;
/// Scratch slots: the source and destination of a two-path operation.
pub const SCRATCH_SLOTS: usize = 2;

/// Dentry levels between a target and its object.
pub const WALK_LIMIT: u32 = 4096;
/// `bpf_loop` iterations one evaluation may use.
pub const EVAL_BUDGET: u32 = 1 << 23;

/// One per-CPU would-deny counter per decision operation.
pub const AUDIT_COUNTERS: usize = 5;

/// The structural hooks, as indexes of the per-hook counters.
pub const HOOKS: usize = 5;
pub const HOOK_UNLINK: u32 = 0;
pub const HOOK_RMDIR: u32 = 1;
pub const HOOK_MKDIR: u32 = 2;
pub const HOOK_LINK: u32 = 3;
pub const HOOK_RENAME: u32 = 4;

/// Cases the kernel cannot decide exactly, and labelling denials. Each is
/// counted per hook.
pub const REASONS: usize = 10;
/// A kernel value could not be read; the operation was allowed.
pub const REASON_UNREADABLE: u32 = 0;
/// The target is more than [`WALK_LIMIT`] levels below its object; denied.
pub const REASON_DEPTH: u32 = 1;
/// The path does not fit the buffer; denied.
pub const REASON_PATH_TOO_LONG: u32 = 2;
/// The walk reached a filesystem root that is not registered; not covered.
pub const REASON_UNREGISTERED_ROOT: u32 = 3;
/// A context holds more rules or scopes than its arrays; denied.
pub const REASON_CONTEXT_OVERFLOW: u32 = 4;
/// An evaluation used its whole `bpf_loop` budget; denied.
pub const REASON_BUDGET: u32 = 5;
/// The caller's label was still pending; the pending policy denied.
pub const REASON_PENDING: u32 = 6;
/// The caller had no label (label map full) or an unpublished one; denied.
pub const REASON_UNLABELLED: u32 = 7;
/// The caller was pending and its label wait ran out; the pending policy denied.
pub const REASON_WAIT_TIMEOUT: u32 = 8;
/// Every attempt's per-CPU evaluation state was used by another hook on the
/// same CPU before the verdict was read; denied.
pub const REASON_STATE_CONTENTION: u32 = 9;
pub const COUNTERS: usize = REASONS * HOOKS;

/// Rule lists. A rule reference carries the list its rule came from.
pub const LIST_READ: u8 = 0;
pub const LIST_WRITE: u8 = 1;
pub const LIST_EXECUTE: u8 = 2;

/// `RuleRef::flags` bit 0: the rule allows.
pub const RULE_ALLOW: u8 = 1;
/// `RuleRef::flags` bits 1–2: the rule's ObjectKind (0 any, 1 file, 2 folder).
pub const RULE_KIND_SHIFT: u8 = 1;
pub const RULE_KIND_MASK: u8 = 3;

/// `Context::flags`: the context overflowed its scope array.
pub const CONTEXT_OVERFLOW: u32 = 1;

/// The existing Filemaster engine's operation dimension.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DecisionOp(pub u32);

impl DecisionOp {
	pub const READ: DecisionOp = DecisionOp(0);
	pub const WRITE: DecisionOp = DecisionOp(1);
	pub const EXECUTE: DecisionOp = DecisionOp(2);
	pub const CREATE: DecisionOp = DecisionOp(3);
	pub const DELETE: DecisionOp = DecisionOp(4);
}

/// Whether the target is a file or a folder, for ObjectKind-qualified rules.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TargetKind(pub u32);

impl TargetKind {
	pub const FILE: TargetKind = TargetKind(1);
	pub const FOLDER: TargetKind = TargetKind(2);
}

/// A table value. A transparent integer keeps every map bit pattern valid.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Verdict(pub u32);

impl Verdict {
	pub const DENY: Verdict = Verdict(0);
	pub const ALLOW: Verdict = Verdict(1);

	pub const fn allows(self) -> bool {
		self.0 == Self::ALLOW.0
	}
}

padded_pod! {
	/// `(inode identity, bank) -> ObjectValue`, the walk's stop test.
	#[repr(C)]
	#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
	pub struct ObjectKey {
		pub file: FileId,
		pub bank: Bank,
	}
}

impl ObjectKey {
	pub const fn new(bank: Bank, file: FileId) -> Self {
		ObjectKey {
			file,
			bank,
			_pad: [0; Self::PAD],
		}
	}
}

/// The contiguous run of `CONTEXTS` entries for one object.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ObjectValue {
	pub first_context: u32,
	pub context_count: u32,
}

/// One watch-scope entry: an arena string and whether it excludes.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ScopeRef {
	pub off: u32,
	pub len: u32,
	pub exclude: u32,
}

/// One rule in a context's ordered list.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RuleRef {
	pub pattern: u16,
	pub list: u8,
	pub flags: u8,
}

/// One absolute path an object is reachable at, with the scope entries that
/// can apply at or below it. Each policy's rules for it are a `RuleList`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Context {
	/// Arena offset of the path.
	pub path_off: u32,
	/// Bytes copied in front of the relative path: 0 for `/`.
	pub path_len: u32,
	/// `len(filepath.Dir(path))`, for an entry operation on the object itself.
	pub parent_len: u32,
	pub flags: u32,
	pub scope_count: u32,
	pub _pad: u32,
	pub scopes: [ScopeRef; CONTEXT_SCOPES],
}

/// One rule pattern. A `recursive` pattern holds the cleaned `/**` prefix in
/// the arena (`off`/`len`) and matches by path containment. A non-recursive
/// pattern is a tokenized `filepath.Match` program: `chunk_off`/`chunk_len`
/// index the `CHUNKS` table.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Pattern {
	pub off: u32,
	pub len: u32,
	pub recursive: u32,
	pub chunk_off: u32,
	pub chunk_len: u32,
}

/// One chunk of a tokenized pattern: Go's scanChunk star flag and a token range.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Chunk {
	pub star: u32,
	pub token_off: u32,
	pub token_len: u32,
}

/// One token: a literal byte, `?`, or a `[...]` class (`negated` plus a range
/// range). Kinds are `TOKEN_LITERAL`/`TOKEN_QUESTION`/`TOKEN_CLASS`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Token {
	pub kind: u8,
	pub byte: u8,
	pub negated: u8,
	pub _pad: u8,
	pub range_off: u32,
	pub range_len: u32,
}

/// One inclusive class rune range, as Go's getEsc resolves it.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Range {
	pub lo: u32,
	pub hi: u32,
}

/// One bank's string arena.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Arena(pub [u8; ARENA_SIZE + ARENA_SLACK]);

/// One per-CPU path buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Scratch(pub [u8; SCRATCH_SIZE + SCRATCH_SLACK]);

#[cfg(feature = "user")]
mod user {
	use super::*;

	// SAFETY: each type is a fixed `repr(C)`/transparent arrangement of integer
	// POD values with no implicit padding (ObjectKey has explicit zero padding).
	unsafe impl aya::Pod for DecisionOp {}
	unsafe impl aya::Pod for TargetKind {}
	unsafe impl aya::Pod for Verdict {}
	unsafe impl aya::Pod for ObjectKey {}
	unsafe impl aya::Pod for ObjectValue {}
	unsafe impl aya::Pod for ScopeRef {}
	unsafe impl aya::Pod for RuleRef {}
	unsafe impl aya::Pod for Context {}
	unsafe impl aya::Pod for Pattern {}
	unsafe impl aya::Pod for Chunk {}
	unsafe impl aya::Pod for Token {}
	unsafe impl aya::Pod for Range {}
}

#[cfg(test)]
mod tests {
	extern crate std;

	use super::*;
	use crate::label_maps::*;
	use crate::offsets::Offsets;
	use core::mem::{offset_of, size_of};
	use std::string::{String, ToString};

	#[test]
	fn writes_abi_manifest() {
		let mut manifest = String::from("{\n");
		let layouts: &[(&str, usize, &[(&str, usize)])] = &[
			("FileId", size_of::<FileId>(), &[("dev", offset_of!(FileId, dev)), ("ino", offset_of!(FileId, ino))]),
			(
				"Settings",
				size_of::<Settings>(),
				&[
					("daemon_start", offset_of!(Settings, daemon_start)),
					("daemon_tgid", offset_of!(Settings, daemon_tgid)),
					("daemon_span", offset_of!(Settings, daemon_span)),
					("active_bank", offset_of!(Settings, active_bank)),
					("audit", offset_of!(Settings, audit)),
					("flags", offset_of!(Settings, flags)),
				],
			),
			(
				"ObjectKey",
				size_of::<ObjectKey>(),
				&[
					("file", offset_of!(ObjectKey, file)),
					("bank", offset_of!(ObjectKey, bank)),
					("pad", offset_of!(ObjectKey, _pad)),
				],
			),
			(
				"ObjectValue",
				size_of::<ObjectValue>(),
				&[
					("first_context", offset_of!(ObjectValue, first_context)),
					("context_count", offset_of!(ObjectValue, context_count)),
				],
			),
			(
				"ScopeRef",
				size_of::<ScopeRef>(),
				&[("off", offset_of!(ScopeRef, off)), ("len", offset_of!(ScopeRef, len)), ("exclude", offset_of!(ScopeRef, exclude))],
			),
			(
				"RuleRef",
				size_of::<RuleRef>(),
				&[("pattern", offset_of!(RuleRef, pattern)), ("list", offset_of!(RuleRef, list)), ("flags", offset_of!(RuleRef, flags))],
			),
			(
				"Context",
				size_of::<Context>(),
				&[
					("path_off", offset_of!(Context, path_off)),
					("path_len", offset_of!(Context, path_len)),
					("parent_len", offset_of!(Context, parent_len)),
					("flags", offset_of!(Context, flags)),
					("scope_count", offset_of!(Context, scope_count)),
					("scopes", offset_of!(Context, scopes)),
				],
			),
			(
				"Pattern",
				size_of::<Pattern>(),
				&[
					("off", offset_of!(Pattern, off)),
					("len", offset_of!(Pattern, len)),
					("recursive", offset_of!(Pattern, recursive)),
					("chunk_off", offset_of!(Pattern, chunk_off)),
					("chunk_len", offset_of!(Pattern, chunk_len)),
				],
			),
			(
				"Chunk",
				size_of::<Chunk>(),
				&[("star", offset_of!(Chunk, star)), ("token_off", offset_of!(Chunk, token_off)), ("token_len", offset_of!(Chunk, token_len))],
			),
			(
				"Token",
				size_of::<Token>(),
				&[
					("kind", offset_of!(Token, kind)),
					("byte", offset_of!(Token, byte)),
					("negated", offset_of!(Token, negated)),
					("range_off", offset_of!(Token, range_off)),
					("range_len", offset_of!(Token, range_len)),
				],
			),
			("Range", size_of::<Range>(), &[("lo", offset_of!(Range, lo)), ("hi", offset_of!(Range, hi))]),
			(
				"ExecFile",
				size_of::<ExecFile>(),
				&[("dev", offset_of!(ExecFile, dev)), ("ino", offset_of!(ExecFile, ino)), ("generation", offset_of!(ExecFile, generation))],
			),
			("ExecLabelKey", size_of::<ExecLabelKey>(), &[("exe", offset_of!(ExecLabelKey, exe)), ("script", offset_of!(ExecLabelKey, script))]),
			(
				"ProcValue",
				size_of::<ProcValue>(),
				&[
					("start", offset_of!(ProcValue, start)),
					("seq", offset_of!(ProcValue, seq)),
					("span", offset_of!(ProcValue, span)),
					("label", offset_of!(ProcValue, label)),
				],
			),
			(
				"Resolved",
				size_of::<Resolved>(),
				&[("start", offset_of!(Resolved, start)), ("seq", offset_of!(Resolved, seq)), ("label", offset_of!(Resolved, label))],
			),
			(
				"PolicyListKey",
				size_of::<PolicyListKey>(),
				&[("bank", offset_of!(PolicyListKey, bank)), ("policy", offset_of!(PolicyListKey, policy)), ("context", offset_of!(PolicyListKey, context))],
			),
			(
				"RuleList",
				size_of::<RuleList>(),
				&[("rule_count", offset_of!(RuleList, rule_count)), ("flags", offset_of!(RuleList, flags)), ("rules", offset_of!(RuleList, rules))],
			),
			(
				"WaitSettings",
				size_of::<WaitSettings>(),
				&[
					("heartbeat", offset_of!(WaitSettings, heartbeat)),
					("max_waiters", offset_of!(WaitSettings, max_waiters)),
					("enabled", offset_of!(WaitSettings, enabled)),
				],
			),
			(
				"RecordHeader",
				size_of::<RecordHeader>(),
				&[
					("kind", offset_of!(RecordHeader, kind)),
					("tgid", offset_of!(RecordHeader, tgid)),
					("start", offset_of!(RecordHeader, start)),
					("seq", offset_of!(RecordHeader, seq)),
					("exe", offset_of!(RecordHeader, exe)),
					("script", offset_of!(RecordHeader, script)),
					("parent_seq", offset_of!(RecordHeader, parent_seq)),
					("parent_tgid", offset_of!(RecordHeader, parent_tgid)),
					("flags", offset_of!(RecordHeader, flags)),
					("args_len", offset_of!(RecordHeader, args_len)),
					("env_len", offset_of!(RecordHeader, env_len)),
					("path_len", offset_of!(RecordHeader, path_len)),
				],
			),
			(
				"DecisionRecord",
				size_of::<DecisionRecord>(),
				&[
					("kind", offset_of!(DecisionRecord, kind)),
					("operation", offset_of!(DecisionRecord, operation)),
					("verdict", offset_of!(DecisionRecord, verdict)),
					("reason", offset_of!(DecisionRecord, reason)),
					("tgid", offset_of!(DecisionRecord, tgid)),
					("label", offset_of!(DecisionRecord, label)),
					("bank", offset_of!(DecisionRecord, bank)),
					("flags", offset_of!(DecisionRecord, flags)),
					("start", offset_of!(DecisionRecord, start)),
					("source", offset_of!(DecisionRecord, source)),
					("target", offset_of!(DecisionRecord, target)),
					("source_context", offset_of!(DecisionRecord, source_context)),
					("target_context", offset_of!(DecisionRecord, target_context)),
					("source_len", offset_of!(DecisionRecord, source_len)),
					("target_len", offset_of!(DecisionRecord, target_len)),
					("suppressed", offset_of!(DecisionRecord, suppressed)),
					("source_path", offset_of!(DecisionRecord, source_path)),
					("target_path", offset_of!(DecisionRecord, target_path)),
				],
			),
			("DecisionSuppressKey", size_of::<DecisionSuppressKey>(), &[("tgid", offset_of!(DecisionSuppressKey, tgid)), ("operation", offset_of!(DecisionSuppressKey, operation)), ("verdict", offset_of!(DecisionSuppressKey, verdict))]),
			("DecisionSuppressValue", size_of::<DecisionSuppressValue>(), &[("window_start", offset_of!(DecisionSuppressValue, window_start)), ("emitted", offset_of!(DecisionSuppressValue, emitted)), ("dropped", offset_of!(DecisionSuppressValue, dropped))]),
			("Arena", size_of::<Arena>(), &[]),
			("Scratch", size_of::<Scratch>(), &[]),
			("Offsets", size_of::<Offsets>(), &[]),
		];
		for (index, (name, size, offsets)) in layouts.iter().enumerate() {
			if index != 0 {
				manifest.push_str(",\n");
			}
			append_layout(&mut manifest, name, *size, offsets);
		}
		let counts: &[(&str, usize)] = &[
			("NUM_BANKS", NUM_BANKS),
			("MAX_OBJECTS", MAX_OBJECTS),
			("MAX_CONTEXTS", MAX_CONTEXTS),
			("MAX_PATTERNS", MAX_PATTERNS),
			("MAX_CHUNKS", MAX_CHUNKS),
			("MAX_TOKENS", MAX_TOKENS),
			("MAX_RANGES", MAX_RANGES),
			("CONTEXT_RULES", CONTEXT_RULES),
			("CONTEXT_SCOPES", CONTEXT_SCOPES),
			("ARENA_SIZE", ARENA_SIZE),
			("MAX_STRING", MAX_STRING),
			("AUDIT_COUNTERS", AUDIT_COUNTERS),
			("NOMATCH_ENTRIES", NOMATCH_ENTRIES),
			("HOOKS", HOOKS),
			("REASONS", REASONS),
			("MAX_LABELS", MAX_LABELS),
			("MAX_POLICIES", MAX_POLICIES),
			("MAX_RULELISTS", MAX_RULELISTS),
			("MAX_POLICY_LISTS", MAX_POLICY_LISTS),
			("MAX_PROCS", MAX_PROCS),
			("MAX_EXEC_LABELS", MAX_EXEC_LABELS),
			("EXEC_SCRATCH_ENTRIES", EXEC_SCRATCH_ENTRIES),
			("RECORDS_SIZE", RECORDS_SIZE),
			("RECORD_BUF_SIZE", RECORD_BUF_SIZE),
			("DECISION_PATH_MAX", DECISION_PATH_MAX),
			("DECISION_RECORD_SIZE", DECISION_RECORD_SIZE),
			("DECISION_SUPPRESS_ENTRIES", DECISION_SUPPRESS_ENTRIES as usize),
			("DECISION_SUPPRESS_LIMIT", DECISION_SUPPRESS_LIMIT as usize),
			("ARGS_MAX", ARGS_MAX as usize),
			("ENV_MAX", ENV_MAX as usize),
			("LABEL_COUNTERS", LABEL_COUNTERS),
			("WAIT_CAP_NS", WAIT_CAP_NS as usize),
			("WAIT_STALE_NS", WAIT_STALE_NS as usize),
		];
		manifest.push_str(",\n  \"constants\": {");
		for (index, (name, value)) in counts.iter().enumerate() {
			if index != 0 {
				manifest.push_str(", ");
			}
			manifest.push('"');
			manifest.push_str(name);
			manifest.push_str("\": ");
			manifest.push_str(&value.to_string());
		}
		manifest.push_str("}\n}\n");
		let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("abi-manifest.json");
		std::fs::write(&path, manifest).expect("write ABI manifest");
	}

	fn append_layout(out: &mut String, name: &str, size: usize, offsets: &[(&str, usize)]) {
		out.push_str("  \"");
		out.push_str(name);
		out.push_str("\": {\"size\": ");
		out.push_str(&size.to_string());
		if !offsets.is_empty() {
			out.push_str(", \"offsets\": {");
			for (index, (field, offset)) in offsets.iter().enumerate() {
				if index != 0 {
					out.push_str(", ");
				}
				out.push('"');
				out.push_str(field);
				out.push_str("\": ");
				out.push_str(&offset.to_string());
			}
			out.push('}');
		}
		out.push('}');
	}
}
