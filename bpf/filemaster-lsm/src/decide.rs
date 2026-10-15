//! Filemaster's M2 structural-decision data plane.
//!
//! The functions in this file are custom Filemaster code. They preserve the M1
//! dentry walk, double-buffer bank selection, daemon pid+executable bypass, and
//! verifier-safe return boundary while replacing Cordon's ordered-rule maps with
//! precompiled Filemaster verdict tables.

use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, PerCpuArray};
use filemaster_lsm_common::{
    Bank, DecisionOp, FileId, Label, NoMatchKey, ObjectId, ObjectKey, Relation, Settings,
    TargetKind, Verdict, VerdictKey, AUDIT_COUNTERS, MAX_NOMATCH, MAX_OBJECTS, MAX_VERDICTS,
    NUM_BANKS,
};

use crate::kernel;

/// Bound the dentry walk so the verifier can prove it terminates.
const MAX_ANCESTORS: usize = 32;
/// Linux's UAPI value for `RENAME_EXCHANGE`.
const RENAME_EXCHANGE: u32 = 1 << 1;

/// Inode identity roots for each bank. This replaces M1's Cordon `PROTECTED` map.
#[map]
static OBJECTS: HashMap<ObjectKey, ObjectId> =
    HashMap::with_max_entries((NUM_BANKS * MAX_OBJECTS) as u32, 0);
/// Fully resolved Filemaster decisions for covered targets.
#[map]
static VERDICT: HashMap<VerdictKey, Verdict> = HashMap::with_max_entries(MAX_VERDICTS as u32, 0);
/// Owner/default decision for the uncovered side of an otherwise covered operation.
#[map]
static NOMATCH: HashMap<NoMatchKey, Verdict> = HashMap::with_max_entries(MAX_NOMATCH as u32, 0);
/// One would-deny counter per Filemaster decision operation, per CPU.
#[map]
static AUDIT: PerCpuArray<u64> = PerCpuArray::with_max_entries(AUDIT_COUNTERS as u32, 0);
/// The one-element control record (daemon identity, active bank, audit mode).
#[map]
static SETTINGS: Array<Settings> = Array::with_max_entries(1, 0);

/// The operation target after resolving a dentry against an object root.
#[derive(Clone, Copy)]
struct ObjectMatch {
    object: ObjectId,
    relation: Relation,
    kind: TargetKind,
}

/// An operation's raw verdict and the operation responsible for a possible
/// would-deny audit count.
#[derive(Clone, Copy)]
pub struct DecisionResult {
    verdict: Verdict,
    operation: DecisionOp,
    audit: bool,
}

impl DecisionResult {
    const fn allow(operation: DecisionOp, audit: bool) -> Self {
        DecisionResult {
            verdict: Verdict::ALLOW,
            operation,
            audit,
        }
    }

    const fn deny(operation: DecisionOp, audit: bool) -> Self {
        DecisionResult {
            verdict: Verdict::DENY,
            operation,
            audit,
        }
    }
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
    if result.audit {
        increment_audit(result.operation);
        return 0;
    }

    // Keep this branch visible to LLVM: the v6.12 verifier requires proof that
    // R0 is within the LSM errno range even though the source has only two
    // possible results.
    let ret = core::hint::black_box(-1i32);
    if ret == -1 {
        -1
    } else {
        0
    }
}

/// `inode_unlink` and `inode_rmdir`: Filemaster's `DecisionDelete`.
pub fn remove(dentry: kernel::Dentry, force_folder: bool) -> Option<DecisionResult> {
    let settings = live_settings()?;
    let bank = settings.active_bank.masked();
    let kind = dentry_kind(dentry, force_folder)?;
    let target = positive_target(dentry, bank, force_folder)?;
    let covered = target.is_some();
    Some(evaluate(
        target,
        kind,
        DecisionOp::DELETE,
        bank,
        covered,
        settings.audit != 0,
    ))
}

/// `inode_mkdir`: Filemaster's `DecisionCreate`; a negative dentry is resolved
/// through its parent and is always a folder target.
pub fn mkdir(dentry: kernel::Dentry) -> Option<DecisionResult> {
    let settings = live_settings()?;
    let bank = settings.active_bank.masked();
    let kind = TargetKind::FOLDER;
    let target = destination_target(dentry, bank, TargetKind::FOLDER)?;
    let covered = target.is_some();
    Some(evaluate(
        target,
        kind,
        DecisionOp::CREATE,
        bank,
        covered,
        settings.audit != 0,
    ))
}

/// `inode_link`: preserve `DecisionSnapshot.DecideHardLink`'s source
/// read/write/execute order, then destination delete/create order.
pub fn hard_link(
    source_dentry: kernel::Dentry,
    destination_dentry: kernel::Dentry,
) -> Option<DecisionResult> {
    let settings = live_settings()?;
    let bank = settings.active_bank.masked();
    let source_kind = dentry_kind(source_dentry, false)?;
    let destination_kind = source_kind;
    let source = positive_target(source_dentry, bank, false)?;
    let destination = destination_target(destination_dentry, bank, destination_kind)?;
    let covered = source.is_some() || destination.is_some();
    let audit = settings.audit != 0;

    for operation in [DecisionOp::READ, DecisionOp::WRITE, DecisionOp::EXECUTE] {
        let result = evaluate(source, source_kind, operation, bank, covered, audit);
        if !result.verdict.allows() {
            return Some(result);
        }
    }

    if dentry_exists(destination_dentry) {
        let result = evaluate(
            destination,
            destination_kind,
            DecisionOp::DELETE,
            bank,
            covered,
            audit,
        );
        if !result.verdict.allows() {
            return Some(result);
        }
    }
    Some(evaluate(
        destination,
        destination_kind,
        DecisionOp::CREATE,
        bank,
        covered,
        audit,
    ))
}

/// `inode_rename`: preserve `DecisionSnapshot.DecideRename` exactly. The kernel
/// passes both exchange dentries in one hook invocation, so an exchange evaluates
/// both directed renames and permits only their conjunction.
pub fn rename(
    source_dentry: kernel::Dentry,
    destination_dentry: kernel::Dentry,
    flags: u32,
) -> Option<DecisionResult> {
    let settings = live_settings()?;
    let bank = settings.active_bank.masked();
    let source_kind = dentry_kind(source_dentry, false)?;
    let source = positive_target(source_dentry, bank, false)?;
    let destination_exists = dentry_exists(destination_dentry);
    let destination_kind = if destination_exists {
        dentry_kind(destination_dentry, false)?
    } else {
        source_kind
    };
    let destination = destination_target(destination_dentry, bank, source_kind)?;
    let audit = settings.audit != 0;

    if flags & RENAME_EXCHANGE != 0 {
        // An exchange requires both directions, and both dentries are positive
        // by the VFS contract. Never use a one-sided answer here.
        let reverse_kind = destination_kind;
        let reverse_source = positive_target(destination_dentry, bank, false)?;
        let reverse_destination = destination_target(source_dentry, bank, reverse_kind)?;
        let forward = decide_rename(
            source,
            source_kind,
            destination,
            destination_kind,
            true,
            bank,
            audit,
        );
        if !forward.verdict.allows() {
            return Some(forward);
        }
        return Some(decide_rename(
            reverse_source,
            reverse_kind,
            reverse_destination,
            source_kind,
            true,
            bank,
            audit,
        ));
    }

    Some(decide_rename(
        source,
        source_kind,
        destination,
        destination_kind,
        destination_exists,
        bank,
        audit,
    ))
}

#[inline(always)]
fn decide_rename(
    source: Option<ObjectMatch>,
    source_kind: TargetKind,
    destination: Option<ObjectMatch>,
    destination_kind: TargetKind,
    destination_exists: bool,
    bank: Bank,
    audit: bool,
) -> DecisionResult {
    let covered = source.is_some() || destination.is_some();
    let result = evaluate(
        source,
        source_kind,
        DecisionOp::DELETE,
        bank,
        covered,
        audit,
    );
    if !result.verdict.allows() {
        return result;
    }
    if !destination_exists {
        return evaluate(
            destination,
            destination_kind,
            DecisionOp::CREATE,
            bank,
            covered,
            audit,
        );
    }
    let result = evaluate(
        destination,
        destination_kind,
        DecisionOp::WRITE,
        bank,
        covered,
        audit,
    );
    if !result.verdict.allows() {
        return result;
    }
    evaluate(
        destination,
        destination_kind,
        DecisionOp::DELETE,
        bank,
        covered,
        audit,
    )
}

/// Reads settings and applies the daemon's M1 pid+executable bypass. M2 has no
/// label map: all remaining processes use `Label::UNIDENTIFIED`.
#[inline(always)]
fn live_settings() -> Option<Settings> {
    let settings = SETTINGS.get(0).copied()?;
    if kernel::current_pid() == settings.daemon_pid
        && kernel::caller_exe() == Some(settings.daemon_exe)
    {
        return None;
    }
    Some(settings)
}

/// Look up a positive dentry. A negative dentry is not an error: its owner is
/// represented by [`destination_target`] through the parent relation.
#[inline(always)]
fn positive_target(
    dentry: kernel::Dentry,
    bank: Bank,
    force_folder: bool,
) -> Option<Option<ObjectMatch>> {
    let kind = dentry_kind(dentry, force_folder)?;
    Some(find_object(dentry, bank, kind))
}

#[inline(always)]
fn dentry_kind(dentry: kernel::Dentry, force_folder: bool) -> Option<TargetKind> {
    if force_folder {
        return Some(TargetKind::FOLDER);
    }
    Some(kind_of(dentry.inode()?.mode()?))
}

/// Resolve a destination. Existing names carry their own inode kind. For a
/// negative name, the matched parent relation advances one level (`SELF` →
/// `CHILD`, all other relations → `DESCENDANT`) and the hook/source supplies
/// the newly-created target kind.
#[inline(always)]
fn destination_target(
    dentry: kernel::Dentry,
    bank: Bank,
    negative_kind: TargetKind,
) -> Option<Option<ObjectMatch>> {
    if dentry_exists(dentry) {
        return positive_target(dentry, bank, false);
    }
    let parent = dentry.parent()?;
    let Some(mut matched) = find_object(parent, bank, negative_kind) else {
        return Some(None);
    };
    matched.kind = negative_kind;
    matched.relation = if matched.relation == Relation::SELF {
        Relation::CHILD
    } else {
        Relation::DESCENDANT
    };
    Some(Some(matched))
}

#[inline(always)]
fn dentry_exists(dentry: kernel::Dentry) -> bool {
    dentry.inode().is_some()
}

#[inline(always)]
fn kind_of(mode: u16) -> TargetKind {
    const S_IFMT: u16 = 0o170000;
    const S_IFDIR: u16 = 0o040000;
    if mode & S_IFMT == S_IFDIR {
        TargetKind::FOLDER
    } else {
        TargetKind::FILE
    }
}

/// M1's deepest-object ancestor walk, now looking up only an M2 `ObjectId`.
#[inline(always)]
fn find_object(leaf_dentry: kernel::Dentry, bank: Bank, kind: TargetKind) -> Option<ObjectMatch> {
    let mut dentry = leaf_dentry;
    let mut relation = Relation::SELF;
    for _ in 0..MAX_ANCESTORS {
        let id = FileId::new(dentry.super_block()?.dev()?, dentry.inode()?.ino()?);
        if let Some(object) = object_id(bank, id) {
            return Some(ObjectMatch {
                object,
                relation,
                kind,
            });
        }
        let parent = dentry.parent()?;
        if parent == dentry {
            break;
        }
        dentry = parent;
        relation = if relation == Relation::SELF {
            Relation::CHILD
        } else {
            Relation::DESCENDANT
        };
    }
    None
}

/// Resolve a precompiled table answer. A missing table entry on a covered target
/// fails closed; an operation with no covered target is expressly allowed.
#[inline(always)]
fn evaluate(
    target: Option<ObjectMatch>,
    target_kind: TargetKind,
    operation: DecisionOp,
    bank: Bank,
    covered: bool,
    audit: bool,
) -> DecisionResult {
    let verdict = match target {
        Some(target) => verdict_for(bank, target, operation).unwrap_or(Verdict::DENY),
        None if covered => no_match(bank, operation, target_kind).unwrap_or(Verdict::DENY),
        None => Verdict::ALLOW,
    };
    if verdict.allows() {
        DecisionResult::allow(operation, audit)
    } else {
        DecisionResult::deny(operation, audit)
    }
}

#[inline(always)]
fn object_id(bank: Bank, file: FileId) -> Option<ObjectId> {
    // SAFETY: a copied map value cannot alias a concurrent userspace update.
    unsafe { OBJECTS.get(&ObjectKey::new(bank, file)).copied() }
}

#[inline(always)]
fn verdict_for(bank: Bank, target: ObjectMatch, operation: DecisionOp) -> Option<Verdict> {
    let key = VerdictKey::new(
        bank,
        target.object,
        Label::UNIDENTIFIED,
        operation,
        target.relation,
        target.kind,
    );
    // SAFETY: copied immediately, exactly like `OBJECTS` above.
    unsafe { VERDICT.get(&key).copied() }
}

#[inline(always)]
fn no_match(bank: Bank, operation: DecisionOp, target_kind: TargetKind) -> Option<Verdict> {
    let key = NoMatchKey::new(bank, Label::UNIDENTIFIED, operation, target_kind);
    // SAFETY: copied immediately, exactly like `OBJECTS` above.
    unsafe { NOMATCH.get(&key).copied() }
}

#[inline(always)]
fn increment_audit(operation: DecisionOp) {
    let Some(counter) = AUDIT.get_ptr_mut(operation.0) else {
        return;
    };
    // SAFETY: this is this CPU's array slot; BPF program invocations are
    // non-preemptible while accessing a per-CPU map value.
    unsafe { *counter = (*counter).wrapping_add(1) };
}
