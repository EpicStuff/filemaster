//! Filemaster's structural-decision-table ABI.
//!
//! This is deliberately separate from the vendored Cordon rule-table types in
//! `policy_maps`: M2 does not evaluate Cordon subjects or ordered rules in the
//! kernel.  Userspace resolves Filemaster's existing decision engine into these
//! complete, banked lookup tables instead.

use crate::ids::Bank;
use crate::maps::FileId;

/// Names of the M2 maps owned by the structural backend.
pub const MAP_OBJECTS: &str = "OBJECTS";
pub const MAP_VERDICT: &str = "VERDICT";
pub const MAP_NOMATCH: &str = "NOMATCH";
pub const MAP_AUDIT: &str = "AUDIT";

/// The two generations used for atomic table publication.
pub const NUM_BANKS: usize = 2;
/// The number of inode-keyed object roots supported by one generation.
pub const MAX_OBJECTS: usize = 1024;
/// There is one M2 label, five operations, three relationships and two kinds.
pub const MAX_VERDICTS: usize = NUM_BANKS * MAX_OBJECTS * 5 * 3 * 2;
/// One no-object decision for each operation and target kind in each generation.
pub const MAX_NOMATCH: usize = NUM_BANKS * 5 * 2;
/// One per-CPU would-deny counter per decision operation.
pub const AUDIT_COUNTERS: usize = 5;

/// A dense per-generation object identifier.  It is a lookup-table handle, not
/// an inode number; [`ObjectKey`] maps the latter to this value.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ObjectId(pub u32);

/// M2 process labels.  `SELF` is reserved for M3; the daemon uses its explicit
/// pid+executable bypass and ordinary callers are `UNIDENTIFIED` today.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Label(pub u32);

impl Label {
    pub const UNIDENTIFIED: Label = Label(1);
    pub const SELF: Label = Label(2);
}

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

/// How the target dentry relates to the matched object root.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Relation(pub u32);

impl Relation {
    pub const SELF: Relation = Relation(0);
    pub const CHILD: Relation = Relation(1);
    pub const DESCENDANT: Relation = Relation(2);
}

/// Filemaster's rule-kind dimension, encoded in the verdict-table key.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TargetKind(pub u32);

impl TargetKind {
    pub const FILE: TargetKind = TargetKind(1);
    pub const FOLDER: TargetKind = TargetKind(2);
}

/// A table value.  A transparent integer keeps every map bit pattern valid.
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
    /// `(bank, inode identity) -> ObjectId`, the ancestor walk's only map.
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

/// Complete lookup key for a covered object operation.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct VerdictKey {
    pub bank: Bank,
    pub object: ObjectId,
    pub label: Label,
    pub operation: DecisionOp,
    pub relation: Relation,
    pub target_kind: TargetKind,
}

impl VerdictKey {
    pub const fn new(
        bank: Bank,
        object: ObjectId,
        label: Label,
        operation: DecisionOp,
        relation: Relation,
        target_kind: TargetKind,
    ) -> Self {
        VerdictKey {
            bank,
            object,
            label,
            operation,
            relation,
            target_kind,
        }
    }
}

/// Fallback for an uncovered side of a multi-object operation.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NoMatchKey {
    pub bank: Bank,
    pub label: Label,
    pub operation: DecisionOp,
    pub target_kind: TargetKind,
}

impl NoMatchKey {
    pub const fn new(
        bank: Bank,
        label: Label,
        operation: DecisionOp,
        target_kind: TargetKind,
    ) -> Self {
        NoMatchKey {
            bank,
            label,
            operation,
            target_kind,
        }
    }
}

#[cfg(feature = "user")]
mod user {
    use super::*;

    // SAFETY: each type is a fixed `repr(C)`/transparent arrangement of integer
    // POD values with no implicit padding (ObjectKey has explicit zero padding).
    unsafe impl aya::Pod for ObjectId {}
    unsafe impl aya::Pod for Label {}
    unsafe impl aya::Pod for DecisionOp {}
    unsafe impl aya::Pod for Relation {}
    unsafe impl aya::Pod for TargetKind {}
    unsafe impl aya::Pod for Verdict {}
    unsafe impl aya::Pod for ObjectKey {}
    unsafe impl aya::Pod for VerdictKey {}
    unsafe impl aya::Pod for NoMatchKey {}
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::maps::Settings;
    use core::mem::{offset_of, size_of};
    use std::string::{String, ToString};

    #[test]
    fn writes_abi_manifest() {
        let mut manifest = String::from("{\n");
        append_layout(
            &mut manifest,
            "FileId",
            size_of::<FileId>(),
            &[
                ("dev", offset_of!(FileId, dev)),
                ("ino", offset_of!(FileId, ino)),
            ],
        );
        manifest.push_str(",\n");
        append_layout(
            &mut manifest,
            "Settings",
            size_of::<Settings>(),
            &[
                ("daemon_pid", offset_of!(Settings, daemon_pid)),
                ("active_bank", offset_of!(Settings, active_bank)),
                ("daemon_exe", offset_of!(Settings, daemon_exe)),
                ("audit", offset_of!(Settings, audit)),
                ("pad", offset_of!(Settings, _pad)),
            ],
        );
        manifest.push_str(",\n");
        append_layout(
            &mut manifest,
            "ObjectKey",
            size_of::<ObjectKey>(),
            &[
                ("file", offset_of!(ObjectKey, file)),
                ("bank", offset_of!(ObjectKey, bank)),
                ("pad", offset_of!(ObjectKey, _pad)),
            ],
        );
        manifest.push_str(",\n");
        append_layout(
            &mut manifest,
            "VerdictKey",
            size_of::<VerdictKey>(),
            &[
                ("bank", offset_of!(VerdictKey, bank)),
                ("object", offset_of!(VerdictKey, object)),
                ("label", offset_of!(VerdictKey, label)),
                ("operation", offset_of!(VerdictKey, operation)),
                ("relation", offset_of!(VerdictKey, relation)),
                ("target_kind", offset_of!(VerdictKey, target_kind)),
            ],
        );
        manifest.push_str(",\n");
        append_layout(
            &mut manifest,
            "NoMatchKey",
            size_of::<NoMatchKey>(),
            &[
                ("bank", offset_of!(NoMatchKey, bank)),
                ("label", offset_of!(NoMatchKey, label)),
                ("operation", offset_of!(NoMatchKey, operation)),
                ("target_kind", offset_of!(NoMatchKey, target_kind)),
            ],
        );
        manifest.push_str(",\n");
        append_layout(&mut manifest, "Verdict", size_of::<Verdict>(), &[]);
        manifest.push_str(",\n  \"AUDIT\": {\"key_size\": ");
        manifest.push_str(&size_of::<u32>().to_string());
        manifest.push_str(", \"value_size\": ");
        manifest.push_str(&size_of::<u64>().to_string());
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
                out.push_str("\"");
                out.push_str(field);
                out.push_str("\": ");
                out.push_str(&offset.to_string());
            }
            out.push('}');
        }
        out.push('}');
    }
}
