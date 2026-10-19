// Ported from Cordon's M1 hook shell at b40a8c7 (Apache-2.0). M2 removes the
// `PROTECTED`, `RULES`, and `RULE_COUNT` maps and delegates all Filemaster
// policy evaluation to the custom `decide` module; the M2 fix-up drops the
// nonexistent `inode_rename` flags argument and passes each hook's counter index.
//! Filemaster's eBPF LSM hook boundary for structural mutations.

#![no_std]
#![no_main]

mod decide;
mod kernel;
mod maps;
mod matcher;

use aya_ebpf::macros::lsm;
use aya_ebpf::programs::LsmContext;
use filemaster_lsm_common::decision_maps::{HOOK_LINK, HOOK_MKDIR, HOOK_RENAME, HOOK_RMDIR, HOOK_UNLINK};

/// `inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)`.
#[lsm(hook = "inode_link")]
pub fn inode_link(ctx: LsmContext) -> i32 {
    decide::clamped(decide::hard_link(
        kernel::Dentry::from_arg(&ctx, 0),
        kernel::Dentry::from_arg(&ctx, 2),
        HOOK_LINK,
    ))
}

/// `inode_rename(struct inode *old_dir, struct dentry *old_dentry,
/// struct inode *new_dir, struct dentry *new_dentry)`.
#[lsm(hook = "inode_rename")]
pub fn inode_rename(ctx: LsmContext) -> i32 {
    decide::clamped(decide::rename(
        kernel::Dentry::from_arg(&ctx, 1),
        kernel::Dentry::from_arg(&ctx, 3),
        HOOK_RENAME,
    ))
}

/// `inode_unlink(struct inode *dir, struct dentry *dentry)`.
#[lsm(hook = "inode_unlink")]
pub fn inode_unlink(ctx: LsmContext) -> i32 {
    decide::clamped(decide::remove(kernel::Dentry::from_arg(&ctx, 1), false, HOOK_UNLINK))
}

/// `inode_rmdir(struct inode *dir, struct dentry *dentry)`.
#[lsm(hook = "inode_rmdir")]
pub fn inode_rmdir(ctx: LsmContext) -> i32 {
    decide::clamped(decide::remove(kernel::Dentry::from_arg(&ctx, 1), true, HOOK_RMDIR))
}

/// `inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)`.
#[lsm(hook = "inode_mkdir")]
pub fn inode_mkdir(ctx: LsmContext) -> i32 {
    decide::clamped(decide::mkdir(kernel::Dentry::from_arg(&ctx, 1), HOOK_MKDIR))
}

/// eBPF programs calling GPL-only helpers must declare a GPL-compatible license.
#[link_section = "license"]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
