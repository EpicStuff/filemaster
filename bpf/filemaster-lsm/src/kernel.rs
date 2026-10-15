// Ported from cordon crates/bpf/src/kernel.rs @ b40a8c7 (Apache-2.0) — renamed
// the common crate; removed cgroup/open/exec helpers and, in M2, the dead
// `EVENTS`, `SCRATCH`, and `SUPPRESS` maps with their event-only helpers.
//! The unsafe boundary: every read of kernel memory lives here, behind safe typed
//! handles, so the decision flow in `main.rs` is `unsafe`-free.
//!
//! ## No committed struct layout — offsets come from the running kernel
//! There is no `vmlinux.rs` here. rustc can't emit CO-RE relocations
//! (rust-lang/rust#158412), so a generated binding would pin this object to the
//! layout of whatever kernel it was *built* against and silently read garbage on any
//! other. Instead every field is read at a byte offset taken from [`OFFSETS`] — a
//! `.rodata` global the daemon fills from the running kernel's BTF and injects at
//! load time. The handles below (`File`, `Dentry`, …) are `Copy` newtypes over a raw
//! base address; each accessor reads one field at its injected offset.
//!
//! [`read_at`] (a `bpf_probe_read_kernel`, the kernel's *fault-safe* reader: a bad
//! address faults into an `Err` instead of crashing) does all the actually-unsafe
//! work. Accessors return [`Option`] — `None` ("couldn't read") becomes a fail-open
//! allow in the caller.
//!
//! There is **no path resolution** here: `bpf_d_path` is not allowed at the
//! `file_open` LSM hook, so both subtrees and executables are identified by inode
//! ([`FileId`]).

use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel};
use filemaster_lsm_common::{Dev, FileId, Ino, Offsets, Pid};

/// Running-kernel field offsets, injected into `.rodata` by the daemon
/// (`override_global("OFFSETS", …)`) after it parses the kernel BTF. The initializer
/// is [`Offsets::POISON`] (all-ones) so a missing injection fails open + trips the
/// daemon's self-test rather than silently mis-reading; see `offsets` module docs.
#[unsafe(no_mangle)]
static OFFSETS: Offsets = Offsets::POISON;

/// Read one field of [`OFFSETS`]. Volatile so the optimizer can't fold in the POISON
/// initializer — the loader overwrites these bytes before the program is verified.
macro_rules! offset {
    ($field:ident) => {
        // SAFETY: `&raw const OFFSETS.$field` addresses an initialized `u32` in the
        // `.rodata` global; the volatile read forces the load the loader's value backs.
        unsafe { core::ptr::read_volatile(&raw const OFFSETS.$field) }
    };
}

/// Read a `T` from kernel memory at `base + off`, fault-safely. The address is pure
/// integer arithmetic (`base` is never dereferenced in Rust — only handed to the
/// probe helper), so a wild offset can't be UB, only an `Err`. `T` is POD here
/// (a pointer or an integer — every bit pattern is valid).
fn read_at<T>(base: *const u8, off: u32) -> Option<T> {
    let src = base.wrapping_add(off as usize) as *const T;
    unsafe { bpf_probe_read_kernel(src).ok() }
}

/// Read a pointer field (the common case: chasing one `struct foo *` to the next).
fn ptr_at(base: *const u8, off: u32) -> Option<*const u8> {
    read_at::<*const u8>(base, off)
}

/// The thread-group id (userspace pid) of the current task.
pub fn current_pid() -> Pid {
    Pid((bpf_get_current_pid_tgid() >> 32) as u32)
}

/// Read a scalar LSM hook argument. `inode_rename`'s fifth parameter is its
/// `unsigned int flags` value (including `RENAME_EXCHANGE`).
pub fn u32_from_arg(ctx: &aya_ebpf::programs::LsmContext, n: usize) -> u32 {
    unsafe { ctx.arg(n) }
}

/// A `struct file *`.
#[derive(Clone, Copy)]
pub struct File(*const u8);

impl File {
    /// The file's inode (via the direct `f_inode` field).
    pub fn inode(self) -> Option<Inode> {
        Some(Inode(ptr_at(self.0, offset!(file_f_inode))?))
    }
}

/// A `struct dentry *`. `PartialEq` compares the pointer (a dentry that is its own
/// parent is the mount root — the walk's stop condition).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Dentry(*const u8);

impl Dentry {
    /// The nth pointer argument of the LSM hook, for the hooks whose arguments are
    /// dentries rather than a `struct file` (`inode_link` arg 0 = `old_dentry`,
    /// `inode_rename` arg 1 = `old_dentry`, `inode_unlink`/`inode_rmdir` arg 1).
    ///
    /// The index is the caller's responsibility and is **not** type-checked: reading an
    /// `inode *` argument as a dentry yields a plausible-but-wrong pointer whose field
    /// reads fail, which fails *open*. The daemon's self-test exercises every hook for
    /// exactly this reason.
    pub fn from_arg(ctx: &aya_ebpf::programs::LsmContext, n: usize) -> Dentry {
        Dentry(unsafe { ctx.arg(n) })
    }
    /// The dentry's inode, or `None` when the dentry is **negative** — `d_inode` is NULL,
    /// i.e. the name does not exist yet.
    ///
    /// The distinction decides a verdict, so it is tested rather than left to the NULL read
    /// faulting out on its own: `link(2)`'s target is always negative (the VFS resolves it
    /// with `LOOKUP_CREATE`, so an existing name is `EEXIST` before this hook runs), while
    /// `rename(2)`'s destination is *positive* whenever it clobbers — and `vfs_rename` then
    /// destroys that inode. See `decide_reparent`.
    pub fn inode(self) -> Option<Inode> {
        let inode = ptr_at(self.0, offset!(dentry_d_inode))?;
        (!inode.is_null()).then_some(Inode(inode))
    }
    pub fn super_block(self) -> Option<SuperBlock> {
        Some(SuperBlock(ptr_at(self.0, offset!(dentry_d_sb))?))
    }
    pub fn parent(self) -> Option<Dentry> {
        Some(Dentry(ptr_at(self.0, offset!(dentry_d_parent))?))
    }
}

/// A `struct inode *`.
#[derive(Clone, Copy)]
pub struct Inode(*const u8);

impl Inode {
    pub fn ino(self) -> Option<Ino> {
        // i_ino is c_ulong == u64.
        Some(Ino(read_at::<u64>(self.0, offset!(inode_i_ino))?))
    }
    /// The inode's mode bits.  M2 only needs `S_IFDIR` to distinguish the
    /// Filemaster folder-rule dimension from file rules.
    pub fn mode(self) -> Option<u16> {
        Some(read_at::<u16>(self.0, offset!(inode_i_mode))?)
    }
    pub fn super_block(self) -> Option<SuperBlock> {
        Some(SuperBlock(ptr_at(self.0, offset!(inode_i_sb))?))
    }
    /// The inode's `(dev, inode)` identity.
    pub fn file_id(self) -> Option<FileId> {
        Some(FileId::new(self.super_block()?.dev()?, self.ino()?))
    }
}

/// A `struct super_block *`.
#[derive(Clone, Copy)]
pub struct SuperBlock(*const u8);

impl SuperBlock {
    /// The device number in the kernel's `s_dev` encoding (matches what the daemon
    /// re-packs `stat(2)`'s `st_dev` into).
    pub fn dev(self) -> Option<Dev> {
        // s_dev is dev_t == u32.
        Some(Dev(read_at::<u32>(self.0, offset!(sb_s_dev))? as u64))
    }
}

/// The current task's executable identity (`mm->exe_file`'s inode). `None` for a
/// kernel thread (no `mm`) or an unreadable chain — the caller fails open.
#[inline(always)]
pub fn caller_exe() -> Option<FileId> {
    current_exe_file()?.inode()?.file_id()
}

/// The current task's `mm->exe_file`, if any (kernel threads have no `mm`).
fn current_exe_file() -> Option<File> {
    let task = unsafe { bpf_get_current_task() } as *const u8;
    let mm = ptr_at(task, offset!(task_mm))?;
    if mm.is_null() {
        return None;
    }
    let exe_file = ptr_at(mm, offset!(mm_exe_file))?;
    (!exe_file.is_null()).then_some(File(exe_file))
}
