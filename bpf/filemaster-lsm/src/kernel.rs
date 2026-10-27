// Ported from cordon crates/bpf/src/kernel.rs @ b40a8c7 (Apache-2.0) — renamed
// the common crate; removed cgroup/open/exec helpers and, in M2, the dead
// `EVENTS`, `SCRATCH`, and `SUPPRESS` maps with their event-only helpers. The M2
// fix-up removed the scalar-argument reader and added raw dentry handles, a
// negative-versus-unreadable inode read and the `d_name` reader for the path walk.
// M3 replaces `caller_exe` with the task, mm, binprm and inode-generation
// readers for labelling. The race fix reads hook arguments as plain integers.
// M5 adds the superblock magic and btrfs subvolume readers.
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
use filemaster_lsm_common::decision_maps::BTRFS_SUPER_MAGIC;
use filemaster_lsm_common::label_maps::EXEC_SUBVOL_UNKNOWN;
use filemaster_lsm_common::{Dev, ExecFile, Ino, Offsets, Pid};

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
    ///
    /// Read with a probe rather than a context load: the verifier types a context
    /// load as a BTF pointer, which a global BPF function cannot take as a `u64`.
    pub fn from_arg(ctx: &aya_ebpf::programs::LsmContext, n: usize) -> Dentry {
        let slot = (aya_ebpf::EbpfContext::as_ptr(ctx) as *const u64).wrapping_add(n);
        Dentry(unsafe { bpf_probe_read_kernel(slot) }.unwrap_or(0) as *const u8)
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
    /// The dentry as a plain integer, for a `bpf_loop` callback's state.
    pub fn raw(self) -> u64 {
        self.0 as u64
    }
    pub fn from_raw(raw: u64) -> Dentry {
        Dentry(raw as *const u8)
    }
    /// `Some(None)` for a negative dentry, `None` when `d_inode` is unreadable.
    pub fn inode_or_negative(self) -> Option<Option<Inode>> {
        let inode = ptr_at(self.0, offset!(dentry_d_inode))?;
        Some((!inode.is_null()).then_some(Inode(inode)))
    }
    /// The component name pointer and length from `d_name`.
    pub fn name(self) -> Option<(*const u8, u32)> {
        let len = read_at::<u32>(self.0, offset!(dentry_d_name_len))?;
        Some((ptr_at(self.0, offset!(dentry_d_name_name))?, len))
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
    /// A btrfs inode's subvolume, `BTRFS_I(inode)->root->root_key.objectid`,
    /// which is what btrfs's getattr reports as `STATX_SUBVOL`. `root` is the
    /// `btrfs_inode.root` offset relative to the embedded `struct inode`, and
    /// `root_id` the objectid's offset in `btrfs_root`.
    pub fn btrfs_subvolume(self, root: i32, root_id: u32) -> Option<u64> {
        let root = read_at::<*const u8>(self.0.wrapping_offset(root as isize), 0)?;
        read_at::<u64>(root, root_id)
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
    pub fn magic(self) -> Option<u64> {
        // s_magic is unsigned long.
        read_at::<u64>(self.0, offset!(sb_s_magic))
    }
}

/// A `struct task_struct *`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Task(*const u8);

impl Task {
    pub fn current() -> Task {
        Task(unsafe { bpf_get_current_task() } as *const u8)
    }
    pub fn from_raw(raw: *const u8) -> Task {
        Task(raw)
    }
    pub fn tgid(self) -> Option<u32> {
        read_at::<u32>(self.0, offset!(task_tgid))
    }
    pub fn group_leader(self) -> Option<Task> {
        Some(Task(ptr_at(self.0, offset!(task_group_leader))?))
    }
    /// The task's `start_boottime`; the group leader's identifies the process.
    pub fn start_boottime(self) -> Option<u64> {
        read_at::<u64>(self.0, offset!(task_start_boottime))
    }
    /// `Some(None)` for a kernel thread (no `mm`).
    pub fn mm(self) -> Option<Option<Mm>> {
        let mm = ptr_at(self.0, offset!(task_mm))?;
        Some((!mm.is_null()).then_some(Mm(mm)))
    }
    /// `signal->live`: the thread group's live thread count.
    pub fn live_threads(self) -> Option<i32> {
        let signal = ptr_at(self.0, offset!(task_signal))?;
        read_at::<i32>(signal, offset!(signal_live))
    }
}

/// A `struct mm_struct *`.
#[derive(Clone, Copy)]
pub struct Mm(*const u8);

impl Mm {
    pub fn exe_file(self) -> Option<File> {
        let exe_file = ptr_at(self.0, offset!(mm_exe_file))?;
        (!exe_file.is_null()).then_some(File(exe_file))
    }
    /// The user-space `[start, end)` of the argv strings.
    pub fn args(self) -> Option<(u64, u64)> {
        Some((read_at::<u64>(self.0, offset!(mm_arg_start))?, read_at::<u64>(self.0, offset!(mm_arg_end))?))
    }
    /// The user-space `[start, end)` of the envp strings.
    pub fn env(self) -> Option<(u64, u64)> {
        Some((read_at::<u64>(self.0, offset!(mm_env_start))?, read_at::<u64>(self.0, offset!(mm_env_end))?))
    }
}

/// A `struct linux_binprm *`.
#[derive(Clone, Copy)]
pub struct Binprm(*const u8);

impl Binprm {
    pub fn from_raw(raw: *const u8) -> Binprm {
        Binprm(raw)
    }
    pub fn raw(self) -> u64 {
        self.0 as u64
    }
    pub fn file(self) -> Option<File> {
        Some(File(ptr_at(self.0, offset!(binprm_file))?))
    }
    /// The `interp` string: the path of the binary the final binfmt pass loads.
    pub fn interp(self) -> Option<*const u8> {
        ptr_at(self.0, offset!(binprm_interp))
    }
    /// True on the first binfmt pass: no handler has replaced `interp` yet.
    pub fn first_pass(self) -> Option<bool> {
        Some(ptr_at(self.0, offset!(binprm_filename))? == ptr_at(self.0, offset!(binprm_interp))?)
    }
}

impl Inode {
    pub fn generation(self) -> Option<u32> {
        read_at::<u32>(self.0, offset!(inode_i_generation))
    }
}

impl File {
    /// The file's `(dev, ino, generation, subvolume)` identity. `btrfs` is the
    /// layout the active table keys btrfs with; without it a btrfs file's
    /// subvolume is `EXEC_SUBVOL_UNKNOWN`.
    pub fn exec_file(self, btrfs: Option<(i32, u32)>) -> Option<ExecFile> {
        let inode = self.inode()?;
        let sb = inode.super_block()?;
        let subvol = if sb.magic()? != BTRFS_SUPER_MAGIC {
            0
        } else if let Some((root, root_id)) = btrfs {
            inode.btrfs_subvolume(root, root_id)?
        } else {
            EXEC_SUBVOL_UNKNOWN
        };
        Some(ExecFile { dev: sb.dev()?.0, ino: inode.ino()?.0, generation: inode.generation()?, _pad: 0, subvol })
    }
}
