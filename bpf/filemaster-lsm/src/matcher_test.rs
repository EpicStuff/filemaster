//! A test-only BPF object for Gate B: it shares `maps.rs` and `matcher.rs` with
//! the production object and drives the matcher over (pattern, name) pairs via
//! `BPF_PROG_TEST_RUN`, so the kernel matcher can be compared with Go's
//! `filepath.Match` on 10,000+ pairs without shipping any of this in the
//! production object. The Go harness fills the pattern tables (PATTERNS /
//! CHUNKS / TOKENS / RANGES) and writes the name into SCRATCH; this program runs
//! one match and leaves the result in EVAL.covered.

#![no_std]
#![no_main]

#[path = "maps.rs"]
mod maps;
#[path = "matcher.rs"]
mod matcher;

// decide.rs is not part of this object; matcher.rs only needs the maps module.

use aya_ebpf::cty::c_long;
use aya_ebpf::helpers::r#gen::bpf_loop;
use aya_ebpf::macros::map;
use aya_ebpf::maps::Array;
use filemaster_lsm_common::decision_maps::EVAL_BUDGET;

use core::ffi::c_void;

/// The pending match request, filled by the harness before each run.
#[repr(C)]
#[derive(Clone, Copy)]
struct Request {
	pattern_idx: u32,
	name_base: u32,
	name_end: u32,
	result: u32,
}

#[map]
static REQUEST: Array<Request> = Array::with_max_entries(1, 0);

#[no_mangle]
#[link_section = "syscall"]
fn run(_ctx: *mut c_void) -> i32 {
	let (Some(req), Some(e)) = (REQUEST.get_ptr_mut(0), maps::EVAL.get_ptr_mut(0)) else {
		return 0;
	};
	// SAFETY: this CPU's slots; the program is non-preemptible here.
	let req = unsafe { &mut *req };
	let e = unsafe { &mut *e };
	e.reset();
	matcher::setup_self_match(e, 0, req.pattern_idx, req.name_base, req.name_end);
	// SAFETY: the callback reads the EVAL map value, which outlives the call.
	unsafe {
		bpf_loop(EVAL_BUDGET, matcher::eval_step as *mut c_void, core::ptr::null_mut(), 0);
	}
	let Some(e) = maps::EVAL.get_ptr_mut(0) else {
		return 0;
	};
	// SAFETY: as above.
	let e = unsafe { &mut *e };
	req.result = e.covered;
	0
}

#[link_section = "license"]
#[used]
static LICENSE: [u8; 4] = *b"GPL\0";

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
	loop {}
}

#[allow(dead_code)]
fn _c_long_marker(_: c_long) {}
