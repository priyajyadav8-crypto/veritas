#![no_std]
#![no_main]

use aya_ebpf::macros::{tracepoint, map};
use aya_ebpf::programs::TracePointContext;
use aya_ebpf::maps::HashMap;

#[map]
static KERNEL_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[tracepoint(category = "syscalls", name = "sys_enter_getdents64")]
pub fn veritas(_ctx: TracePointContext) -> u32 {
    let pid = aya_ebpf::helpers::bpf_get_current_pid_tgid() as u32;
    KERNEL_PIDS.insert(&pid, &1u32, 0).ok();
    0u32
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
