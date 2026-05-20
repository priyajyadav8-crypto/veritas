#![no_std]
#![no_main]

use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

#[tracepoint(category = "syscalls", name = "sys_enter_getdents64")]
pub fn veritas(_ctx: TracePointContext) -> u32 {
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
