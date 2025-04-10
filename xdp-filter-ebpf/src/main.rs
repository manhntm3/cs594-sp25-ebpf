#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

mod maps;
mod xdp;
mod tc;

// Re-export the programs WITH their attributes
pub use xdp::xdp_filter;
pub use tc::tc_egress;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
