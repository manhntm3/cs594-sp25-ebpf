#![no_std]
#![no_main]

use aya_ebpf::{macros::xdp, programs::XdpContext};
use aya_ebpf::bindings::xdp_action;
use aya_ebpf::helpers::bpf_probe_read_kernel;
use core::mem;

// Packed struct to match IPv4 header layout (20 bytes, no padding)
#[repr(C, packed)]
struct Ipv4Hdr {
    _version_ihl: u8,
    _tos: u8,
    _tot_len: u16,
    _id: u16,
    _frag_off: u16,
    _ttl: u8,
    _protocol: u8,
    _check: u16,
    src_addr: u32, // Source IP
    dst_addr: u32, // Destination IP
}

#[xdp]
pub fn xdp_blocker(ctx: XdpContext) -> u32 {
    // Get packet data bounds
    let data_start = match ctx.data() {
        start => start,
        // _ => return xdp_action::XDP_PASS, // Invalid packet
    };
    let data_end = match ctx.data_end() {
        end => end,
        // _ => return xdp_action::XDP_PASS,
    };

    // Check if packet is long enough for IPv4 header (20 bytes)
    if (data_end - data_start) < mem::size_of::<Ipv4Hdr>() as usize {
        return xdp_action::XDP_PASS; // Too short, skip
    }

    // Safely read the IPv4 header
    let ip_hdr: Ipv4Hdr = match unsafe {
        bpf_probe_read_kernel(data_start as *const Ipv4Hdr)
    } {
        Ok(hdr) => hdr,
        Err(_) => return xdp_action::XDP_PASS, // Read failed
    };

    // Block if destination is 1.2.3.4
    if ip_hdr.dst_addr == u32::from_be_bytes([1, 2, 3, 4]) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}