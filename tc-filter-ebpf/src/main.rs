#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use core::mem;

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{map, classifier},
    maps::HashMap,
    programs::{TcContext},
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use xdp_filter_common::{BLOCKLIST_V4, BLOCKLIST_V6};


#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn block_ipv4(ip: u32) -> bool {
    unsafe { BLOCKLIST_V4.get(&ip).is_some() }
}

fn block_ipv6(ip: [u8; 16]) -> bool {
    unsafe { BLOCKLIST_V6.get(&ip).is_some() }
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let destination = u32::from_be(ipv4hdr.dst_addr);

    let action = if block_ipv4(destination) {
        info!(&ctx, "DEST {:i}, BLOCKED", destination);
        TC_ACT_SHOT
    } else {
        info!(&ctx, "DEST {:i}, ALLOWED", destination);
        TC_ACT_PIPE
    };

    Ok(action)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
