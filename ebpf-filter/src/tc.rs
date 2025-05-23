use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

use crate::maps::{block_ipv4, block_ipv6};

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_tc_egress(ctx: TcContext) -> Result<i32, ()> {
    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            let destination = u32::from_be(ipv4hdr.dst_addr);
        
            let action = if block_ipv4(destination) {
                info!(&ctx, "DEST {:i}, BLOCKED", destination);
                TC_ACT_SHOT
            } else {
                info!(&ctx, "DEST {:i}, ALLOWED", destination);
                TC_ACT_PIPE
            };

           return Ok(action);
        }
        EtherType::Ipv6 => {
            let ipv6hdr: Ipv6Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
            let destination = unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 };

            let action = if block_ipv6(destination) {
                info!(&ctx, "DEST {:i}, BLOCKED", destination);
                TC_ACT_SHOT
            } else {
                info!(&ctx, "DEST {:i}, ALLOWED", destination);
                TC_ACT_PIPE
            };

            return Ok(action);
        }
        _ => return Ok(TC_ACT_PIPE),
    }
}