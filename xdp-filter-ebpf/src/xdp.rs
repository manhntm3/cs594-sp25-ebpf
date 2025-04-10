
use aya_ebpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
    icmp::IcmpHdr,
};

use crate::maps::{block_ipv4, block_ipv6};

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    match try_xdp_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}


fn try_xdp_filter(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let action: u32;
    let source_port: u16;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

            // Extract source port (TCP/UDP)
            source_port = match unsafe { (*ipv4hdr).proto } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*udphdr).source })
                }
                IpProto::Icmp => {
                    let icmphdr: *const IcmpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*icmphdr).un.echo.id })
                }
                _ => {
                    info!(&ctx, "Unknown protocol {}", unsafe {
                        (*ipv4hdr).proto as u8
                    });
                    return Err(());
                }
            };

            action = if block_ipv4(source_addr) {
                info!(
                    &ctx,
                    "SRC IPv4: {:i}, SRC PORT: {}, PACKET DROPPED", source_addr, source_port
                );
                xdp_action::XDP_DROP
            } else {
                info!(
                    &ctx,
                    "SRC IPv4: {:i}, SRC PORT: {}, PACKET ALLOWED", source_addr, source_port
                );
                xdp_action::XDP_PASS
            };
        }
        EtherType::Ipv6 => {
            let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let source_addr = unsafe { (*ipv6hdr).src_addr.in6_u.u6_addr8 };

            // Extract source port (TCP/UDP)
            source_port = match unsafe { (*ipv6hdr).next_hdr } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*udphdr).source })
                }
                IpProto::Icmp => {
                    let icmphdr: *const IcmpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv6Hdr::LEN)?;
                    u16::from_be(unsafe { (*icmphdr).un.echo.id })
                }
                _ => {
                    info!(&ctx, "Unknown protocol {}", unsafe {
                        (*ipv6hdr).next_hdr as u8
                    });
                    return Err(());
                }
            };

            action = if block_ipv6(source_addr) {
                info!(
                    &ctx,
                    "SRC IPv6: {:i}, SRC PORT: {}, PACKET DROPPED", source_addr, source_port
                );
                xdp_action::XDP_DROP
            } else {
                info!(
                    &ctx,
                    "SRC IPv6: {:i}, SRC PORT: {}, PACKET ALLOWED", source_addr, source_port
                );
                xdp_action::XDP_PASS
            };

        }

        _ => return Ok(xdp_action::XDP_PASS),
    };

    Ok(action)
}
