#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use core::mem;

use aya_ebpf::{
    bindings::{xdp_action, TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{map, xdp, classifier},
    maps::HashMap,
    programs::{XdpContext, TcContext},
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static BLOCKLIST_V4: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static BLOCKLIST_V6: HashMap<[u8; 16], [u8; 16]> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_filter(ctx: XdpContext) -> u32 {
    match try_xdp_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
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

fn block_ipv4(ip: u32) -> bool {
    unsafe { BLOCKLIST_V4.get(&ip).is_some() }
}

fn block_ipv6(ip: [u8; 16]) -> bool {
    unsafe { BLOCKLIST_V6.get(&ip).is_some() }
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
                xdp_action::XDP_DROP
            } else {
                xdp_action::XDP_PASS
            };
            if source_addr != u32::from_be_bytes([172, 16, 172, 1]) {
                info!(
                    &ctx,
                    "SRC IPv4: {:i}, SRC PORT: {}, ACTION {}", source_addr, source_port, action
                );
            }
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
                xdp_action::XDP_DROP
            } else {
                xdp_action::XDP_PASS
            };

            info!(
                &ctx,
                "SRC IPv6: {:i}, SRC PORT: {}, ACTION {}", source_addr, source_port, action
            );

        }

        _ => return Ok(xdp_action::XDP_PASS),
    };

    Ok(action)
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
        TC_ACT_SHOT
    } else {
        TC_ACT_PIPE
    };

    info!(&ctx, "DEST {:i}, ACTION {}", destination, action);

    Ok(action)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
