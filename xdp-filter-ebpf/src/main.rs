#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_ebpf::{
    bindings::xdp_action, 
    macros::{map, xdp}, 
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EtherType, EthHdr},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
static BLOCKLIST_V4: HashMap<u32, u32> = 
    HashMap::with_max_entries(177402, 0);

#[map]
static BLOCKLIST_V6: HashMap<[u8; 16], [u8; 16]> = HashMap::with_max_entries(177402, 0);

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

fn block_ipv4(ip: u32) -> bool {
    unsafe { BLOCKLIST_V4.get(&ip).is_some() }
}

fn block_ipv6(ip: [u8; 16]) -> bool {
    unsafe { BLOCKLIST_V6.get(&ip).is_some() }
}

fn try_xdp_filter(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let mut action: u32 = 0;
    // let log_ip: [u8; 16];  // For logging (IPv6-sized buffer)
    let mut source_port: u16 = 0;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

             // Extract source port (TCP/UDP)
            let source_port = match unsafe { (*ipv4hdr).proto } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr = 
                        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr = 
                        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*udphdr).source })
                }
                _ => return Err(()),
            };


            let action: u32 = if block_ipv4(source_addr) {
                xdp_action::XDP_DROP
            } else {
                xdp_action::XDP_PASS
            };

            info!(&ctx, "SRC IPv4: {:i}, SRC PORT: {}, ACTION {}", source_addr, source_port, action);
            // Convert IPv4 to [u8; 16] for logging (zero-pad)
            // log_ip = {
            //     let bytes = source_addr.to_be_bytes();
            //     [
            //         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
            //         bytes[0], bytes[1], bytes[2], bytes[3]
            //     ]
            // };

        }
        EtherType::Ipv6 => {
            let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
            let source_addr = unsafe { (*ipv6hdr).src_addr.in6_u.u6_addr8 };

             // Extract source port (TCP/UDP)
            source_port = match unsafe { (*ipv6hdr).next_hdr } {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr = 
                        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*tcphdr).source })
                }
                IpProto::Udp => {
                    let udphdr: *const UdpHdr = 
                        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                    u16::from_be(unsafe { (*udphdr).source })
                }
                _ => return Err(()),
            };


            let action: u32 = if block_ipv6(source_addr) {
                xdp_action::XDP_DROP
            } else {
                xdp_action::XDP_PASS
            };

            // let source_addr = &source_addr[..];

            info!(&ctx, "SRC IPv6: {:i}, SRC PORT: {}, ACTION {}", source_addr, source_port, action);

            // log_ip = source_addr;

        }

        _ => return Ok(xdp_action::XDP_PASS),
    };

    
    // let log_ip = &log_ip[..];
    // Log the action (IPv6-sized IP for compatibility)
    // info!(&ctx, "SRC IP: {:x}, SRC PORT: {}, ACTION {}", log_ip, source_port, action);

    Ok(action)

}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
