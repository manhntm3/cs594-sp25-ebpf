use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;
use aya_ebpf::helpers::bpf_ktime_get_ns;

const THERSHOLD: u32 = 500;
const WINDOW: u64 = 1000000000;


pub struct RateLimit {
    pub last_update: u64,
    pub packet_count: u32,
}

impl RateLimit {
    pub fn new() -> Self {
        RateLimit {
            last_update: unsafe{bpf_ktime_get_ns()},
            packet_count: 1,
        }
    }
}

#[map(name = "BLOCKLIST_V4")]
pub static BLOCKLIST_V4: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map(name = "BLOCKLIST_V6")]
pub static BLOCKLIST_V6: HashMap<[u8; 16], [u8; 16]> = HashMap::with_max_entries(1024, 0);

#[map(name = "TRACKER_V4")]
pub static TRACKER_V4: HashMap<u32, RateLimit> = HashMap::with_max_entries(1024, 0);

#[map(name = "TRACKER_V6")]
pub static TRACKER_V6: HashMap<[u8; 16], RateLimit> = HashMap::with_max_entries(1024, 0);


pub fn block_ipv4(ip: u32) -> bool {
    unsafe { BLOCKLIST_V4.get(&ip).is_some() }
}

pub fn block_ipv6(ip: [u8; 16]) -> bool {
    unsafe { BLOCKLIST_V6.get(&ip).is_some() }
}

pub fn check_rate_limit_v4(ctx: &XdpContext ,ip: &u32)  {
    if let Some(rate_limit) = TRACKER_V4.get_ptr_mut(&ip) {
        unsafe{
            if bpf_ktime_get_ns() - (*rate_limit).last_update < WINDOW {
                (*rate_limit).packet_count += 1;
                if (*rate_limit).packet_count  > THERSHOLD {
                    info!(ctx, "IP: {:i} IS ATTACKING TOTAL PACKETS: {} SINCE {}ns AGO", *ip, (*rate_limit).packet_count, bpf_ktime_get_ns() - (*rate_limit).last_update);
                    BLOCKLIST_V4.insert(&ip, &0, 0).ok();
                }
            } else {
                (*rate_limit).last_update  = bpf_ktime_get_ns();
                (*rate_limit).packet_count = 1;
            }
        }
    }else{
        let rate_limit = RateLimit::new();
        TRACKER_V4.insert(&ip, &rate_limit, 0).ok();
    }
}

pub fn check_rate_limit_v6(ctx: &XdpContext ,ip: &[u8; 16])  {
    if let Some(rate_limit) = TRACKER_V6.get_ptr_mut(&ip) {
        unsafe{
            if bpf_ktime_get_ns() - (*rate_limit).last_update < WINDOW {
                (*rate_limit).packet_count += 1;
                if (*rate_limit).packet_count  > THERSHOLD {
                    info!(ctx, "IP: {:i} IS ATTACKING TOTAL PACKETS: {} SINCE {}ns AGO", *ip, (*rate_limit).packet_count, bpf_ktime_get_ns() - (*rate_limit).last_update);
                    BLOCKLIST_V6.insert(&ip, &[0;16], 0).ok();
                }
            } else {
                (*rate_limit).last_update  = bpf_ktime_get_ns();
                (*rate_limit).packet_count = 1;
            }
        }
    }else{
        let rate_limit = RateLimit::new();
        TRACKER_V6.insert(&ip, &rate_limit, 0).ok();
    }
}