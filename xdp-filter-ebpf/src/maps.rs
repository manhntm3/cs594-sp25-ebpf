use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

#[map(name = "BLOCKLIST_V4")]
pub static BLOCKLIST_V4: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map(name = "BLOCKLIST_V6")]
pub static BLOCKLIST_V6: HashMap<[u8; 16], [u8; 16]> = HashMap::with_max_entries(1024, 0);


pub fn block_ipv4(ip: u32) -> bool {
    unsafe { BLOCKLIST_V4.get(&ip).is_some() }
}

pub fn block_ipv6(ip: [u8; 16]) -> bool {
    unsafe { BLOCKLIST_V6.get(&ip).is_some() }
}