#![no_std]
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

#[map]
pub static BLOCKLIST_V4: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
pub static BLOCKLIST_V6: HashMap<[u8; 16], [u8; 16]> = HashMap::with_max_entries(1024, 0);