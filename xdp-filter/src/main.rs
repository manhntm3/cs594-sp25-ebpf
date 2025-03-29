use anyhow::Context;
use aya::{
    programs::{Xdp, XdpFlags},
    maps::HashMap,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::signal;
// use std::io::BufRead;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    // let rlim = libc::rlimit {
    //     rlim_cur: libc::RLIM_INFINITY,
    //     rlim_max: libc::RLIM_INFINITY,
    // };
    // let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    // if ret != 0 {
    //     debug!("remove limit on locked memory failed, ret is: {}", ret);
    // }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    info!(env!("OUT_DIR"));
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-filter"
    )))?;

    let ebpf_ref = &mut ebpf;

    if let Err(e) = EbpfLogger::init(ebpf_ref) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = 
    ebpf_ref.program_mut("xdp_filter").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut v4_map: HashMap<_, u32, u32> = HashMap::try_from(ebpf.map_mut("BLOCKLIST_V4").unwrap())?;

    // let v4_map = HashMap::<_, u32, u32>::try_from(ebpf_ref.map_mut("BLOCKLIST_V4").unwrap())?;

    let block_addr: u32 = Ipv4Addr::new(54,237,226,164).into();
    v4_map.insert(block_addr, 0, 0)?;
    let block_addr: u32 = Ipv4Addr::new(52,3,144,142).into();
    v4_map.insert(block_addr, 0, 0)?;
    let block_addr: u32 = Ipv4Addr::new(3,230,129,93).into();
    v4_map.insert(block_addr, 0, 0)?;

    v4_map.pin("/sys/fs/bpf/blocklist_v4")?;


    let mut v6_map: HashMap<_, [u8; 16], [u8; 16]> = HashMap::try_from(ebpf.map_mut("BLOCKLIST_V6").unwrap())?;

    // let v6_map = HashMap::<_, [u8; 16], [u8; 16]>::try_from(ebpf_ref.map_mut("BLOCKLIST_V6").unwrap())?;
    
    let block_addr: [u8; 16] = Ipv6Addr::new(0x2600,0x1f18,0x631e,0x2f85,0x93a9,0xf7b0,0xd18,0x89a7).octets();
    v6_map.insert(block_addr, [0; 16], 0)?;
    let block_addr:  [u8; 16]= Ipv6Addr::new(0x2600,0x1f18,0x631e,0x2f84,0x4f7a,0x4092,0xe2e9,0xc617).octets();
    v6_map.insert(block_addr, [0; 16], 0)?;
    let block_addr:  [u8; 16]= Ipv6Addr::new(0x2600,0x1f18,0x631e,0x2f83,0x49ee,0xbeaa,0x2dfd,0xae8f).octets();
    v6_map.insert(block_addr, [0; 16], 0)?;
    
    v6_map.pin("/sys/fs/bpf/blocklist_v6")?;

    // println!("Reading blocklist.txt");
    // let file = std::fs::File::open("xdp-filter/blocklist.txt")?;
    // let reader = std::io::BufReader::new(file);
    // for line in reader.lines() {
    //     let line = line?;
    //     let ip: Ipv4Addr = line.parse()?;
    //     let ip = u32::from(ip);
    //     blocklist.insert(ip, 0, 0)?;
    // }



    
    // blocklist.pin("/sys/fs/bpf/blocklist")?;

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    if let Err(e) = std::fs::remove_file("/sys/fs/bpf/blocklist_v4") {
        warn!("Failed to remove blocklist_v4: {}", e);
    }
    if let Err(e) = std::fs::remove_file("/sys/fs/bpf/blocklist_v6") {
        warn!("Failed to remove blocklist_v6: {}", e);
    }    

    Ok(())
}
