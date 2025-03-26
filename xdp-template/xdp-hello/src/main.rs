use anyhow::Context;
use aya::{
    programs::{Xdp, XdpFlags},
    maps::HashMap,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
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
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp-hello"
    )))?;
    if let Err(e) = EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = 
        ebpf.program_mut("xdp_hello").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.map_mut("BLOCKLIST").unwrap())?;

    // println!("Reading blocklist.txt");
    // let file = std::fs::File::open("xdp-hello/blocklist.txt")?;
    // let reader = std::io::BufReader::new(file);
    // for line in reader.lines() {
    //     let line = line?;
    //     let ip: Ipv4Addr = line.parse()?;
    //     let ip = u32::from(ip);
    //     blocklist.insert(ip, 0, 0)?;
    // }

    let block_addr: u32 = Ipv4Addr::new(34,201,207,153).into();
    blocklist.insert(block_addr, 0, 0)?;

    let block_addr: u32 = Ipv4Addr::new(3,214,199,225).into();
    blocklist.insert(block_addr, 0, 0)?;

    let block_addr: u32 = Ipv4Addr::new(54,204,180,25).into();
    blocklist.insert(block_addr, 0, 0)?;

    let block_addr: u32 = Ipv4Addr::new(3,211,174,179).into();
    blocklist.insert(block_addr, 0, 0)?;

    let block_addr: u32 = Ipv4Addr::new(34,193,184,57).into();
    blocklist.insert(block_addr, 0, 0)?;

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
