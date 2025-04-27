use anyhow::Context;
use aya::{
    maps::HashMap,
    programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include the eBPF object file as raw bytes at compile-time and load it at runtime.
    // `Bpf::load_file` can be also used to load program at runtime.
    info!(env!("OUT_DIR"));
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/ebpf-loader"
    )))?;

    let ebpf_ref = &mut ebpf;

    if let Err(e) = EbpfLogger::init(ebpf_ref) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt { iface } = opt;

    let xdp_program: &mut Xdp = ebpf_ref.program_mut("xdp_filter").unwrap().try_into()?;
    xdp_program.load()?;
    xdp_program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let tc_program: &mut SchedClassifier = ebpf_ref
    .program_mut("tc_egress")
    .unwrap()
    .try_into()?;

    tc_program.load()?;
    tc_program.attach(
        &iface,
        TcAttachType::Egress
    )?;    
    
    let v4_map: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.map_mut("BLOCKLIST_V4").unwrap())?;

    v4_map.pin("/sys/fs/bpf/blocklist_v4")?;

    let v6_map: HashMap<_, [u8; 16], [u8; 16]> =
        HashMap::try_from(ebpf.map_mut("BLOCKLIST_V6").unwrap())?;

    v6_map.pin("/sys/fs/bpf/blocklist_v6")?;

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
