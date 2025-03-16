use aya::programs::{Xdp, XdpFlags};
use aya::Bpf;
use std::path::Path;

fn main() -> Result<(), anyhow::Error> {
    let mut bpf = Bpf::load_file(Path::new("../xdp-program/target/release/libxdp_program.a"))?;
    let program: &mut Xdp = bpf.program_mut("xdp_blocker").unwrap().try_into()?;
    program.load()?;
    program.attach("eth0", XdpFlags::default())?; // Replace "eth0" with your interface
    println!("Blocking traffic to 1.2.3.4! Press Ctrl+C to stop.");
    std::thread::park();
    Ok(())
}