use std::io::{self, BufRead};
use std::{net::{IpAddr, Ipv4Addr}, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use aya::{maps::Map, maps::HashMap, maps::MapData};
use clap::Parser;
use trust_dns_resolver::TokioAsyncResolver;
use std::convert::TryInto;

#[derive(Parser, Debug)]
#[command(name = "xdp-filter-dynamic", about = "Dynamically add resolved IP to eBPF filter map")]
struct Args {
    /// Domain to resolve and block
    domain: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    // Step 1: Resolve the domain to IP
    let ip = resolve_domain_to_ipv4(&args.domain)
        .await
        .context("Failed to resolve domain to IPv4")?;

    println!("Resolved {} to {}", args.domain, ip);

    // Load pinned map data
    let pinned_data = MapData::from_pin("/sys/fs/bpf/my_blocklist")?;
    let pinned_map = Map::HashMap(pinned_data);

    let mut blocklist: HashMap<_, u32, u32> = pinned_map.try_into()?;

    let ip_block = u32::from(ip);
    blocklist.insert(ip_block, 0, 0)?;

    println!("✅ Added {ip} to blocked IPs.");

    Ok(())
    
}

async fn resolve_domain_to_ipv4(domain: &str) -> Result<Ipv4Addr> {
    // Create a DNS resolver from the system config
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .context("Failed to create DNS resolver")?;

    // Lookup the IP addresses associated with the domain
    let response = resolver
        .lookup_ip(domain)
        .await
        .with_context(|| format!("Failed to look up IP for {domain}"))?;

    // Pick the first IPv4 address found
    let ip = response
        .iter()
        .find(|ip| ip.is_ipv4())
        .ok_or_else(|| anyhow!("No IPv4 address found for {domain}"))?;

    // Match to extract the Ipv4Addr
    match ip {
        IpAddr::V4(ipv4) => Ok(ipv4),
        IpAddr::V6(_) => bail!("No IPv4 address found for {domain}"),
    }
}