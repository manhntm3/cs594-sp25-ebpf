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
    let ips = resolve_all_ipv4(&args.domain)
    .await
    .with_context(|| format!("Failed to resolve IPs for domain: {}", args.domain))?;

    println!("IPv4 addresses for {}:", args.domain);

    // Load pinned map data
    let pinned_data = MapData::from_pin("/sys/fs/bpf/blocklist")?;
    let pinned_map = Map::HashMap(pinned_data);

    let mut blocklist: HashMap<_, u32, u32> = pinned_map.try_into()?;

    for ip in ips {
        println!("{}", ip);
        let ip_block = u32::from(ip);
        blocklist.insert(ip_block, 0, 0)?;

        println!("✅ Added {ip} to blocked IPs.");
    }

    Ok(())
}

async fn resolve_all_ipv4(domain: &str) -> Result<Vec<Ipv4Addr>> {
    // Create a DNS resolver using system configuration
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .context("Failed to create DNS resolver")?;

    // Perform DNS lookup
    let response = resolver
        .lookup_ip(domain)
        .await
        .with_context(|| format!("DNS lookup failed for {}", domain))?;

    // Collect all IPv4 addresses
    let ipv4s: Vec<Ipv4Addr> = response
        .iter()
        .filter_map(|ip| {
            if let std::net::IpAddr::V4(v4) = ip {
                Some(v4)
            } else {
                None
            }
        })
        .collect();

    if ipv4s.is_empty() {
        return Err(anyhow!("No IPv4 addresses found for {}", domain));
    }

    Ok(ipv4s)
}