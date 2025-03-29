use std::io::{self, BufRead};
use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, str::FromStr};

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

    let (ipv4, ipv6) = resolve_all_ipv4(&args.domain).await;
    // .with_context(|| format!("Failed to resolve IPs for domain: {}", args.domain))?;

    // println!("IPv4 addresses for {}:", args.domain);

    // Load pinned map data
    let v4_map = Map::HashMap(MapData::from_pin("/sys/fs/bpf/blocklist_v4").unwrap());
    let v6_map = Map::HashMap(MapData::from_pin("/sys/fs/bpf/blocklist_v6").unwrap());


    let mut blocklist_v4: HashMap<_, u32, u32> = v4_map.try_into()?;

        
    match ipv4 {
        Some(ips) =>{
            for ip in ips {
                println!("{}", ip);
                let ip_block = u32::from(ip);
                blocklist_v4.insert(ip_block, 0, 0)?;
        
                println!("✅ Added {ip} to blocked IPs.");
            }
        },
        None => println!("No IPv4 addresses"),
    }

    let mut blocklist_v6: HashMap<_, [u8; 16], [u8; 16]> = v6_map.try_into()?;

    match ipv6 {
        Some(ips) =>{
            for ip in ips {
                println!("{}", ip);
                let ip_block = ip.octets();
                blocklist_v6.insert(ip_block, [0; 16], 0)?;
        
                println!("✅ Added {ip} to blocked IPs.");
            }
        },
        None => println!("No IPv4 addresses"),
    }


    Ok(())
}

async fn resolve_all_ipv4(domain: &str) -> (Option<Vec<Ipv4Addr>>, Option<Vec<Ipv6Addr>>) {
    // Create a DNS resolver using system configuration
    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .context("Failed to create DNS resolver").unwrap();

    // Perform DNS lookup
    let response = resolver
        .lookup_ip(domain)
        .await
        .with_context(|| format!("DNS lookup failed for {}", domain)).unwrap();

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

    let ipv6s: Vec<Ipv6Addr> = response
        .iter()
        .filter_map(|ip| {
            if let std::net::IpAddr::V6(v6) = ip {
                Some(v6)
            } else {
                None
            }
        })
        .collect();

    let mut ret_v4: Option<Vec<Ipv4Addr>> = None;

    if !ipv4s.is_empty() {
        ret_v4 = Some(ipv4s);
    }

    let mut ret_v6: Option<Vec<Ipv6Addr>> = None;

    if !ipv6s.is_empty() {
        ret_v6 = Some(ipv6s);
    }

    (ret_v4, ret_v6)
}