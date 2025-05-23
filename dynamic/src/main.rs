use std::{
    convert::TryInto,
    net::{Ipv4Addr, Ipv6Addr},
};

use anyhow::{Context, Result};
use aya::maps::{HashMap, Map, MapData};
use clap::Parser;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Parser, Debug)]
#[command(
    name = "xdp-filter-dynamic",
    about = "Dynamically add resolved IP to eBPF filter map"
)]
struct Args {
    /// Domain to resolve and block
    domain: String,

    /// If set, remove the domain instead of adding it
    #[arg(long)]
    remove: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let (ipv4, ipv6) = resolve_all_ips(&args.domain).await?;

    // println!("IPs addresses for {}:", args.domain);

    // Load pinned map data
    let v4_map = Map::HashMap(MapData::from_pin("/sys/fs/bpf/blocklist_v4").unwrap());
    let v6_map = Map::HashMap(MapData::from_pin("/sys/fs/bpf/blocklist_v6").unwrap());

    let mut blocklist_v4: HashMap<_, u32, u32> = v4_map.try_into()?;

    match ipv4 {
        Some(ips) => {
            for ip in ips {
                println!("{}", ip);
                let ip_block = u32::from(ip);

                if args.remove {
                    if let Err(_e) = blocklist_v4.remove(&ip_block) {
                        println!("Failed to remove {ip} from blocked IPs.");
                    } else {
                        println!("✅ Removed {ip} from blocked IPs.");
                    }
                } else {
                    blocklist_v4.insert(ip_block, 0, 0)?;
                    println!("✅ Added {ip} to blocked IPs.");
                }
            }
        }
        None => println!("No IPv4 addresses"),
    }

    let mut blocklist_v6: HashMap<_, [u8; 16], [u8; 16]> = v6_map.try_into()?;

    match ipv6 {
        Some(ips) => {
            for ip in ips {
                println!("{}", ip);
                let ip_block = ip.octets();
                if args.remove {
                    if let Err(_e) = blocklist_v6.remove(&ip_block) {
                        println!("Failed to remove {ip} from blocked IPs.");
                    } else {
                        println!("✅ Removed {ip} from blocked IPs.");
                    }
                } else {
                    println!("✅ Added {ip} to blocked IPs.");
                    blocklist_v6.insert(ip_block, [0; 16], 0)?;
                }
            }
        }
        None => println!("No IPv6 addresses"),
    }

    Ok(())
}

async fn resolve_all_ips(domain: &str) -> Result<(Option<Vec<Ipv4Addr>>, Option<Vec<Ipv6Addr>>)> {
    // Create a DNS resolver using system configuration
    let resolver =
        TokioAsyncResolver::tokio_from_system_conf().context("Failed to create DNS resolver")?;

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

    Ok((ret_v4, ret_v6))
}
