use std::{io::{self, BufRead}, 
net::{IpAddr, Ipv4Addr}};

fn main() {
    let stdin = io::stdin();

    // Read from stdin line by line
    for line in stdin.lock().lines() {
        match line {
            Ok(line) => {
                match check_for_ip(&line) {
                    Some(ip) => println!("Found IP address: {}", ip),
                    None => {}
                }
            }
            Err(err) => eprintln!("Error reading line: {}", err),
        }
    }
}

fn check_for_ip(input: &str) -> Option<Ipv4Addr> {
    if input.contains("Address:") {
        let ip = input.split_whitespace().last()?;
        let ip = ip.parse::<IpAddr>().ok()?;
        match ip {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        }
    } else {
        None
    }

}