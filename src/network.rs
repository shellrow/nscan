use std::net::IpAddr;
use std::str::FromStr;
use ipnet::{Ipv4Net, Ipv6Net};

pub fn get_network_address(ip_str: String) -> Result<String, String>{
    let addr = IpAddr::from_str(&ip_str);
    match addr {
        Ok(ip_addr) => {
            match ip_addr {
                IpAddr::V4(ipv4_addr) => {
                    let net: Ipv4Net = Ipv4Net::new(ipv4_addr, 24).unwrap();
                    Ok(net.network().to_string())
                },
                IpAddr::V6(ipv6_addr) => {
                    let net: Ipv6Net = Ipv6Net::new(ipv6_addr, 24).unwrap();
                    Ok(net.network().to_string())
                },
            }
        },
        Err(_) => {
            Err(String::from("Invalid IP Address"))
        }
    }
}
