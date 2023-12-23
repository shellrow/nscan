use std::{net::IpAddr, collections::HashMap};
use default_net::mac::MacAddr;
use netprobe::{setting::ProbeSetting, neighbor::DeviceResolver};
use xenet::net::ipnet::{Ipv4Net, Ipv6Net};

pub fn get_network_address(ip_addr: IpAddr) -> Result<String, String> {
    match ip_addr {
        IpAddr::V4(ipv4_addr) => {
            let net: Ipv4Net = Ipv4Net::new(ipv4_addr, 24);
            Ok(net.network().to_string())
        }
        IpAddr::V6(ipv6_addr) => {
            let net: Ipv6Net = Ipv6Net::new(ipv6_addr, 24);
            Ok(net.network().to_string())
        }
    }
}

pub fn is_global_addr(ip_addr: IpAddr) -> bool {
    match ip_addr {
        IpAddr::V4(ipv4) => xenet::net::ipnet::is_global_ipv4(&ipv4),
        IpAddr::V6(ipv6) => xenet::net::ipnet::is_global_ipv6(&ipv6),
    }
}

pub fn in_same_network(src_ip: IpAddr, dst_ip: IpAddr) -> bool {
    let src_ip_nw = match get_network_address(src_ip) {
        Ok(nw) => nw,
        Err(_) => return false,
    };
    let dst_ip_nw = match get_network_address(dst_ip) {
        Ok(nw) => nw,
        Err(_) => return false,
    };
    if src_ip_nw == dst_ip_nw {
        true
    } else {
        false
    }
}

pub fn guess_initial_ttl(ttl: u8) -> u8 {
    if ttl <= 64 {
        64
    } else if 64 < ttl && ttl <= 128 {
        128
    } else {
        255
    }
}

pub fn get_mac_addresses(ips: Vec<IpAddr>, src_ip: IpAddr) -> HashMap<IpAddr, String> {
    let mut map : HashMap<IpAddr, String> = HashMap::new();
    if let Some(c_interface) = crate::interface::get_interface_by_ip(src_ip) {
        for ip in ips {
            if ip == src_ip {
                map.insert(ip, c_interface.clone().mac_addr.unwrap_or(MacAddr::zero()).to_string());
                continue;
            }
            if !is_global_addr(ip) && in_same_network(src_ip, ip) {
                let setting: ProbeSetting = match ip {
                    IpAddr::V4(ipv4) => {
                        ProbeSetting::arp(c_interface.clone(), ipv4, 1).unwrap()
                    },
                    IpAddr::V6(ipv6) => {
                        ProbeSetting::ndp(c_interface.clone(), ipv6, 1).unwrap()
                    }
                };
                let resolver: DeviceResolver = DeviceResolver::new(setting).unwrap();
                match resolver.resolve() {
                    Ok(result) => {
                        if result.results.len() > 0 {
                            map.insert(ip, result.results[0].mac_addr.address());
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }
    map
}
