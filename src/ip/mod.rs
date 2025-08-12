use std::net::IpAddr;

use netdev::Interface;

pub fn is_global_addr(ip_addr: &IpAddr) -> bool {
    match ip_addr {
        IpAddr::V4(ipv4) => nex::net::ip::is_global_ipv4(&ipv4),
        IpAddr::V6(ipv6) => nex::net::ip::is_global_ipv6(&ipv6),
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

/// Get the next hop IP address for a target IP address based on the interface's routing information.
pub fn next_hop_ip(iface: &Interface, target: IpAddr) -> Option<IpAddr> {
    match target {
        IpAddr::V4(dst) => {
            // Check if the target IP is in the same network as the interface
            if let Some(_) = iface.ipv4.iter().find(|ipnet| ipnet.contains(&dst)) {
                return Some(IpAddr::V4(dst));
            }
            // off-link, return the default gateway (IPv4)
            match &iface.gateway {
                Some(gw) => gw.ipv4.iter().next().map(|ip| IpAddr::V4(*ip)),
                None => None,
            }
        }
        IpAddr::V6(dst) => {
            if let Some(_) = iface.ipv6.iter().find(|ipnet| ipnet.contains(&dst)) {
                return Some(IpAddr::V6(dst));
            }
            // off-link, return the default gateway (IPv6)
            match &iface.gateway {
                Some(gw) => gw.ipv6.iter().next().map(|ip| IpAddr::V6(*ip)),
                None => None,
            }
        }
    }
}
