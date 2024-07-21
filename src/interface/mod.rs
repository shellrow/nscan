use netdev::interface::Interface;
use netdev::mac::MacAddr;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub fn get_interface_by_ip(ip_addr: IpAddr) -> Option<Interface> {
    for iface in netdev::interface::get_interfaces() {
        for ip in iface.ipv4.clone() {
            if ip.addr == ip_addr {
                return Some(iface);
            }
        }
        for ip in iface.ipv6.clone() {
            if ip.addr == ip_addr {
                return Some(iface);
            }
        }
    }
    return None;
}

pub fn get_interface_by_index(index: u32) -> Option<Interface> {
    for iface in netdev::interface::get_interfaces() {
        if iface.index == index {
            return Some(iface);
        }
    }
    return None;
}

pub fn get_interface_by_name(name: String) -> Option<Interface> {
    for iface in netdev::interface::get_interfaces() {
        if iface.name == name {
            return Some(iface);
        }
    }
    return None;
}

pub fn get_interface_ipv4(iface: &Interface) -> Option<IpAddr> {
    for ip in iface.ipv4.clone() {
        return Some(IpAddr::V4(ip.addr));
    }
    return None;
}

pub fn get_interface_global_ipv6(iface: &Interface) -> Option<IpAddr> {
    for ip in iface.ipv6.clone() {
        if nex::net::ip::is_global_ipv6(&ip.addr) {
            return Some(IpAddr::V6(ip.addr));
        }
    }
    return None;
}

pub fn get_interface_local_ipv6(iface: &Interface) -> Option<IpAddr> {
    for ip in iface.ipv6.clone() {
        if !nex::net::ip::is_global_ipv6(&ip.addr) {
            return Some(IpAddr::V6(ip.addr));
        }
    }
    return None;
}

pub fn get_interface_ips(iface: &Interface) -> Vec<String> {
    let mut ips: Vec<String> = Vec::new();
    for ip in iface.ipv4.clone() {
        ips.push(ip.addr.to_string());
    }
    for ip in iface.ipv6.clone() {
        ips.push(ip.addr.to_string());
    }
    ips
}

pub fn get_local_ips(if_index: u32) -> HashSet<IpAddr> {
    let interface = get_interface_by_index(if_index).unwrap();
    let mut ips: HashSet<IpAddr> = HashSet::new();
    for ip in interface.ipv4.clone() {
        ips.insert(IpAddr::V4(ip.addr));
    }
    for ip in interface.ipv6.clone() {
        ips.insert(IpAddr::V6(ip.addr));
    }
    // localhost IP addresses
    ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    ips
}

pub fn get_default_local_ips() -> HashSet<IpAddr> {
    // Default interface IP addresses
    let default_interface = netdev::get_default_interface().unwrap();
    let mut ips: HashSet<IpAddr> = HashSet::new();
    for ip in default_interface.ipv4.clone() {
        ips.insert(IpAddr::V4(ip.addr));
    }
    for ip in default_interface.ipv6.clone() {
        ips.insert(IpAddr::V6(ip.addr));
    }
    // localhost IP addresses
    ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    ips
}

pub fn get_interface_local_ips(iface: &Interface) -> HashSet<IpAddr> {
    let mut ips: HashSet<IpAddr> = HashSet::new();
    for ip in iface.ipv4.clone() {
        ips.insert(IpAddr::V4(ip.addr));
    }
    for ip in iface.ipv6.clone() {
        ips.insert(IpAddr::V6(ip.addr));
    }
    // localhost IP addresses
    ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    ips
}

pub fn get_local_ip_map() -> HashMap<IpAddr, String> {
    let mut ip_map: HashMap<IpAddr, String> = HashMap::new();
    for iface in netdev::interface::get_interfaces() {
        for ip in iface.ipv4.clone() {
            ip_map.insert(IpAddr::V4(ip.addr), iface.name.clone());
        }
        for ip in iface.ipv6.clone() {
            ip_map.insert(IpAddr::V6(ip.addr), iface.name.clone());
        }
    }
    ip_map
}

// get usable interface list
pub fn get_usable_interfaces() -> Vec<Interface> {
    let mut usable_interfaces: Vec<Interface> = Vec::new();
    for iface in netdev::interface::get_interfaces() {
        if iface.is_up() && (iface.ipv4.len() > 0 || iface.ipv6.len() > 0) {
            usable_interfaces.push(iface);
        }
    }
    usable_interfaces
}

pub fn get_interface_macaddr(iface: &Interface) -> MacAddr {
    match &iface.mac_addr {
        Some(mac_addr) => mac_addr.clone(),
        None => MacAddr::zero(),
    }
}

pub fn get_gateway_macaddr(iface: &Interface) -> MacAddr {
    match &iface.gateway {
        Some(gateway) => gateway.mac_addr.clone(),
        None => MacAddr::zero(),
    }
}
