use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub index: u32,
    pub name: String,
    pub friendly_name: String,
    pub description: String,
    pub if_type: String,
    pub mac_addr: String,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
    pub gateway_mac_addr: String,
    pub gateway_ipv4: Ipv4Addr,
    pub gateway_ipv6: Ipv6Addr,
}

impl NetworkInterface {
    pub fn default() -> NetworkInterface {
        let default_interface:default_net::Interface = default_net::get_default_interface().unwrap();
        NetworkInterface {
            index: default_interface.index,
            name: default_interface.name,
            friendly_name: default_interface.friendly_name.unwrap_or(String::new()),
            description: default_interface.description.unwrap_or(String::new()),
            if_type: default_interface.if_type.name(),
            mac_addr: if let Some(mac_addr) = default_interface.mac_addr {mac_addr.address()} else {default_net::interface::MacAddr::zero().address()},
            ipv4: default_interface.ipv4.iter().map(|ip| ip.addr).collect(),
            ipv6: default_interface.ipv6.iter().map(|ip| ip.addr).collect(),
            gateway_mac_addr: if let Some(gateway) = &default_interface.gateway {gateway.mac_addr.address()} else {default_net::interface::MacAddr::zero().address()},
            gateway_ipv4: if let Some(gateway) = &default_interface.gateway {
                match gateway.ip_addr {
                    IpAddr::V4(ipv4) => {ipv4}
                    _ => {Ipv4Addr::UNSPECIFIED}
                }
            } else {Ipv4Addr::UNSPECIFIED},
            gateway_ipv6: if let Some(gateway) = &default_interface.gateway {
                match gateway.ip_addr {
                    IpAddr::V6(ipv6) => {ipv6}
                    _ => {Ipv6Addr::UNSPECIFIED}
                }
            } else {Ipv6Addr::UNSPECIFIED},
        }
    }
    pub fn from_default_net_type(interface: default_net::Interface) -> NetworkInterface {
        let if_type = if interface.if_type.name() == String::from("Unknown") && interface.is_tun() {String::from("Tunnel")} else {interface.if_type.name()};
        NetworkInterface {
            index: interface.index,
            name: interface.name,
            friendly_name: interface.friendly_name.unwrap_or(String::new()),
            description: interface.description.unwrap_or(String::new()),
            if_type: if_type,
            mac_addr: if let Some(mac_addr) = interface.mac_addr {mac_addr.address()} else {default_net::interface::MacAddr::zero().address()},
            ipv4: interface.ipv4.iter().map(|ip| ip.addr).collect(),
            ipv6: interface.ipv6.iter().map(|ip| ip.addr).collect(),
            gateway_mac_addr: if let Some(gateway) = &interface.gateway {gateway.mac_addr.address()} else {default_net::interface::MacAddr::zero().address()},
            gateway_ipv4: if let Some(gateway) = &interface.gateway {
                match gateway.ip_addr {
                    IpAddr::V4(ipv4) => {ipv4}
                    _ => {Ipv4Addr::UNSPECIFIED}
                }
            } else {Ipv4Addr::UNSPECIFIED},
            gateway_ipv6: if let Some(gateway) = &interface.gateway {
                match gateway.ip_addr {
                    IpAddr::V6(ipv6) => {ipv6}
                    _ => {Ipv6Addr::UNSPECIFIED}
                }
            } else {Ipv6Addr::UNSPECIFIED},
        }
    }
}

pub fn get_interfaces() -> Vec<NetworkInterface> {
    let mut interfaces: Vec<NetworkInterface> = vec![];
    for iface in default_net::get_interfaces() {
        interfaces.push(NetworkInterface::from_default_net_type(iface));
    }
    interfaces
}

pub fn get_interface_by_ip(ip_addr: IpAddr) -> Option<default_net::Interface> {
    for iface in default_net::get_interfaces() {
        match ip_addr {
            IpAddr::V4(ipv4) => {
                for ip in &iface.ipv4 {
                    if ip.addr == ipv4 {
                        return Some(iface);
                    }
                }
            }
            IpAddr::V6(ipv6) => {
                for ip in &iface.ipv6 {
                    if ip.addr == ipv6 {
                        return Some(iface);
                    }
                }
            }
        }
    }
    return None;
}

pub fn get_interface_by_name(if_name: String) -> Option<default_net::Interface> {
    for iface in default_net::get_interfaces() {
        if iface.name == if_name {
            return Some(iface);
        }
        if let Some(friendly_name) = &iface.friendly_name {
            if friendly_name == &if_name {
                return Some(iface);
            }
        }
    }
    return None;
}