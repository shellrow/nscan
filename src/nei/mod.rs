pub mod arp;
pub mod ndp;

use serde::{Deserialize, Serialize};

use anyhow::Result;
use netdev::mac::MacAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Structure of NetworkDevice information
#[derive(Deserialize, Serialize, Clone, Eq, PartialEq, Hash, Debug)]
pub struct NetworkDevice {
    /// MAC address of the device
    pub mac_addr: MacAddr,
    /// List of IPv4 address of the device
    pub ipv4: Vec<Ipv4Addr>,
    /// List of IPv6 address of the device
    pub ipv6: Vec<Ipv6Addr>,
}

impl NetworkDevice {
    /// Construct a new NetworkDevice instance
    pub fn new() -> NetworkDevice {
        NetworkDevice {
            mac_addr: MacAddr::zero(),
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        }
    }
}

pub fn resolve_next_hop(
    target_ip_addr: IpAddr,
    iface: &netdev::Interface,
) -> Result<NetworkDevice> {
    match target_ip_addr {
        IpAddr::V4(ipv4) => crate::nei::arp::send_arp(ipv4, iface),
        IpAddr::V6(ipv6) => crate::nei::ndp::send_ndp(ipv6, iface),
    }
}
