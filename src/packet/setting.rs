use crate::{
    config::DEFAULT_LOCAL_UDP_PORT,
    ping::setting::PingSetting,
};
use netdev::mac::MacAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug)]
pub struct PacketBuildSetting {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub hop_limit: u8,
    pub payload: Vec<u8>,
    pub ip_packet: bool,
}

impl PacketBuildSetting {
    pub fn new() -> Self {
        Self {
            src_mac: MacAddr::zero(),
            dst_mac: MacAddr::zero(),
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            src_port: 0,
            dst_port: 0,
            hop_limit: 64,
            payload: Vec::new(),
            ip_packet: false,
        }
    }
    pub fn from_ping_setting(ping_setting: &PingSetting) -> Self {
        match crate::interface::get_interface_by_index(ping_setting.if_index) {
            Some(interface) => {
                let dst_mac = match &interface.gateway {
                    Some(gateway) => gateway.mac_addr,
                    None => MacAddr::zero(),
                };
                let src_ip = match ping_setting.dst_ip {
                    IpAddr::V4(_) => crate::interface::get_interface_ipv4(&interface)
                        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    IpAddr::V6(ipv6_addr) => {
                        if nex::net::ip::is_global_ipv6(&ipv6_addr) {
                            crate::interface::get_interface_global_ipv6(&interface)
                                .unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST))
                        } else {
                            crate::interface::get_interface_local_ipv6(&interface)
                                .unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST))
                        }
                    }
                };
                Self {
                    src_mac: interface.mac_addr.unwrap_or(MacAddr::zero()),
                    dst_mac: dst_mac,
                    src_ip: src_ip,
                    dst_ip: ping_setting.dst_ip,
                    src_port: DEFAULT_LOCAL_UDP_PORT,
                    dst_port: ping_setting.dst_port.unwrap_or(0),
                    hop_limit: ping_setting.hop_limit,
                    payload: Vec::new(),
                    ip_packet: interface.is_tun() || interface.is_loopback(),
                }
            }
            None => Self {
                src_mac: MacAddr::zero(),
                dst_mac: MacAddr::zero(),
                src_ip: ping_setting.dst_ip,
                dst_ip: ping_setting.dst_ip,
                src_port: 0,
                dst_port: 0,
                hop_limit: ping_setting.hop_limit,
                payload: Vec::new(),
                ip_packet: false,
            },
        }
    }
}
