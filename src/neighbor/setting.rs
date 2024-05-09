use netdev::Interface;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{net::IpAddr, time::Duration};
use crate::protocol::Protocol;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AddressResolveSetting {
    pub if_index: u32,
    pub dst_hostname: String,
    pub dst_ip: IpAddr,
    pub protocol: Protocol,
    pub count: u32,
    pub receive_timeout: Duration,
    pub probe_timeout: Duration,
    pub send_rate: Duration,
    pub tunnel: bool,
    pub loopback: bool,
}

impl Default for AddressResolveSetting {
    fn default() -> Self {
        Self {
            if_index: 0,
            dst_hostname: "localhost".to_string(),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            protocol: Protocol::ARP,
            count: 1,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: false,
            loopback: false,
        }
    }
}

impl AddressResolveSetting {
    pub fn arp(
        interface: Interface,
        dst_ipv4_addr: Ipv4Addr,
        count: u32,
    ) -> Result<AddressResolveSetting, String> {
        if interface.is_tun() {
            return Err(format!("ARP: tun interface is not supported"));
        }
        if interface.is_loopback() {
            return Err(format!("ARP: loopback interface is not supported"));
        }
        let setting = AddressResolveSetting {
            if_index: interface.index,
            dst_ip: IpAddr::V4(dst_ipv4_addr),
            dst_hostname: dst_ipv4_addr.to_string(),
            count: count,
            protocol: Protocol::ARP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: false,
            loopback: false,
        };
        Ok(setting)
    }
    pub fn ndp(
        interface: Interface,
        dst_ipv6_addr: Ipv6Addr,
        count: u32,
    ) -> Result<AddressResolveSetting, String> {
        if interface.is_tun() {
            return Err(format!("NDP: tun interface is not supported"));
        }
        if interface.is_loopback() {
            return Err(format!("NDP: loopback interface is not supported"));
        }
        let setting = AddressResolveSetting {
            if_index: interface.index,
            dst_ip: IpAddr::V6(dst_ipv6_addr),
            dst_hostname: dst_ipv6_addr.to_string(),
            count: count,
            protocol: Protocol::NDP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: false,
            loopback: false,
        };
        Ok(setting)
    }
}
