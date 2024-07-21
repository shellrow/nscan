use std::net::Ipv4Addr;
use std::{net::IpAddr, time::Duration};

use netdev::Interface;
use serde::{Deserialize, Serialize};

use crate::config::{DEFAULT_HOP_LIMIT, DEFAULT_PING_COUNT};
use crate::protocol::Protocol;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct PingSetting {
    pub if_index: u32,
    pub dst_hostname: String,
    pub dst_ip: IpAddr,
    pub dst_port: Option<u16>,
    pub hop_limit: u8,
    pub protocol: Protocol,
    pub count: u32,
    pub receive_timeout: Duration,
    pub probe_timeout: Duration,
    pub send_rate: Duration,
    pub tunnel: bool,
    pub loopback: bool,
}

impl Default for PingSetting {
    fn default() -> Self {
        Self {
            if_index: 0,
            dst_hostname: "localhost".to_string(),
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_port: None,
            hop_limit: DEFAULT_HOP_LIMIT,
            protocol: Protocol::ICMP,
            count: DEFAULT_PING_COUNT,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: false,
            loopback: false,
        }
    }
}

impl PingSetting {
    pub fn icmp_ping(
        interface: &Interface,
        dst_ip_addr: IpAddr,
        count: u32,
    ) -> Result<PingSetting, String> {
        let use_tun = interface.is_tun();
        let loopback = interface.is_loopback();

        let setting = PingSetting {
            if_index: interface.index,
            dst_ip: dst_ip_addr,
            dst_hostname: dst_ip_addr.to_string(),
            dst_port: None,
            hop_limit: 64,
            count: count,
            protocol: Protocol::ICMP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
    pub fn tcp_ping(
        interface: &Interface,
        dst_ip_addr: IpAddr,
        dst_port: u16,
        count: u32,
    ) -> Result<PingSetting, String> {
        let use_tun = interface.is_tun();
        let loopback = interface.is_loopback();

        let setting = PingSetting {
            if_index: interface.index,
            dst_ip: dst_ip_addr,
            dst_hostname: dst_ip_addr.to_string(),
            dst_port: Some(dst_port),
            hop_limit: 64,
            count: count,
            protocol: Protocol::TCP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
    pub fn udp_ping(
        interface: &Interface,
        dst_ip_addr: IpAddr,
        count: u32,
    ) -> Result<PingSetting, String> {
        let use_tun = interface.is_tun();
        let loopback = interface.is_loopback();

        let setting: PingSetting = PingSetting {
            if_index: interface.index,
            dst_ip: dst_ip_addr,
            dst_hostname: dst_ip_addr.to_string(),
            dst_port: Some(crate::config::DEFAULT_BASE_TARGET_UDP_PORT),
            hop_limit: 64,
            count: count,
            protocol: Protocol::UDP,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
}
