use crate::config::default::{DEFAULT_BASE_TARGET_UDP_PORT, DEFAULT_HOP_LIMIT, DEFAULT_PING_COUNT};
use crate::endpoint::Host;
use crate::protocol::Protocol;
use anyhow::Result;
use netdev::Interface;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::{net::IpAddr, time::Duration};

/// Settings for a ping operation
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct PingSetting {
    pub if_index: u32,
    pub dst_hostname: Option<String>,
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
            dst_hostname: None,
            dst_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_port: None,
            hop_limit: DEFAULT_HOP_LIMIT,
            protocol: Protocol::Icmp,
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
    /// Create a new ICMP ping setting
    pub fn icmp_ping(interface: &Interface, dst_host: Host, count: u32) -> Result<PingSetting> {
        let use_tun = interface.is_tun();
        let loopback = interface.is_loopback();

        let setting = PingSetting {
            if_index: interface.index,
            dst_ip: dst_host.ip,
            dst_hostname: dst_host.hostname,
            dst_port: None,
            hop_limit: 64,
            count: count,
            protocol: Protocol::Icmp,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
    /// Create a new TCP ping setting
    pub fn tcp_ping(
        interface: &Interface,
        dst_host: Host,
        dst_port: u16,
        count: u32,
    ) -> Result<PingSetting> {
        let use_tun = interface.is_tun();
        let loopback = interface.is_loopback();

        let setting = PingSetting {
            if_index: interface.index,
            dst_ip: dst_host.ip,
            dst_hostname: dst_host.hostname,
            dst_port: Some(dst_port),
            hop_limit: 64,
            count: count,
            protocol: Protocol::Tcp,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
    /// Create a new UDP ping setting
    pub fn udp_ping(interface: &Interface, dst_host: Host, count: u32) -> Result<PingSetting> {
        let use_tun = interface.is_tun();
        let loopback = interface.is_loopback();

        let setting: PingSetting = PingSetting {
            if_index: interface.index,
            dst_ip: dst_host.ip,
            dst_hostname: dst_host.hostname,
            dst_port: Some(DEFAULT_BASE_TARGET_UDP_PORT),
            hop_limit: 64,
            count: count,
            protocol: Protocol::Udp,
            receive_timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(30),
            send_rate: Duration::from_secs(1),
            tunnel: use_tun,
            loopback: loopback,
        };
        Ok(setting)
    }
}
