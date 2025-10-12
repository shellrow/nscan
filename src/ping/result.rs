use crate::{probe::{ProbeResult, ProbeStatus, ProbeStatusKind}, protocol::Protocol};
use serde::{Deserialize, Serialize};
use std::{net::{IpAddr, Ipv4Addr}, time::Duration};

/// Statistics of ping results
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PingStat {
    /// Ping responses
    pub responses: Vec<ProbeResult>,
    /// The entire ping probe time
    pub probe_time: Duration,
    /// Transmitted packets
    pub transmitted_count: usize,
    /// Received packets
    pub received_count: usize,
    /// Minimum RTT
    pub min: Option<Duration>,
    /// Avarage RTT
    pub avg: Option<Duration>,
    /// Maximum RTT
    pub max: Option<Duration>,
}

impl PingStat {
    pub fn new() -> PingStat {
        PingStat {
            responses: Vec::new(),
            probe_time: Duration::from_millis(0),
            transmitted_count: 0,
            received_count: 0,
            min: None,
            avg: None,
            max: None,
        }
    }
}

/// Result of a ping operation
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PingResult {
    pub stat: PingStat,
    pub probe_status: ProbeStatus,
    pub elapsed_time: Duration,
    pub ip_addr: IpAddr,
    pub hostname: Option<String>,
    pub port_number: Option<u16>,
    pub protocol: Protocol,
}

impl PingResult {
    pub fn new() -> PingResult {
        PingResult {
            stat: PingStat::new(),
            probe_status: ProbeStatus::new(),
            elapsed_time: Duration::from_millis(0),
            ip_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            hostname: None,
            port_number: None,
            protocol: Protocol::Icmp,
        }
    }
    /// Return first successful response
    pub fn first_response(&self) -> Option<&ProbeResult> {
        self.stat.responses.iter().find(|r| r.probe_status.kind == ProbeStatusKind::Done)
    }
}

/// Result of device resolution (ARP/NDP)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceResolveResult {
    pub results: Vec<ProbeResult>,
    pub probe_status: ProbeStatus,
    /// start-time in RFC 3339 and ISO 8601 date and time string
    pub start_time: String,
    /// end-time in RFC 3339 and ISO 8601 date and time string
    pub end_time: String,
    pub elapsed_time: Duration,
    pub protocol: Protocol,
}

impl DeviceResolveResult {
    pub fn new() -> DeviceResolveResult {
        DeviceResolveResult {
            results: Vec::new(),
            probe_status: ProbeStatus::new(),
            start_time: String::new(),
            end_time: String::new(),
            elapsed_time: Duration::from_millis(0),
            protocol: Protocol::Arp,
        }
    }
}
