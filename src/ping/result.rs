use crate::probe::{ProbeResult, ProbeStatus};
use crate::protocol::Protocol;
use std::time::Duration;
use serde::{Deserialize, Serialize};

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
    pub min: Duration,
    /// Avarage RTT
    pub avg: Duration,
    /// Maximum RTT
    pub max: Duration,
}

impl PingStat {
    pub fn new() -> PingStat {
        PingStat {
            responses: Vec::new(),
            probe_time: Duration::from_millis(0),
            transmitted_count: 0,
            received_count: 0,
            min: Duration::from_millis(0),
            avg: Duration::from_millis(0),
            max: Duration::from_millis(0),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PingResult {
    pub stat: PingStat,
    pub probe_status: ProbeStatus,
    /// start-time in RFC 3339 and ISO 8601 date and time string
    pub start_time: String,
    /// end-time in RFC 3339 and ISO 8601 date and time string
    pub end_time: String,
    /// Elapsed time
    pub elapsed_time: Duration,
    pub protocol: Protocol,
}

impl PingResult {
    pub fn new() -> PingResult {
        PingResult {
            stat: PingStat::new(),
            probe_status: ProbeStatus::new(),
            start_time: String::new(),
            end_time: String::new(),
            elapsed_time: Duration::from_millis(0),
            protocol: Protocol::ICMP,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TracerouteResult {
    pub nodes: Vec<ProbeResult>,
    pub probe_status: ProbeStatus,
    /// start-time in RFC 3339 and ISO 8601 date and time string
    pub start_time: String,
    /// end-time in RFC 3339 and ISO 8601 date and time string
    pub end_time: String,
    /// Elapsed time
    pub elapsed_time: Duration,
    pub protocol: Protocol,
}

impl TracerouteResult {
    pub fn new() -> TracerouteResult {
        TracerouteResult {
            nodes: Vec::new(),
            probe_status: ProbeStatus::new(),
            start_time: String::new(),
            end_time: String::new(),
            elapsed_time: Duration::from_millis(0),
            protocol: Protocol::UDP,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceResolveResult {
    pub results: Vec<ProbeResult>,
    pub probe_status: ProbeStatus,
    /// start-time in RFC 3339 and ISO 8601 date and time string
    pub start_time: String,
    /// end-time in RFC 3339 and ISO 8601 date and time string
    pub end_time: String,
    /// Elapsed time
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
            protocol: Protocol::ARP,
        }
    }
}
