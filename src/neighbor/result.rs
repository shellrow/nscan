use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::{probe::{ProbeResult, ProbeStatus}, protocol::Protocol};

#[derive(Clone, Debug, Serialize, Deserialize)]
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
