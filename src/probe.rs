use crate::endpoint::{Endpoint, NodeType, PortState};
use crate::protocol::Protocol;
use nex::net::mac::MacAddr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Settings for probe
#[derive(Debug, Clone)]
pub struct ProbeSetting {
    pub target_endpoints: Vec<Endpoint>,
    pub if_index: u32,
    pub host_concurrency: usize,
    pub port_concurrency: usize,
    pub task_timeout: Duration,
    pub connect_timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
}

impl ProbeSetting {
    /// Get a map of IP addresses to hostnames for DNS resolution
    pub fn get_dns_map(&self) -> HashMap<IpAddr, String> {
        let mut map = HashMap::new();
        for ep in &self.target_endpoints {
            if let Some(hostname) = &ep.hostname {
                map.insert(ep.ip, hostname.clone());
            }
        }
        map
    }
}

/// Status of probe
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum ProbeStatusKind {
    /// Successfully completed
    Done,
    /// Interrupted by error
    Error,
    /// Execution time exceeds the configured timeout value
    Timeout,
}

impl ProbeStatusKind {
    /// Get the name of the status
    pub fn name(&self) -> String {
        match *self {
            ProbeStatusKind::Done => String::from("Done"),
            ProbeStatusKind::Error => String::from("Error"),
            ProbeStatusKind::Timeout => String::from("Timeout"),
        }
    }
}

/// Status of probe
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProbeStatus {
    pub kind: ProbeStatusKind,
    pub message: String,
}

impl ProbeStatus {
    /// Create a new ProbeStatus with Done kind
    pub fn new() -> ProbeStatus {
        ProbeStatus {
            kind: ProbeStatusKind::Done,
            message: String::new(),
        }
    }
    /// Create a new ProbeStatus with Error kind and message
    pub fn with_error_message(message: String) -> ProbeStatus {
        ProbeStatus {
            kind: ProbeStatusKind::Error,
            message: message,
        }
    }
    /// Create a new ProbeStatus with Timeout kind and message
    pub fn with_timeout_message(message: String) -> ProbeStatus {
        ProbeStatus {
            kind: ProbeStatusKind::Timeout,
            message: message,
        }
    }
}

/// Result of probe
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProbeResult {
    /// Sequence number
    pub seq: u32,
    /// MAC address
    pub mac_addr: MacAddr,
    /// IP address
    pub ip_addr: IpAddr,
    /// Host name
    pub host_name: Option<String>,
    /// Port
    pub port_number: Option<u16>,
    /// Port Status
    pub port_status: Option<PortState>,
    /// Time To Live
    pub ttl: u8,
    /// Number of hops
    pub hop: u8,
    /// Round Trip Time (microsecond)
    pub rtt: Duration,
    /// Status
    pub probe_status: ProbeStatus,
    /// Protocol
    pub protocol: Protocol,
    /// Node type
    pub node_type: NodeType,
    /// Sent packet size
    pub sent_packet_size: usize,
    /// Received packet size
    pub received_packet_size: usize,
}

impl ProbeResult {
    /// Create a new ProbeResult with default values
    pub fn new() -> ProbeResult {
        ProbeResult {
            seq: 0,
            mac_addr: MacAddr::zero(),
            ip_addr: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            host_name: None,
            port_number: None,
            port_status: None,
            ttl: 0,
            hop: 0,
            rtt: Duration::from_millis(0),
            probe_status: ProbeStatus::new(),
            protocol: Protocol::Icmp,
            node_type: NodeType::Destination,
            sent_packet_size: 0,
            received_packet_size: 0,
        }
    }
    /// Create a new ProbeResult with timeout status
    pub fn timeout(
        seq: u32,
        ip_addr: IpAddr,
        host_name: Option<String>,
        protocol: Protocol,
        sent_packet_size: usize,
    ) -> ProbeResult {
        ProbeResult {
            seq: seq,
            mac_addr: MacAddr::zero(),
            ip_addr: ip_addr,
            host_name: host_name,
            port_number: None,
            port_status: None,
            ttl: 0,
            hop: 0,
            rtt: Duration::from_millis(0),
            probe_status: ProbeStatus::with_timeout_message(format!(
                "Request timeout for seq {}",
                seq
            )),
            protocol: protocol,
            node_type: NodeType::Destination,
            sent_packet_size: sent_packet_size,
            received_packet_size: 0,
        }
    }
    /// Create a new ProbeResult for trace timeout
    pub fn trace_timeout(
        seq: u32,
        protocol: Protocol,
        sent_packet_size: usize,
        node_type: NodeType,
    ) -> ProbeResult {
        ProbeResult {
            seq: seq,
            mac_addr: MacAddr::zero(),
            ip_addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            host_name: None,
            port_number: None,
            port_status: None,
            ttl: 0,
            hop: 0,
            rtt: Duration::from_millis(0),
            probe_status: ProbeStatus::with_timeout_message(format!(
                "Request timeout for seq {}",
                seq
            )),
            protocol: protocol,
            node_type: node_type,
            sent_packet_size: sent_packet_size,
            received_packet_size: 0,
        }
    }
}
