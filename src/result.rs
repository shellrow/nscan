use crate::option::Protocol;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::{time::Duration, vec};

/// Exit status of probe
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProbeStatus {
    /// Successfully completed
    Done,
    /// Interrupted by error
    Error,
    /// Execution time exceeds the configured timeout value
    Timeout,
}

/// Node type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeType {
    /// Default gateway
    DefaultGateway,
    /// Relay node
    Relay,
    /// Destination host
    Destination,
}

impl NodeType {
    /* pub fn name(&self) -> String {
        match *self {
            NodeType::DefaultGateway => String::from("DefaultGateway"),
            NodeType::Relay => String::from("Relay"),
            NodeType::Destination => String::from("Destination"),
        }
    } */
}

/// Node structure
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    /// Sequence number
    pub seq: u8,
    /// IP address
    pub ip_addr: IpAddr,
    /// Host name
    pub host_name: String,
    /// Time To Live
    pub ttl: Option<u8>,
    /// Number of hops
    pub hop: Option<u8>,
    /// Node type
    pub node_type: NodeType,
    /// Round Trip Time
    pub rtt: Duration,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortInfo {
    pub port_number: u16,
    pub port_status: String,
    pub service_name: String,
    pub service_version: String,
    pub remark: String,
}

impl PortInfo {
    /* pub fn new() -> PortInfo {
        PortInfo {
            port_number: 0,
            port_status: String::new(),
            service_name: String::new(),
            service_version: String::new(),
            remark: String::new(),
        }
    } */
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostInfo {
    pub ip_addr: String,
    pub host_name: String,
    pub mac_addr: String,
    pub vendor_info: String,
    pub os_name: String,
    pub cpe: String,
}

impl HostInfo {
    pub fn new() -> HostInfo {
        HostInfo {
            ip_addr: String::new(),
            host_name: String::new(),
            mac_addr: String::new(),
            vendor_info: String::new(),
            os_name: String::new(),
            cpe: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortScanResult {
    pub ports: Vec<PortInfo>,
    pub host: HostInfo,
    pub port_scan_time: Duration,
    pub service_detection_time: Duration,
    pub os_detection_time: Duration,
    pub total_scan_time: Duration,
}

impl PortScanResult {
    pub fn new() -> PortScanResult {
        PortScanResult {
            ports: vec![],
            host: HostInfo::new(),
            port_scan_time: Duration::from_millis(0),
            service_detection_time: Duration::from_millis(0),
            os_detection_time: Duration::from_millis(0),
            total_scan_time: Duration::from_millis(0),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostScanResult {
    pub hosts: Vec<HostInfo>,
    pub protocol: Protocol,
    pub port_number: u16,
    pub host_scan_time: Duration,
    pub lookup_time: Duration,
    pub total_scan_time: Duration,
}

impl HostScanResult {
    pub fn new() -> HostScanResult {
        HostScanResult {
            hosts: vec![],
            protocol: Protocol::ICMPv4,
            port_number: 0,
            host_scan_time: Duration::from_millis(0),
            lookup_time: Duration::from_millis(0),
            total_scan_time: Duration::from_millis(0),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PingResult {
    /// Sequence number
    pub seq: u8,
    /// IP address
    pub ip_addr: IpAddr,
    /// Host name
    pub host_name: String,
    /// Port
    pub port_number: Option<u16>,
    /// Time To Live
    pub ttl: u8,
    /// Number of hops
    pub hop: u8,
    /// Round Trip Time (microsecond)
    pub rtt: u64,
    /// Status
    pub status: ProbeStatus,
    /// Protocol
    pub protocol: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Domain {
    pub domain_name: String,
    pub ips: Vec<IpAddr>,
}

/// Result of domain scan  
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DomainScanResult {
    pub base_domain: String,
    /// HashMap of domain.
    ///
    /// (Domain, IP Addresses)
    pub domains: Vec<Domain>,
    /// Time from start to end of scan.  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ProbeStatus,
}

impl DomainScanResult {
    /* pub fn new() -> DomainScanResult {
        DomainScanResult {
            domains: vec![],
            scan_time: Duration::from_millis(0),
            scan_status: ProbeStatus::Done,
        }
    } */
}
