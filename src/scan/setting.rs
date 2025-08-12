use crate::host::Host;
use crate::protocol::Protocol;
use crate::scan::payload::PayloadBuilder;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::config::DEFAULT_PORTS_CONCURRENCY;

use super::payload::PayloadInfo;

/* /// Scan Type
#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum ScanType {
    /// Port scan type.
    PortScan(PortScanType),
    /// Host scan type.
    HostScan(HostScanType),
}
 */

/// Port Scan Type
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq, Hash)]
pub enum PortScanType {
    /// Default fast port scan type.
    ///
    /// Send TCP packet with SYN flag to the target ports and check response.
    TcpSynScan,
    /// Attempt TCP connection and check port status.
    ///
    /// Slow but can be run without administrator privileges.
    TcpConnectScan,
}

impl PortScanType {
    pub fn from_str(scan_type: &str) -> PortScanType {
        match scan_type.to_uppercase().as_str() {
            "SYN" | "TCP-SYN" | "TCP_SYN" => PortScanType::TcpSynScan,
            "CONNECT" | "TCP-CONNECT" | "TCP_CONNECT" => PortScanType::TcpConnectScan,
            _ => PortScanType::TcpSynScan,
        }
    }
    pub fn to_str(&self) -> &str {
        match self {
            PortScanType::TcpSynScan => "TCP-SYN",
            PortScanType::TcpConnectScan => "TCP-CONNECT",
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct PortScanSetting {
    pub if_index: u32,
    pub targets: Vec<Host>,
    pub protocol: Protocol,
    pub scan_type: PortScanType,
    pub concurrency: usize,
    pub task_timeout: Duration,
    pub connect_timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub randomize: bool,
    pub minimize_packet: bool,
    pub dns_map: HashMap<IpAddr, String>,
    pub async_scan: bool,
}

impl Default for PortScanSetting {
    fn default() -> Self {
        Self {
            if_index: 0,
            targets: Vec::new(),
            protocol: Protocol::TCP,
            scan_type: PortScanType::TcpConnectScan,
            concurrency: DEFAULT_PORTS_CONCURRENCY,
            task_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_millis(200),
            wait_time: Duration::from_millis(100),
            send_rate: Duration::from_millis(0),
            randomize: true,
            minimize_packet: false,
            dns_map: HashMap::new(),
            async_scan: false,
        }
    }
}

impl PortScanSetting {
    // support builder pattern for all fields
    pub fn set_if_index(mut self, if_index: u32) -> Self {
        self.if_index = if_index;
        self
    }
    pub fn add_target(mut self, target: Host) -> Self {
        self.targets.push(target);
        self
    }
    pub fn set_targets(mut self, targets: Vec<Host>) -> Self {
        self.targets = targets;
        self
    }
    pub fn set_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }
    pub fn set_scan_type(mut self, scan_type: PortScanType) -> Self {
        self.scan_type = scan_type;
        self
    }
    pub fn set_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }
    pub fn set_task_timeout(mut self, timeout: Duration) -> Self {
        self.task_timeout = timeout;
        self
    }
    pub fn set_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }
    pub fn set_wait_time(mut self, wait_time: Duration) -> Self {
        self.wait_time = wait_time;
        self
    }
    pub fn set_send_rate(mut self, send_rate: Duration) -> Self {
        self.send_rate = send_rate;
        self
    }
    pub fn set_randomize(mut self, randomize: bool) -> Self {
        self.randomize = randomize;
        self
    }
    pub fn set_minimize_packet(mut self, minimize_packet: bool) -> Self {
        self.minimize_packet = minimize_packet;
        self
    }
    pub fn set_dns_map(mut self, dns_map: HashMap<IpAddr, String>) -> Self {
        self.dns_map = dns_map;
        self
    }
    pub fn set_async_scan(mut self, async_scan: bool) -> Self {
        self.async_scan = async_scan;
        self
    }
    pub fn randomize_hosts(&mut self) {
        let mut rng = rand::thread_rng();
        self.targets.shuffle(&mut rng);
    }
    pub fn randomize_ports(&mut self) {
        for target in &mut self.targets {
            target.ports.shuffle(&mut rand::thread_rng());
        }
    }
}

/// Host Scan Type
#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum HostScanType {
    /// Default host scan type.
    ///
    /// Send ICMP echo request and check response.
    IcmpPingScan,
    /// Perform host scan for a specific service.
    ///
    /// Send TCP packets with SYN flag to a specific port and check response.
    TcpPingScan,
    /// Send UDP packets to a probably closed port and check response.
    /// This expects ICMP port unreachable message.
    UdpPingScan,
}

impl HostScanType {
    pub fn from_str(scan_type: &str) -> HostScanType {
        match scan_type {
            "ICMP" | "ICMP-PING" | "ICMP_PING" => HostScanType::IcmpPingScan,
            "TCP" | "TCP-PING" | "TCP_PING" => HostScanType::TcpPingScan,
            "UDP" | "UDP-PING" | "UDP_PING" => HostScanType::UdpPingScan,
            _ => HostScanType::IcmpPingScan,
        }
    }
    pub fn to_str(&self) -> &str {
        match self {
            HostScanType::IcmpPingScan => "ICMP-PING",
            HostScanType::TcpPingScan => "TCP-PING",
            HostScanType::UdpPingScan => "UDP-PING",
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct HostScanSetting {
    pub if_index: u32,
    pub targets: Vec<Host>,
    pub protocol: Protocol,
    pub scan_type: HostScanType,
    pub concurrency: usize,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub send_rate: Duration,
    pub randomize: bool,
    pub minimize_packet: bool,
    pub dns_map: HashMap<IpAddr, String>,
    pub async_scan: bool,
    pub detect_only: bool,
}

impl Default for HostScanSetting {
    fn default() -> Self {
        Self {
            if_index: 0,
            targets: Vec::new(),
            protocol: Protocol::ICMP,
            scan_type: HostScanType::IcmpPingScan,
            concurrency: DEFAULT_PORTS_CONCURRENCY,
            timeout: Duration::from_secs(30),
            wait_time: Duration::from_millis(200),
            send_rate: Duration::from_millis(0),
            randomize: true,
            minimize_packet: false,
            dns_map: HashMap::new(),
            async_scan: false,
            detect_only: false,
        }
    }
}

impl HostScanSetting {
    // support builder pattern for all fields
    pub fn set_if_index(mut self, if_index: u32) -> Self {
        self.if_index = if_index;
        self
    }
    pub fn set_targets(mut self, targets: Vec<Host>) -> Self {
        self.targets = targets;
        self
    }
    pub fn set_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }
    pub fn set_scan_type(mut self, scan_type: HostScanType) -> Self {
        self.scan_type = scan_type;
        self
    }
    pub fn set_concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }
    pub fn set_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    pub fn set_wait_time(mut self, wait_time: Duration) -> Self {
        self.wait_time = wait_time;
        self
    }
    pub fn set_send_rate(mut self, send_rate: Duration) -> Self {
        self.send_rate = send_rate;
        self
    }
    pub fn set_randomize(mut self, randomize: bool) -> Self {
        self.randomize = randomize;
        self
    }
    pub fn set_minimize_packet(mut self, minimize_packet: bool) -> Self {
        self.minimize_packet = minimize_packet;
        self
    }
    pub fn set_dns_map(mut self, dns_map: HashMap<IpAddr, String>) -> Self {
        self.dns_map = dns_map;
        self
    }
    pub fn add_target(mut self, target: Host) -> Self {
        self.targets.push(target);
        self
    }
    pub fn set_async_scan(mut self, async_scan: bool) -> Self {
        self.async_scan = async_scan;
        self
    }
    pub fn set_detect_only(mut self, detect_only: bool) -> Self {
        self.detect_only = detect_only;
        self
    }
    pub fn randomize_hosts(&mut self) {
        let mut rng = rand::thread_rng();
        self.targets.shuffle(&mut rng);
    }
    pub fn randomize_ports(&mut self) {
        for target in &mut self.targets {
            target.ports.shuffle(&mut rand::thread_rng());
        }
    }
    pub fn get_target_map(&self) -> HashMap<IpAddr, Host> {
        let mut target_map: HashMap<IpAddr, Host> = HashMap::new();
        for target in &self.targets {
            target_map.insert(target.ip_addr, target.clone());
        }
        target_map
    }
}

/// Probe setting for service detection
#[derive(Clone, Debug)]
pub struct ServiceProbeSetting {
    /// Destination IP address
    pub ip_addr: IpAddr,
    /// Destination Host Name
    pub hostname: String,
    /// Target ports for service detection
    pub ports: Vec<u16>,
    /// TCP connect (open) timeout
    pub connect_timeout: Duration,
    /// TCP read timeout
    pub read_timeout: Duration,
    /// SSL/TLS certificate validation when detecting HTTPS services.  
    ///
    /// Default value is false, which means validation is enabled.
    pub accept_invalid_certs: bool,
    /// Payloads for specified ports.
    ///
    /// If not set, default null probe will be used. (No payload, just open TCP connection and read response)
    pub payload_map: HashMap<u16, PayloadInfo>,
    /// Concurrent connection limit for service detection
    pub concurrent_limit: usize,
}

impl ServiceProbeSetting {
    /// Create new ProbeSetting
    pub fn new() -> ServiceProbeSetting {
        ServiceProbeSetting {
            ip_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            hostname: String::new(),
            ports: vec![],
            connect_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_secs(5),
            accept_invalid_certs: false,
            payload_map: HashMap::new(),
            concurrent_limit: 10,
        }
    }
    pub fn default(ip_addr: IpAddr, hostname: String, ports: Vec<u16>) -> ServiceProbeSetting {
        let mut payload_map: HashMap<u16, PayloadInfo> = HashMap::new();
        let http_head = PayloadBuilder::http_head();
        let https_head = PayloadBuilder::https_head(&hostname);
        payload_map.insert(80, http_head.clone());
        payload_map.insert(443, https_head.clone());
        payload_map.insert(8080, http_head);
        payload_map.insert(8443, https_head);
        ServiceProbeSetting {
            ip_addr: ip_addr,
            hostname: hostname,
            ports: ports,
            connect_timeout: Duration::from_secs(1),
            read_timeout: Duration::from_secs(5),
            accept_invalid_certs: false,
            payload_map: payload_map,
            concurrent_limit: 10,
        }
    }
    /// Set Destination IP address
    pub fn with_ip_addr(&mut self, ip_addr: IpAddr) -> &mut Self {
        self.ip_addr = ip_addr;
        self
    }
    /// Set Destination Host Name. If IP address is not set, it will be resolved from the hostname.
    pub fn with_hostname(&mut self, hostname: String) -> &mut Self {
        self.hostname = hostname;
        if self.ip_addr == IpAddr::V4(Ipv4Addr::LOCALHOST)
            || self.ip_addr == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            || self.ip_addr == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            || self.ip_addr == IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        {
            if let Some(ip_addr) = crate::dns::lookup_host_name(&self.hostname) {
                self.ip_addr = ip_addr;
            }
        }
        self
    }
    /// Add target port
    pub fn add_port(&mut self, port: u16) {
        self.ports.push(port);
    }
    /// Set connect (open) timeout in milliseconds
    pub fn set_connect_timeout_millis(&mut self, connect_timeout_millis: u64) {
        self.connect_timeout = Duration::from_millis(connect_timeout_millis);
    }
    /// Set TCP read timeout in milliseconds
    pub fn set_read_timeout_millis(&mut self, read_timeout_millis: u64) {
        self.read_timeout = Duration::from_millis(read_timeout_millis);
    }
}

/// Probe setting for OS detection
#[derive(Clone, Debug)]
pub struct OsProbeSetting {
    /// Interface index for sending packets
    pub if_index: u32,
    /// Destination IP address
    pub ip_addr: IpAddr,
    /// Destination Host Name
    pub hostname: String,
    /// Target ports for OS detection
    pub ports: Vec<u16>,
    pub task_timeout: Duration,
    pub wait_time: Duration,
    /// TCP connect (open) timeout
    pub connect_timeout: Duration,
    /// TCP read timeout
    pub read_timeout: Duration,
    pub send_rate: Duration,
}

impl OsProbeSetting {
    /// Create new ProbeSetting
    pub fn new() -> OsProbeSetting {
        OsProbeSetting {
            if_index: 0,
            ip_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            hostname: String::new(),
            ports: vec![],
            task_timeout: Duration::from_secs(30),
            wait_time: Duration::from_millis(200),
            connect_timeout: Duration::from_millis(200),
            read_timeout: Duration::from_secs(5),
            send_rate: Duration::from_millis(0),
        }
    }
    pub fn with_if_index(&mut self, if_index: u32) -> &mut Self {
        self.if_index = if_index;
        self
    }
    /// Set Destination IP address
    pub fn with_ip_addr(&mut self, ip_addr: IpAddr) -> &mut Self {
        self.ip_addr = ip_addr;
        self
    }
    /// Set Destination Host Name. If IP address is not set, it will be resolved from the hostname.
    pub fn with_hostname(&mut self, hostname: String) -> &mut Self {
        self.hostname = hostname;
        if self.ip_addr == IpAddr::V4(Ipv4Addr::LOCALHOST)
            || self.ip_addr == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            || self.ip_addr == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            || self.ip_addr == IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        {
            if let Some(ip_addr) = crate::dns::lookup_host_name(&self.hostname) {
                self.ip_addr = ip_addr;
            }
        }
        self
    }
    /// Add target port
    pub fn add_port(&mut self, port: u16) -> &mut Self {
        self.ports.push(port);
        self
    }
    /// Set target ports
    pub fn with_ports(&mut self, ports: Vec<u16>) -> &mut Self {
        self.ports = ports;
        self
    }
    /// Freeze and return a new OsProbeSetting
    pub fn freeze(&self) -> OsProbeSetting {
        OsProbeSetting {
            if_index: self.if_index,
            ip_addr: self.ip_addr,
            hostname: self.hostname.clone(),
            ports: self.ports.clone(),
            task_timeout: self.task_timeout,
            wait_time: self.wait_time,
            connect_timeout: self.connect_timeout,
            read_timeout: self.read_timeout,
            send_rate: self.send_rate,
        }
    }
}