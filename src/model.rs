use std::net::{IpAddr, Ipv4Addr};
use serde::{Deserialize, Serialize};

/// Status of the scanned port
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub enum PortStatus {
    Open,
    Closed,
    Filtered,
    Unknown,
}

impl PortStatus {
    pub fn name(&self) -> String {
        match *self {
            PortStatus::Open => String::from("Open"),
            PortStatus::Closed => String::from("Closed"),
            PortStatus::Filtered => String::from("Filtered"),
            PortStatus::Unknown => String::from("Unknown"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Port {
    pub port_number: u16,
    pub port_status: PortStatus,
    pub service_name: String,
}

/// The host
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub ip_addr: IpAddr,
    pub host_name: String,
    pub ports: Vec<Port>,
}

impl Host {
    pub fn new() -> Host {
        Host {
            ip_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            host_name: String::new(),
            ports: Vec::new(),
        }
    }
    pub fn add_open_port(&mut self, port_number: u16, service_name: String) {
        let port: Port = Port {
            port_number: port_number,
            port_status: PortStatus::Open,
            service_name: service_name,
        };
        self.ports.push(port);
    }
    pub fn get_open_ports(&self) -> Vec<u16> {
        let mut open_ports: Vec<u16> = Vec::new();
        for port in &self.ports {
            if port.port_status == PortStatus::Open {
                open_ports.push(port.port_number);
            }
        }
        open_ports
    }
}

/// Port Information
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port_number: u16,
    pub port_status: PortStatus,
    pub service_name: String,
    pub service_version: String,
    pub cpe: String,
    pub remark: String,
}

impl ServiceInfo {
    pub fn new() -> ServiceInfo {
        ServiceInfo {
            port_number: 0,
            port_status: PortStatus::Unknown,
            service_name: String::new(),
            service_version: String::new(),
            cpe: String::new(),
            remark: String::new(),
        }
    }
}

/// Node type
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum NodeType {
    DefaultGateway,
    Relay,
    Destination,
}

/// Host Information
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeInfo {
    pub ip_addr: IpAddr,
    pub host_name: String,
    pub ttl: u8,
    pub mac_addr: String,
    pub vendor_info: String,
    pub os_name: String,
    pub cpe: String,
    pub services: Vec<ServiceInfo>,
    pub node_type: NodeType,
}

impl NodeInfo {
    pub fn new() -> NodeInfo {
        NodeInfo {
            ip_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            host_name: String::new(),
            ttl: 0,
            mac_addr: String::new(),
            vendor_info: String::new(),
            os_name: String::new(),
            cpe: String::new(),
            services: Vec::new(),
            node_type: NodeType::Destination,
        }
    }
    pub fn get_open_ports(&self) -> Vec<u16> {
        let mut open_ports: Vec<u16> = Vec::new();
        for service in &self.services {
            if service.port_status == PortStatus::Open {
                open_ports.push(service.port_number);
            }
        }
        open_ports
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Oui {
    pub mac_prefix: String,
    pub vendor_name: String,
    pub vendor_name_detail: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpService {
    pub port: u16,
    pub service_name: String,
    pub service_description: String,
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpService {
    pub port: u16,
    pub service_name: String,
    pub service_description: String,
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsFingerprint {
    pub cpe: String,
    pub os_name: String,
    pub os_vendor: String,
    pub os_family: String,
    pub os_generation: String,
    pub device_type: String,
    pub tcp_window_sizes: Vec<u16>,
    pub tcp_option_patterns: Vec<String>,
}

impl OsFingerprint {
    pub fn new() -> OsFingerprint {
        OsFingerprint {
            cpe: String::new(),
            os_name: String::new(),
            os_vendor: String::new(),
            os_family: String::new(),
            os_generation: String::new(),
            device_type: String::new(),
            tcp_window_sizes: vec![],
            tcp_option_patterns: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsFamilyFingerprint {
    pub os_family: String,
    pub tcp_window_size: u16,
    pub tcp_option_pattern: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsTtl {
    pub os_family: String,
    pub os_description: String,
    pub initial_ttl: u8,
}