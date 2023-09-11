use serde::{Deserialize, Serialize};
use crate::result::{HostScanResult, PortScanResult};
use crate::option;
use crate::db;
use crate::sys;

// Shared model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonOsInfo {
    pub cpe: String,
    pub os_name: String,
    pub os_vendor: String,
    pub os_family: String,
    pub os_generation: String,
    pub device_type: String,
}

impl JsonOsInfo {
    pub fn new() -> JsonOsInfo {
        JsonOsInfo {
            cpe: String::new(),
            os_name: String::new(),
            os_vendor: String::new(),
            os_family: String::new(),
            os_generation: String::new(),
            device_type: String::new(),
        }
    }
    pub fn from_cpe(cpe: String) -> JsonOsInfo {
        let os_fingerprints = db::get_os_fingerprints();
        for f in os_fingerprints {
            if f.cpe == cpe {
                return JsonOsInfo {
                    cpe: f.cpe,
                    os_name: f.os_name,
                    os_vendor: f.os_vendor,
                    os_family: f.os_family,
                    os_generation: f.os_generation,
                    device_type: f.device_type,
                };
            }
        }
        JsonOsInfo::new()
    }
}

// PortScan JSON model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonPortResult {
    pub port: u16,
    pub port_status: String,
    pub service: String,
    pub service_version: String,
}

impl JsonPortResult {
    pub fn new() -> JsonPortResult {
        JsonPortResult {
            port: 0,
            port_status: String::new(),
            service: String::new(),
            service_version: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonPortScanResult {
    pub probe_id: String,
    pub ip_addr: String,
    pub hostname: String,
    pub protocol: String,
    pub ports: Vec<JsonPortResult>,
    pub os: JsonOsInfo,
    pub issued_at: String,
}

impl JsonPortScanResult {
    pub fn new() -> JsonPortScanResult {
        JsonPortScanResult {
            probe_id: String::new(),
            ip_addr: String::new(),
            hostname: String::new(),
            protocol: String::new(),
            ports: Vec::new(),
            os: JsonOsInfo::new(),
            issued_at: sys::get_sysdate(),
        }
    }
    pub fn from_result(probe_id: String, result: PortScanResult) -> JsonPortScanResult {
        let node = result.nodes[0].clone();
        let mut json_result: JsonPortScanResult = JsonPortScanResult::new();
        json_result.probe_id = probe_id;
        json_result.ip_addr = node.ip_addr.to_string();
        json_result.hostname = node.host_name;
        json_result.protocol = option::IpNextLevelProtocol::TCP.name();
        json_result.ports = result
            .nodes[0].services
            .iter()
            .map(|port| {
                let mut json_port = JsonPortResult::new();
                json_port.port = port.port_number;
                json_port.port_status = port.port_status.name().to_lowercase();
                json_port.service = port.service_name.clone();
                json_port.service_version = port.service_version.clone();
                json_port
            })
            .collect();
        json_result.os = JsonOsInfo::from_cpe(node.cpe);
        json_result.issued_at = sys::get_sysdate();
        json_result
    }
}

// HostScan JSON model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonHostResult {
    pub ip_addr: String,
    pub hostname: String,
    pub ttl: u16,
    pub os_info: String,
    pub mac_addr: String,
    pub vendor: String,
}

impl JsonHostResult {
    pub fn new() -> JsonHostResult {
        JsonHostResult {
            ip_addr: String::new(),
            hostname: String::new(),
            ttl: 0,
            os_info: String::new(),
            mac_addr: String::new(),
            vendor: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonHostScanResult {
    pub probe_id: String,
    pub protocol: String,
    pub port: u16,
    pub hosts: Vec<JsonHostResult>,
    pub issued_at: String,
}

impl JsonHostScanResult {
    pub fn new() -> JsonHostScanResult {
        JsonHostScanResult {
            probe_id: String::new(),
            protocol: String::new(),
            port: 0,
            hosts: Vec::new(),
            issued_at: sys::get_sysdate(),
        }
    }
    pub fn from_result(probe_id: String, result: HostScanResult) -> JsonHostScanResult {
        let mut json_result: JsonHostScanResult = JsonHostScanResult::new();
        json_result.probe_id = probe_id;
        json_result.protocol = result.protocol.name();
        json_result.port = 
            if result.nodes.len() > 0 {
                if result.nodes[0].services.len() > 0 {
                    result.nodes[0].services[0].port_number
                }else{
                    0
                }
            }else{
                0
            };
        json_result.hosts = result
            .nodes
            .iter()
            .map(|host| {
                let mut json_host = JsonHostResult::new();
                json_host.ip_addr = host.ip_addr.to_string();
                json_host.hostname = host.host_name.clone();
                json_host.ttl = host.ttl as u16;
                json_host.os_info = host.os_name.clone();
                json_host.mac_addr = host.mac_addr.clone();
                json_host.vendor = host.vendor_info.clone();
                json_host
            })
            .collect();
        json_result.issued_at = sys::get_sysdate();
        json_result
    }
}

// Ping JSON model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonPingResult {
    pub seq: u16,
    pub ttl: u16,
    pub hop: u16,
    pub rtt: u64,
    pub status: String,
}

// Traceroute JSON model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonTracerouteResult {
    pub seq: u16,
    pub ip_addr: String,
    pub hostname: String,
    pub ttl: u16,
    pub hop: u16,
    pub rtt: u64,
}
