use serde::{Deserialize, Serialize};
use chrono::{Local};
use crate::{result::{HostScanResult, PortScanResult}, option};
use crate::db;

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
            issued_at: Local::now().to_rfc3339(),
        }
    }
    pub fn from_result(probe_id: String, result: PortScanResult) -> JsonPortScanResult {
        let mut json_result: JsonPortScanResult = JsonPortScanResult::new();
        json_result.probe_id = probe_id;
        json_result.ip_addr = result.host.ip_addr;
        json_result.hostname = result.host.host_name;
        json_result.protocol = option::Protocol::TCP.name();
        json_result.ports = result
            .ports
            .iter()
            .map(|port| {
                let mut json_port = JsonPortResult::new();
                json_port.port = port.port_number;
                json_port.port_status = port.port_status.clone();
                json_port.service = port.service_name.clone();
                json_port.service_version = port.service_version.clone();
                json_port
            })
            .collect();
        json_result.os = JsonOsInfo::from_cpe(result.host.cpe);
        json_result.issued_at = Local::now().to_rfc3339();
        json_result
    }
}

// HostScan JSON model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonHostResult {
    pub ip_addr: String,
    pub hostname: String,
    pub os_info: String,
    pub mac_addr: String,
    pub vendor: String,
}

impl JsonHostResult {
    pub fn new() -> JsonHostResult {
        JsonHostResult {
            ip_addr: String::new(),
            hostname: String::new(),
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
            issued_at: Local::now().to_rfc3339(),
        }
    }
    pub fn from_result(probe_id: String, result: HostScanResult) -> JsonHostScanResult {
        let mut json_result: JsonHostScanResult = JsonHostScanResult::new();
        json_result.probe_id = probe_id;
        json_result.protocol = result.protocol.name();
        json_result.port = result.port_number;
        json_result.hosts = result
            .hosts
            .iter()
            .map(|host| {
                let mut json_host = JsonHostResult::new();
                json_host.ip_addr = host.ip_addr.clone();
                json_host.hostname = host.host_name.clone();
                json_host.os_info = host.os_name.clone();
                json_host.mac_addr = host.mac_addr.clone();
                json_host.vendor = host.vendor_info.clone();
                json_host
            })
            .collect();
        json_result.issued_at = Local::now().to_rfc3339();
        json_result
    }
}
