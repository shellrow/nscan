use std::time::Duration;

pub struct PortInfo {
    pub port_number: u16,
    pub port_status: String,
    pub service_name: String,
    pub service_version: String,
    pub remark: String,
}

pub struct HostInfo {
    pub ip_addr: u16,
    pub mac_addr: String,
    pub host_name: String,
    pub os_name: String,
    pub os_version: String,
}

pub struct PortResult {
    pub ports: Vec<PortInfo>,
    pub scan_time: Duration,
}

pub struct HostResult {
    pub hosts: Vec<HostInfo>,
    pub scan_time: Duration,
}
