use std::time::Duration;

#[derive(Clone, Debug)]
pub struct PortInfo {
    pub port_number: u16,
    pub port_status: String,
    pub service_name: String,
    pub service_version: String,
    pub remark: String,
}

#[derive(Clone, Debug)]
pub struct HostInfo {
    pub ip_addr: String,
    pub mac_addr: String,
    pub vendor_info: String,
    pub host_name: String,
    pub os_name: String,
    pub os_version: String,
}

#[derive(Clone, Debug)]
pub struct PortResult {
    pub ports: Vec<PortInfo>,
    pub port_scan_time: Duration,
    pub probe_time: Duration,
    pub total_scan_time: Duration,
}

#[derive(Clone, Debug)]
pub struct HostResult {
    pub hosts: Vec<HostInfo>,
    pub host_scan_time: Duration,
    pub probe_time: Duration,
    pub total_scan_time: Duration,
}

/* impl PortInfo {
    pub fn new() -> PortInfo {
        PortInfo {
            port_number: 0,
            port_status: String::new(),
            service_name: String::new(),
            service_version: String::new(),
            remark: String::new(),
        }
    }
} */

/* impl HostInfo {
    pub fn new() -> HostInfo {
        HostInfo {
            ip_addr: String::new(),
            mac_addr: String::new(),
            vendor_info: String::new(),
            host_name: String::new(),
            os_name: String::new(),
            os_version: String::new(),
        }
    }
} */

/* impl PortResult {
    pub fn new() -> PortResult {
        PortResult {
            ports: vec![],
            port_scan_time: Duration::from_millis(0),
            probe_time: Duration::from_millis(0),
            total_scan_time: Duration::from_millis(0),
        }
    }
} */

/* impl HostResult {
    pub fn new() -> HostResult {
        HostResult {
            hosts: vec![],
            host_scan_time: Duration::from_millis(0),
            probe_time: Duration::from_millis(0),
            total_scan_time: Duration::from_millis(0),
        }
    }
} */
