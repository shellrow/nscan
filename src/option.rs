use netscan::PortScanType;
use std::time::Duration;

pub struct PortOption {
    pub src_port: u16,
    pub dst_ip_addr: String,
    pub dst_host_name: String,
    pub dst_ports: Vec<u16>,
    pub scan_type: PortScanType,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub include_detail: bool,
    pub default_scan: bool,
    pub use_user_list: bool,
    pub list_file_path: String,
    pub interface_name: String,
    pub accept_invalid_certs: bool,
    pub save_file_path: String,
}

pub struct HostOption {
    pub dst_hosts: Vec<String>,
    pub network_addr: String,
    pub scan_host_addr: bool,
    pub use_list: bool,
    pub list_path: String,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub include_detail: bool,
    pub save_path: String,
}
