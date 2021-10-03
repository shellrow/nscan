use netscan::PortScanType;
use std::time::Duration;
use std::fs::read_to_string;
use std::net::{IpAddr, Ipv4Addr};
use ipnet::{Ipv4Net};
use crate::define;

#[derive(Clone)]
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
    pub interface_name: String,
    pub accept_invalid_certs: bool,
    pub save_file_path: String,
}

#[derive(Clone)]
pub struct HostOption {
    pub dst_hosts: Vec<String>,
    pub timeout: Duration,
    pub wait_time: Duration,
    pub include_detail: bool,
    pub save_file_path: String,
}

impl PortOption {
    pub fn new() -> PortOption {
        PortOption {
            src_port: 65432,
            dst_ip_addr: String::new(),
            dst_host_name: String::new(),
            dst_ports: vec![],
            scan_type: PortScanType::SynScan,
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(100),
            include_detail: false,
            default_scan: false,
            interface_name: String::new(),
            accept_invalid_certs: false,
            save_file_path: String::new(),
        }
    }
    pub fn set_src_port(&mut self, v: u16) {
        self.src_port = v;
    }
    pub fn set_dst_ip_addr(&mut self, v: String) {
        self.dst_ip_addr = v;
    }
    pub fn set_dst_host_name(&mut self, v: String) {
        self.dst_host_name = v;
    }
    pub fn set_dst_ports(&mut self, v: Vec<u16>) {
        self.dst_ports = v;
    }
    pub fn set_dst_ports_from_range(&mut self, from_v: u16, to_v: u16) {
        for port in from_v..to_v {
            self.dst_ports.push(port);
        }
    }
    pub fn set_dst_ports_from_csv(&mut self, v: String) {
        let values: Vec<&str> = v.split(",").collect();
        for p in values {
            match p.parse::<u16>(){
                Ok(port) =>{
                    self.dst_ports.push(port);
                },
                Err(_) =>{},
            }
        }
    }
    pub fn set_dst_ports_from_list(&mut self, v: String) {
        let data = read_to_string(v);
        let text = match data {
            Ok(content) => content,
            Err(_) => String::new(),
        };
        let port_list: Vec<&str> = text.trim().split("\n").collect();
        for port in port_list {
            match port.parse::<u16>(){
                Ok(p) =>{
                    self.dst_ports.push(p);
                },
                Err(_) =>{},
            }
        }
    }
    pub fn set_scan_type(&mut self, v: String) {
        let scan_type = match v.as_str() {
            define::PORTSCAN_TYPE_SYN_SCAN => PortScanType::SynScan,
            define::PORTSCAN_TYPE_CONNECT_SCAN => PortScanType::ConnectScan,
            _ => PortScanType::SynScan,
        };
        self.scan_type = scan_type;
    }
    pub fn set_timeout(&mut self, v: u64) {
        self.timeout = Duration::from_millis(v);
    }
    pub fn set_wait_time(&mut self, v: u64) {
        self.wait_time = Duration::from_millis(v);
    }
    pub fn set_include_detail(&mut self, v: bool) {
        self.include_detail = v;
    }
    pub fn set_default_scan(&mut self, v: bool) {
        self.default_scan = v;
    }
    pub fn set_interface_name(&mut self, v: String) {
        self.interface_name = v;
    }
    pub fn set_accept_invalid_certs(&mut self, v: bool) {
        self.accept_invalid_certs = v;
    }
    pub fn set_save_file_path(&mut self, v: String) {
        self.save_file_path = v;
    }
}

impl HostOption {
    pub fn new() -> HostOption {
        HostOption {
            dst_hosts: vec![],
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(200),
            include_detail: false,
            save_file_path: String::new(),
        }
    }
    /* pub fn set_dst_hosts(&mut self, v: Vec<String>) {
        self.dst_hosts = v;
    } */
    pub fn set_dst_hosts_from_list(&mut self, v: String) {
        let data = read_to_string(v);
        let text = match data {
            Ok(content) => content,
            Err(_) => String::new(),
        };
        let host_list: Vec<&str> = text.trim().split("\n").collect();
        for host in host_list {
            match host.parse::<IpAddr>(){
                Ok(addr) =>{
                    self.dst_hosts.push(addr.to_string());
                },
                Err(_) =>{},
            }
        }
        //TODO: add dns_lookup
    }
    pub fn set_dst_hosts_from_na(&mut self, v: String) {
        match v.parse::<IpAddr>(){
            Ok(addr) => {
                match addr {
                    IpAddr::V4(ipv4_addr) => {
                        let net: Ipv4Net = Ipv4Net::new(ipv4_addr, 24).unwrap();
                        let nw_addr = Ipv4Net::new(net.network(), 24).unwrap();
                        let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();
                        for host in hosts {
                            self.dst_hosts.push(host.to_string());
                        }
                    },
                    IpAddr::V6(_) => {},
                }
            },
            Err(_) =>{},
        }
        //TODO: add v6 support
    }
    pub fn set_timeout(&mut self, v: u64) {
        self.timeout = Duration::from_millis(v);
    }
    pub fn set_wait_time(&mut self, v: u64) {
        self.wait_time = Duration::from_millis(v);
    }
    pub fn set_include_detail(&mut self, v: bool) {
        self.include_detail = v;
    }
    pub fn set_save_file_path(&mut self, v: String) {
        self.save_file_path = v;
    }
}
