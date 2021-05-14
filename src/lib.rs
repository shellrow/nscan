#[macro_use]
extern crate log;

pub mod interface;
pub mod arp;
mod ethernet;
mod ipv4;
mod icmp;
mod tcp;
mod udp;
mod packet;
mod status;
mod port;
mod host;

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use std::sync::mpsc::Sender;
use default_net;
use pnet::datalink::MacAddr;

pub use port::PortScanType;
pub use status::ScanStatus;

/// Result of HostScanner::new
pub type NewHostScannerResult = Result<HostScanner, String>;

/// Result of PortScanner::new
pub type NewPortScannerResult = Result<PortScanner, String>;

/// Structure for host scan  
/// 
/// Should be constructed using HostScanner::new 
#[derive(Clone)]
pub struct HostScanner {
    /// Source IP Address  
    src_ipaddr: IpAddr,
    /// List of target host  
    target_hosts: Vec<IpAddr>,
    /// Timeout setting of host scan  
    timeout: Duration,
    /// Timeout setting of host scan  
    wait_time: Duration,
    /// Result of host scan  
    scan_result: HostScanResult,
}

/// Structure for port scan  
/// 
/// Should be constructed using PortScanner::new 
#[derive(Clone)]
pub struct PortScanner {
    /// Index of network interface  
    if_index: u32,
    /// Name of network interface  
    if_name: String,
    /// Source MAC Address
    sender_mac: MacAddr,
    /// Destination MAC Address
    target_mac: MacAddr,
    /// Source IP Address  
    src_ipaddr: Ipv4Addr,
    /// Destination IP Address  
    dst_ipaddr: Ipv4Addr,
    /// Source port
    src_port: u16,
    /// Destination port  
    dst_ports: Vec<u16>,
    /// Type of port scan. Default is PortScanType::SynScan  
    scan_type: PortScanType,
    /// Timeout setting of port scan   
    timeout: Duration,
    /// Wait time after send task is finished
    wait_time: Duration,
    /// Packet send rate
    send_rate: Duration,
    /// Result of port scan  
    scan_result: PortScanResult,
}

/// Result of HostScanner::run_scan  
#[derive(Clone)]
pub struct HostScanResult {
    /// List of up host  
    pub up_hosts: Vec<String>,
    /// Time from start to end of scan  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ScanStatus,
}

/// Result of PortScanner::run_scan  
#[derive(Clone)]
pub struct PortScanResult {
    /// List of open port  
    pub open_ports: Vec<u16>,
    /// Time from start to end of scan  
    pub scan_time: Duration,
    /// Scan job status
    pub scan_status: ScanStatus,
}

impl HostScanner{
    /// Construct new HostScanner  
    pub fn new() -> NewHostScannerResult {
        let ini_scan_result = HostScanResult{
            up_hosts: vec![],
            scan_time: Duration::from_millis(1),
            scan_status: ScanStatus::Ready,
        };
        let host_scanner = HostScanner{
            src_ipaddr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            target_hosts: vec![],
            timeout: Duration::from_millis(10000),
            wait_time: Duration::from_millis(300),
            scan_result: ini_scan_result,
        };
        Ok(host_scanner)
    }
    /// Add target host to list
    pub fn add_ipaddr(&mut self, ipaddr: &str) {
        let addr = ipaddr.parse::<IpAddr>();
        match addr {
            Ok(valid_addr) => {
                self.target_hosts.push(valid_addr);
            }
            Err(e) => {
                error!("Error adding ip address {}. Error: {}", ipaddr, e);
            }
        };
    }
    /// Set scan timeout  
    pub fn set_timeout(&mut self, timeout: Duration){
        self.timeout = timeout;
    }
    /// Set scan wait time  
    pub fn set_wait_time(&mut self, wait_time: Duration){
        self.wait_time = wait_time;
    }
    /// Set source IP Address 
    pub fn set_src_ipaddr(&mut self, src_ipaddr:IpAddr){
        self.src_ipaddr = src_ipaddr;
    }
    /// Get source IP Address
    pub fn get_src_ipaddr(&mut self) -> IpAddr {
        return self.src_ipaddr.clone();
    }
    /// Get target hosts
    pub fn get_target_hosts(&mut self) -> Vec<IpAddr> {
        return self.target_hosts.clone();
    }
    /// Get timeout 
    pub fn get_timeout(&mut self) -> Duration {
        return self.timeout.clone();
    }
    /// Get wait time
    pub fn get_wait_time(&mut self) -> Duration {
        return self.wait_time.clone();
    }
    /// Run scan with current settings 
    /// 
    /// Results are stored in HostScanner::scan_result
    pub fn run_scan(&mut self, tx: Sender<usize>){
        let temp_scanner = self.clone();
        let start_time = Instant::now();
        let (uphosts, status) = host::scan_hosts(&temp_scanner, tx);
        self.scan_result.up_hosts = uphosts;
        self.scan_result.scan_status = status;
        self.scan_result.scan_time = Instant::now().duration_since(start_time);
    }
    /// Return scan result
    pub fn get_result(&mut self) -> HostScanResult{
        return self.scan_result.clone();
    }
}

impl PortScanner{
    /// Construct new PortScanner (with network interface index or name)
    /// 
    /// Specify None for default. `PortScanner::new(None)`
    pub fn new(_if_name: Option<&str>) -> NewPortScannerResult{
        let ini_scan_result = PortScanResult{
            open_ports: vec![],
            scan_time: Duration::from_millis(1),
            scan_status: ScanStatus::Ready,
        };
        let mut port_scanner = PortScanner{
            if_index: 0,
            if_name: String::new(),
            sender_mac: MacAddr::zero(),
            target_mac: MacAddr::zero(),
            src_ipaddr: Ipv4Addr::new(127, 0, 0, 1),
            dst_ipaddr: Ipv4Addr::new(127, 0, 0, 1), 
            src_port: 65432,
            dst_ports: vec![],
            scan_type: PortScanType::SynScan,
            timeout: Duration::from_millis(30000),
            wait_time: Duration::from_millis(100),
            send_rate: Duration::from_millis(1),
            scan_result: ini_scan_result,
        };
        if let Some(if_name) = _if_name {
            let if_index = interface::get_interface_index_by_name(if_name.to_string());
            if let Some(if_index) = if_index{
                port_scanner.if_index = if_index;
                port_scanner.if_name = if_name.to_string();
            }else{
                return Err("Failed to get interface info by name.".to_string());
            }
        }else{
            let def_if_index = default_net::get_default_interface_index();
            if let Some(def_if_index) = def_if_index {
                port_scanner.if_index = def_if_index;
            }else{
                return Err("Failed to get default interface info.".to_string());
            }
        }
        Ok(port_scanner)
    }
    /// Set IP address of target host
    pub fn set_target_ipaddr(&mut self, ipaddr: &str){
        let ipv4addr = ipaddr.parse::<Ipv4Addr>();
        match ipv4addr {
            Ok(valid_ipaddr) => {
                self.dst_ipaddr = valid_ipaddr;
            }
            Err(e) => {
                error!("Error setting IP Address {}. Error: {}", ipaddr, e);
            }
        }
    }
    /// Set range of target ports (by start and end)
    pub fn set_range(&mut self, start: u16, end: u16){
        for i in start..end + 1{
            self.add_target_port(i);
        }
    }
    /// Add target port 
    pub fn add_target_port(&mut self, port_num: u16){
        self.dst_ports.push(port_num);
    }
    /// Set PortScanType. Default is PortScanType::SynScan
    pub fn set_scan_type(&mut self, scan_type: PortScanType){
        self.scan_type = scan_type;
    }
    /// Set scan timeout  
    pub fn set_timeout(&mut self, timeout: Duration){
        self.timeout = timeout;
    }
    /// Set scan wait-time  
    pub fn set_wait_time(&mut self, wait_time: Duration){
        self.wait_time = wait_time;
    }
    /// Set packet send rate
    pub fn set_send_rate(&mut self, send_rate: Duration){
        self.send_rate = send_rate;
    }
    /// Set source port number 
    pub fn set_src_port(&mut self, src_port: u16){
        self.src_port = src_port;
    }
    /// Get network interface index
    pub fn get_if_index(&mut self) -> u32 {
        return self.if_index.clone();
    }
    /// Get network interface name
    pub fn get_if_name(&mut self) -> String {
        return self.if_name.clone();
    }
    /// Get target ip address
    pub fn get_target_ipaddr(&mut self) -> Ipv4Addr {
        return self.dst_ipaddr.clone();
    }
    /// Get target ports
    pub fn get_target_ports(&mut self) -> Vec<u16> {
        return self.dst_ports.clone();
    }
    /// Get PortScanType
    pub fn get_scan_type(&mut self) -> PortScanType {
        return self.scan_type.clone();
    }
    /// Get source port number
    pub fn get_src_port_num(&mut self) -> u16 {
        return self.src_port.clone();
    }
    /// Get timeout
    pub fn get_timeout(&mut self) -> Duration {
        return self.timeout.clone();
    }
    /// Get wait-time
    pub fn get_wait_time(&mut self) -> Duration {
        return self.wait_time.clone();
    }
    /// Get send rate
    pub fn get_send_rate(&mut self) -> Duration {
        return self.send_rate.clone();
    }
    /// Run scan with current settings 
    /// 
    /// Results are stored in PortScanner::scan_result
    pub fn run_scan(&mut self, tx: Sender<usize>){
        let dst_mac = match self.scan_type {
            PortScanType::ConnectScan => {
                pnet::datalink::MacAddr::zero()
            },
            _ => {
                let default_gateway = default_net::get_default_gateway();
                default_gateway.mac.expect("Failed to get gateway mac").parse::<pnet::datalink::MacAddr>().unwrap()
            },
        };
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces.into_iter().filter(|interface: &pnet::datalink::NetworkInterface| interface.index == self.if_index).next().expect("Failed to get Interface");    
        let mut iface_ip: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
        for ip in &interface.ips{
            match ip.ip() {
                IpAddr::V4(ipv4) => {
                    iface_ip = ipv4;
                    break;
                },
                /*
                IpAddr::V6(ipv6) => {
                    
                },
                */
                _ => {
                    continue;
                },
            }
        }
        self.sender_mac = interface.mac.unwrap();
        self.target_mac = dst_mac;
        self.src_ipaddr = iface_ip;
        let temp_scanner = self.clone();
        let start_time = Instant::now();
        let (open_ports, status) = port::scan_ports(&interface, &temp_scanner, tx);
        self.scan_result.open_ports = open_ports;
        self.scan_result.scan_status = status;
        self.scan_result.scan_time = Instant::now().duration_since(start_time);
    }
    /// Return scan result
    pub fn get_result(&mut self) -> PortScanResult{
        return self.scan_result.clone();
    }
}
