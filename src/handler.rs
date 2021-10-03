use netscan::{PortScanner, HostScanner, ScanStatus};
use crossterm::style::Colorize;
use std::io::{stdout, Write};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use crate::option;
use crate::db;
use crate::probe;
use crate::network;
use crate::result::{PortInfo, PortResult, HostInfo, HostResult};
use crate::printer;

pub fn handle_port_scan(opt: option::PortOption) {
    let mut port_info_list: Vec<PortInfo> = vec![];
    let if_name: Option<&str> = if opt.interface_name.is_empty() {
        None
    }else{
        Some(&opt.interface_name)
    };
    let mut port_scanner = match PortScanner::new(if_name){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    port_scanner.set_target_ipaddr(opt.dst_ip_addr.as_str());
    for port in opt.dst_ports {
        port_scanner.add_target_port(port);
    }
    port_scanner.set_scan_type(opt.scan_type);
    port_scanner.set_timeout(opt.timeout);
    port_scanner.set_wait_time(opt.wait_time);
    print!("Scanning... ");
    stdout().flush().unwrap();
    port_scanner.run_scan();
    let result = port_scanner.get_result();
    match result.scan_status {
        ScanStatus::Done => println!("{}", "Done".green()),
        ScanStatus::Timeout => println!("{}", "Timed out".yellow()),
        _ => println!("{}", "Error".red()),
    }
    if result.open_ports.len() == 0 {
        println!("Open port not found");
        std::process::exit(0);
    }
    let mut service_map: HashMap<u16, String> = HashMap::new();
    let probe_start_time = Instant::now();
    if opt.include_detail {
        print!("Detecting service... ");
        stdout().flush().unwrap();
        service_map = probe::service::detect_service_version(opt.dst_ip_addr.parse::<Ipv4Addr>().unwrap(), result.open_ports.clone(), opt.accept_invalid_certs);
        println!("{}", "Done".green());
    }
    let probe_time: Duration = Instant::now().duration_since(probe_start_time);
    let tcp_map = db::get_tcp_map();
    for port in result.open_ports {
        let port_info: PortInfo = PortInfo {
            port_number: port.clone(),
            port_status: String::from("Open"),
            service_name: tcp_map.get(&port.to_string()).unwrap_or(&String::from("None")).to_string(),
            service_version: service_map.get(&port).unwrap_or(&String::from("None")).to_string(),
            remark: String::new(),
        };
        port_info_list.push(port_info);
    }
    let port_result: PortResult = PortResult {
        ports: port_info_list,
        port_scan_time: result.scan_time,
        probe_time: probe_time,
        total_scan_time: result.scan_time + probe_time,
    };
    printer::print_port_result(port_result.clone());
    if !opt.save_file_path.is_empty() {
        printer::save_port_result(port_result);
    }
}

pub fn handle_host_scan(opt: option::HostOption) {
    let mut host_info_list: Vec<HostInfo> = vec![];
    let mut host_scanner = match HostScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    for host in opt.dst_hosts {
        host_scanner.add_ipaddr(&host);
    }
    host_scanner.set_timeout(opt.timeout);
    host_scanner.set_wait_time(opt.wait_time);
    print!("Scanning... ");
    stdout().flush().unwrap();
    host_scanner.run_scan();
    let result = host_scanner.get_result();
    match result.scan_status {
        ScanStatus::Done => {println!("{}", "Done".green())},
        ScanStatus::Timeout => {println!("{}", "Timed out".yellow())},
        _ => {println!("{}", "Error".red())},
    }
    if result.up_hosts.len() == 0 {
        println!("Up-host not found");
        std::process::exit(0);
    }
    let mut vendor_map: HashMap<String, (String, String)> = HashMap::new();
    if opt.include_detail {
        print!("Getting vendor information... ");
        stdout().flush().unwrap();
        let oui_map = db::get_oui_map();
        let default_index = default_net::get_default_interface_index().unwrap();
        let interfaces = pnet::datalink::interfaces();
        let iface = interfaces.into_iter().filter(|interface: &pnet::datalink::NetworkInterface| interface.index == default_index).next().expect("Failed to get Interface");
        for host in result.up_hosts.clone() {
            let mac_addr = network::get_mac_through_arp(&iface, host.parse::<Ipv4Addr>().unwrap()).to_string();
            if mac_addr.len() > 16 {
                let prefix8 = mac_addr[0..8].to_uppercase();
                vendor_map.insert(host, (mac_addr, oui_map.get(&prefix8).unwrap_or(&String::from("None")).to_string()));
            }else{
                vendor_map.insert(host, (mac_addr, String::from("None")));
            }
        }
        println!("{}", "Done".green());
    }
    let probe_start_time = Instant::now();
    for host in result.up_hosts {
        let default_tuple: (String, String) = (String::new(), String::new());
        let vendor_tuple: &(String, String) = vendor_map.get(&host).unwrap_or(&default_tuple);
        let host_info: HostInfo = HostInfo {
            ip_addr: host,
            mac_addr: vendor_tuple.0.clone(),
            vendor_info: vendor_tuple.1.clone(),
            host_name: String::new(),
            os_name: String::new(),
            os_version: String::new(),
        };
        host_info_list.push(host_info);
    }
    let probe_time: Duration = Instant::now().duration_since(probe_start_time);
    let host_result: HostResult = HostResult {
        hosts: host_info_list,
        host_scan_time: result.scan_time,
        probe_time: probe_time,
        total_scan_time: result.scan_time + probe_time,
    };
    printer::print_host_result(host_result.clone());
    if !opt.save_file_path.is_empty() {
        printer::save_host_result(host_result);
    }
}
