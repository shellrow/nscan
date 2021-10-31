use netscan::{PortScanner, HostScanner, AsyncPortScanner, AsyncHostScanner, ScanStatus, PortStatus, PortScanResult, HostScanResult};
use crossterm::style::Colorize;
use std::io::{stdout, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use crate::option;
use crate::db;
use crate::probe;
use crate::network;
use crate::result::{PortInfo, PortResult, HostInfo, HostResult};
use crate::printer;

pub async fn handle_port_scan(opt: option::PortOption) {
    let mut port_info_list: Vec<PortInfo> = vec![];
    printer::print_port_option(opt.clone());
    print!("Checking interface... ");
    stdout().flush().unwrap();
    let src_ip: IpAddr = if opt.src_ip.is_empty() {
        let default_if = default_net::get_default_interface().expect("");
        IpAddr::V4(default_if.ipv4[0]) 
    }else{
        opt.src_ip.parse::<IpAddr>().expect("")
    };
    println!("{}", "Done".green());
    let result: PortScanResult;
    if opt.async_scan {
        let mut port_scanner = match AsyncPortScanner::new(src_ip){
            Ok(scanner) => (scanner),
            Err(e) => panic!("Error creating scanner: {}", e),
        };
        port_scanner.set_dst_ip(opt.dst_ip_addr.parse::<IpAddr>().unwrap());
        for port in opt.dst_ports {
            port_scanner.add_dst_port(port);
        }
        port_scanner.set_scan_type(opt.scan_type);
        port_scanner.set_timeout(opt.timeout);
        port_scanner.set_wait_time(opt.wait_time);
        print!("Scanning... ");
        stdout().flush().unwrap();
        port_scanner.run_scan().await;
        result = port_scanner.get_scan_result();
    }else{
        let mut port_scanner = match PortScanner::new(src_ip){
            Ok(scanner) => (scanner),
            Err(e) => panic!("Error creating scanner: {}", e),
        };
        port_scanner.set_dst_ip(opt.dst_ip_addr.parse::<IpAddr>().unwrap());
        for port in opt.dst_ports {
            port_scanner.add_dst_port(port);
        }
        port_scanner.set_scan_type(opt.scan_type);
        port_scanner.set_timeout(opt.timeout);
        port_scanner.set_wait_time(opt.wait_time);
        print!("Scanning... ");
        stdout().flush().unwrap();
        port_scanner.run_scan();
        result = port_scanner.get_scan_result();
    }
    match result.scan_status {
        ScanStatus::Done => println!("{}", "Done".green()),
        ScanStatus::Timeout => println!("{}", "Timed out".yellow()),
        _ => println!("{}", "Error".red()),
    }
    if result.ports.len() == 0 {
        println!("Open port not found");
        std::process::exit(0);
    }
    let mut service_map: HashMap<u16, String> = HashMap::new();
    let probe_start_time = Instant::now();
    let mut open_port_list: Vec<u16> = vec![];
    for port_info in result.ports.clone() {
        match port_info.status {
            PortStatus::Open => open_port_list.push(port_info.port),
            _ => {},
        }
    }
    if opt.include_detail {
        print!("Detecting service... ");
        stdout().flush().unwrap();
        service_map = probe::service::detect_service_version(opt.dst_ip_addr.parse::<Ipv4Addr>().unwrap(), open_port_list, opt.dst_host_name, opt.accept_invalid_certs);
        println!("{}", "Done".green());
    }
    let probe_time: Duration = if opt.include_detail {Instant::now().duration_since(probe_start_time)} else {Duration::from_nanos(0)};
    let tcp_map = db::get_tcp_map();
    for port_info in result.ports { 
        let svc: String = service_map.get(&port_info.port).unwrap_or(&String::from("None")).to_string();
        let svc_vec: Vec<&str>  = svc.split("\t").collect();
        let port_info: PortInfo = PortInfo {
            port_number: port_info.port,
            port_status: {
                match port_info.status {
                    PortStatus::Open => String::from("Open"),
                    PortStatus::Closed => String::from("Closed"),
                    PortStatus::Filtered => String::from("Filtered"),
                }
            },
            service_name: tcp_map.get(&port_info.port.to_string()).unwrap_or(&String::from("None")).to_string(),
            service_version: svc_vec[0].to_string(),
            remark: {if svc_vec.len() > 1 {svc_vec[1].to_string()} else {String::from("None")} },
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
        if printer::save_port_result(port_result,opt.save_file_path.clone()) {
            println!("Result saved to file: {}", opt.save_file_path);
        }else {
            println!("Failed to save file");
        }
    }
    // Note
    if !opt.include_detail {
        println!("To perform service detection, specify the -d flag");
    }
}

pub async fn handle_host_scan(opt: option::HostOption) {
    let mut host_info_list: Vec<HostInfo> = vec![];
    printer::print_host_option(opt.clone());
    print!("Checking interface... ");
    stdout().flush().unwrap();
    let src_ip: IpAddr = if opt.src_ip.is_empty() {
        let default_if = default_net::get_default_interface().expect("");
        IpAddr::V4(default_if.ipv4[0]) 
    }else{
        opt.src_ip.parse::<IpAddr>().expect("")
    };
    println!("{}", "Done".green());
    let result: HostScanResult;
    if opt.async_scan {
        let mut host_scanner = match AsyncHostScanner::new(src_ip){
            Ok(scanner) => (scanner),
            Err(e) => panic!("Error creating scanner: {}", e),
        };
        for host in opt.dst_hosts {
            host_scanner.add_dst_ip(host.parse::<IpAddr>().unwrap());
        }
        host_scanner.set_timeout(opt.timeout);
        host_scanner.set_wait_time(opt.wait_time);
        print!("Scanning... ");
        stdout().flush().unwrap();
        host_scanner.run_scan().await;
        result = host_scanner.get_scan_result();
    }else{
        let mut host_scanner = match HostScanner::new(src_ip){
            Ok(scanner) => (scanner),
            Err(e) => panic!("Error creating scanner: {}", e),
        };
        for host in opt.dst_hosts {
            host_scanner.add_dst_ip(host.parse::<IpAddr>().unwrap());
        }
        host_scanner.set_timeout(opt.timeout);
        host_scanner.set_wait_time(opt.wait_time);
        print!("Scanning... ");
        stdout().flush().unwrap();
        host_scanner.run_scan();
        result = host_scanner.get_scan_result();
    }
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
    let mut dns_map: HashMap<String, String> = HashMap::new();
    print!("Probing vendor information... ");
    stdout().flush().unwrap();
    let oui_map = db::get_oui_map();
    match default_net::get_default_interface_index() {
        Some(default_index) => {
            let interfaces = pnet::datalink::interfaces();
            let iface = interfaces.into_iter().filter(|interface: &pnet::datalink::NetworkInterface| interface.index == default_index).next().expect("Failed to get Interface");
            for host in result.up_hosts.clone() {
                if !network::is_global_addr(host) {
                    let mac_addr = network::get_mac_through_arp(&iface, host.to_string().parse::<Ipv4Addr>().unwrap()).to_string();
                    if mac_addr.len() > 16 {
                        let prefix8 = mac_addr[0..8].to_uppercase();
                        vendor_map.insert(host.to_string(), (mac_addr, oui_map.get(&prefix8).unwrap_or(&String::from("None")).to_string()));
                    }else{
                        vendor_map.insert(host.to_string(), (mac_addr, String::from("None")));
                    }
                }
                let host_name: String = dns_lookup::lookup_addr(&host).unwrap_or(String::from("None"));
                dns_map.insert(host.to_string(), host_name);
            }
            println!("{}", "Done".green());
        },
        None => {
            println!("{}", "Failed".red());
        },
    }
    let mut os_map: HashMap<String, (String, String)> = HashMap::new();
    if opt.include_detail {
        for host in result.up_hosts.clone() {
            // ToDo
            os_map.insert(host.to_string(), (String::new(),String::new()));
        }
    }
    let probe_start_time = Instant::now();
    for host in result.up_hosts {
        let default_tuple: (String, String) = (String::from("None"), String::from("None"));
        let vendor_tuple: &(String, String) = vendor_map.get(&host.to_string()).unwrap_or(&default_tuple);
        let os_tuple: &(String, String)  = os_map.get(&host.to_string()).unwrap_or(&default_tuple);
        let host_info: HostInfo = HostInfo {
            ip_addr: host.to_string(),
            mac_addr: vendor_tuple.0.clone(),
            vendor_info: vendor_tuple.1.clone(),
            host_name: dns_map.get(&host.to_string()).unwrap_or(&String::from("None")).to_string(),
            os_name: os_tuple.0.clone(),
            os_version: os_tuple.1.clone(),
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
        if printer::save_host_result(host_result,opt.save_file_path.clone()) {
            println!("Result saved to file: {}", opt.save_file_path);
        }else {
            println!("Failed to save file");
        }
    }
}
