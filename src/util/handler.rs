use std::io::{stdout, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::fs::read_to_string;
use std::collections::HashMap;
use std::time::Duration;
use ipnet::{Ipv4Net};
use netscan::{ScanStatus, PortScanType};
use netscan::{PortScanner, HostScanner};
use netscan::arp;
use default_net;
use super::{option, db, service};
use super::sys::{self, SPACE4};
use crossterm::style::Colorize;

pub fn handle_port_scan(opt: option::PortOption) {
    opt.show_options();
    println!();
    print!("Scanning ports... ");
    stdout().flush().unwrap();
    let mut if_name: Option<&str> = None;
    if !opt.if_name.is_empty(){
        if_name = Some(&opt.if_name);
    }
    let mut port_scanner = match PortScanner::new(if_name){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    port_scanner.set_target_ipaddr(&opt.ip_addr);
    if opt.use_list {
        let data = read_to_string(opt.list_path.to_string());
        let text = match data {
            Ok(content) => content,
            Err(e) => {panic!("Could not open or find file: {}", e);}
        };
        let port_list: Vec<&str> = text.trim().split("\n").collect();
        for port in port_list {
            match port.parse::<u16>(){
                Ok(p) =>{
                    port_scanner.add_target_port(p);
                },
                Err(_) =>{},
            }
        }
    }else{
        for p in opt.port_list.clone() {
            port_scanner.add_target_port(p);
        }
    }
    port_scanner.set_scan_type(opt.scan_type);
    port_scanner.set_timeout(opt.timeout);
    port_scanner.set_wait_time(opt.wait_time);
    port_scanner.run_scan();
    let result = port_scanner.get_result();
    match result.scan_status {
        ScanStatus::Done => {println!("{}", "Done".green())},
        ScanStatus::Timeout => {println!("{}", "Timed out".yellow())},
        _ => {println!("{}", "Error".red())},
    }
    let tcp_map = db::get_tcp_map();
    let detail_map: HashMap<u16, String> = match opt.include_detail {
        true => {
            print!("Detecting service version... ");
            stdout().flush().unwrap();
            service::detect_service_version(port_scanner.get_target_ipaddr(), result.open_ports.clone(), opt.accept_invalid_certs)
        },
        false => HashMap::new(),
    };
    if detail_map.len() > 0 {
        println!("{}", "Done".green());
    }
    println!();
    if result.open_ports.len() == 0 {
        println!("No open port found on target.");
        return;
    }
    sys::print_fix32("Scan Reports", sys::FillStr::Hyphen);
    println!("{} open port(s) / scanned {} port(s) ", result.open_ports.len(), opt.port_list.len());
    println!("{}PORT{}SERVICE", SPACE4, SPACE4);
    for port in result.open_ports {
        let service_version: String = match detail_map.get(&port) {
            Some(v) => v.to_string(),
            None => String::from("None"),
        };
        match tcp_map.get(&port.to_string()) {
            Some(service_name) => {
                print_service(port.to_string(), service_name.to_string(), service_version);
            },
            None => {
                print_service(port.to_string(), String::from("Unknown service"), service_version);
            },
        }
    }
    sys::print_fix32("", sys::FillStr::Hyphen);
    println!("Scan Time: {:?}", result.scan_time);
    match port_scanner.get_scan_type() {
        PortScanType::ConnectScan => {},
        _=> {
            if port_scanner.get_wait_time() > Duration::from_millis(0) {
                println!("(Including {:?} of wait time)", port_scanner.get_wait_time());
            }
        },
    }
    if !opt.save_path.is_empty() {
        let s_result = port_scanner.get_result();
        save_port_result(&&opt, s_result, &tcp_map);
    }
}

pub fn handle_host_scan(opt: option::HostOption) {
    opt.show_options();
    println!();
    print!("Scanning... ");
    stdout().flush().unwrap();
    let mut host_scanner = match HostScanner::new(){
        Ok(scanner) => (scanner),
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    if opt.scan_host_addr {
        let addr = IpAddr::from_str(&opt.ip_addr);
        match addr {
            Ok(ip_addr) => {
                match ip_addr {
                    IpAddr::V4(ipv4_addr) => {
                        let net: Ipv4Net = Ipv4Net::new(ipv4_addr, 24).unwrap();
                        let nw_addr = Ipv4Net::new(net.network(), 24).unwrap();
                        let hosts: Vec<Ipv4Addr> = nw_addr.hosts().collect();
                        for host in hosts{
                            host_scanner.add_ipaddr(&host.to_string());
                        }
                    },
                    IpAddr::V6(_ipv6_addr) => {
                        error!("Currently not supported.");
                        std::process::exit(0);
                    },
                }
            },
            Err(_) => {
                error!("Invalid IP address");
                std::process::exit(0);
            }
        }
    }else if opt.use_list {
        let data = read_to_string(opt.list_path.to_string());
        let text = match data {
            Ok(content) => content,
            Err(e) => {panic!("Could not open or find file: {}", e);}
        };
        let host_list: Vec<&str> = text.trim().split("\n").collect();
        for host in host_list {
            let addr = IpAddr::from_str(&host);
            match addr {
                Ok(_) => {
                    host_scanner.add_ipaddr(&host.to_string());        
                },
                Err(_) => {
                    
                }
            }
        }
    }
    host_scanner.set_timeout(opt.timeout);
    host_scanner.set_wait_time(opt.wait_time);
    host_scanner.run_scan();
    let result = host_scanner.get_result();
    match result.scan_status {
        ScanStatus::Done => {println!("{}", "Done".green())},
        ScanStatus::Timeout => {println!("{}", "Timed out".yellow())},
        _ => {println!("{}", "Error".red())},
    }
    println!();
    if result.up_hosts.len() == 0 {
        println!("No up-host found.");
        return;
    }
    let default_interface = default_net::get_default_interface().unwrap();
    let mut result_map: HashMap<String, String> = HashMap::new();
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces.into_iter().filter(|interface: &pnet::datalink::NetworkInterface| interface.index == default_interface.index).next().expect("Failed to get Interface");
    sys::print_fix32("Scan Reports", sys::FillStr::Hyphen);
    println!("{} host(s) up / {} IP address(es)", result.up_hosts.len(), host_scanner.get_target_hosts().len());
    println!("{}IP ADDR {}MAC ADDR", SPACE4, SPACE4.repeat(3));
    let oui_map = db::get_oui_map();
    for host in result.up_hosts {
        match host.parse::<Ipv4Addr>(){
            Ok(ipaddr) => {
                let mac_addr: String = arp::get_mac_through_arp(&interface, ipaddr).to_string();
                if mac_addr.len() < 17 {
                    print!("{}{}{}", SPACE4, ipaddr.to_string().cyan(), " ".repeat(16 - ipaddr.to_string().len()));
                    println!("{}{} Unknown", SPACE4, mac_addr);
                    result_map.insert(ipaddr.to_string(), format!("{} Unknown", mac_addr));
                }else{
                    let prefix8 = mac_addr[0..8].to_uppercase();
                    match oui_map.get(&prefix8) {
                        Some(vendor_name) => {
                            if prefix8 == "00:00:00".to_string() {
                                print_host_info(ipaddr.to_string(), mac_addr.clone(), String::from("Unknown"));
                                result_map.insert(ipaddr.to_string(), format!("{} Unknown", mac_addr));
                            }else{
                                print_host_info(ipaddr.to_string(), mac_addr.clone(), vendor_name.to_string());
                                result_map.insert(ipaddr.to_string(), format!("{} {}", mac_addr, vendor_name));
                            }
                        },
                        None => {
                            if ipaddr.to_string() == default_interface.ipv4[0].to_string() {
                                print_host_info(ipaddr.to_string(), mac_addr.clone(), String::from("Own device"));
                                result_map.insert(ipaddr.to_string(), format!("{} Own device", mac_addr));
                            }else{
                                print_host_info(ipaddr.to_string(), mac_addr.clone(), String::from("Unknown"));
                                result_map.insert(ipaddr.to_string(), format!("{} Unknown", mac_addr));
                            }
                        },
                    }
                }
            },
            Err(_) => {
                println!("{}{}", SPACE4, host.cyan());
            },
        }
    }
    sys::print_fix32("", sys::FillStr::Hyphen);
    println!("Scan Time: {:?}", result.scan_time);
    if host_scanner.get_wait_time() > Duration::from_millis(0) {
        println!("(Including {:?} of wait time)", host_scanner.get_wait_time());
    }
    if !opt.save_path.is_empty() {
        save_host_result(&opt, result_map);
    }
}

fn print_service(port: String, service_name: String, service_version: String){
    print!("{}{}", " ".repeat(8 - port.to_string().len()),port.to_string().cyan());
    println!("{}{}", SPACE4, service_name);
    if !service_version.is_empty() && service_version != "None" {
        println!("{}{}", SPACE4.repeat(3), service_version);
    }
}

fn print_host_info(ip_addr: String, mac_addr: String, vendor_name: String){
    print!("{}{}{}", SPACE4, ip_addr.to_string().cyan(), " ".repeat(16 - ip_addr.to_string().len()));
    print!("{}{} ", SPACE4, mac_addr);
    println!("{}", vendor_name);
}

fn save_port_result(opt: &option::PortOption, result: netscan::PortScanResult, tcp_map: &HashMap<String, String>) {
    let mut data = "[OPTIONS]".to_string();
    data = format!("{}\nIP_ADDR:{}",data,opt.ip_addr);
    data = format!("{}\n[RESULTS]",data);
    for port in result.open_ports {
        match tcp_map.get(&port.to_string()) {
            Some(service_name) => {
                data = format!("{}\n{} tcp {}", data, port.to_string(),service_name);
            },
            None => {
                data = format!("{}\n{} tcp Unknown", data, port);
            }, 
        };
    }
    data = format!("{}\n",data);
    sys::save_file(opt.save_path.to_string(), data);
}

fn save_host_result(opt: &option::HostOption, result_map: HashMap<String, String>){
    let mut data = "[OPTIONS]".to_string();
    if opt.list_path.is_empty() {
        data = format!("{}\nTARGET_NETWORK:{}",data, opt.ip_addr);
    }else{
        data = format!("{}\nLIST_PATH:{}",data, opt.list_path);
    }
    data = format!("{}\n[RESULTS]\n",data);
    for (ip, oui) in result_map{
        data = format!("{}{} {}\n",data, ip, oui);
    }
    data = format!("{}\n",data);
    sys::save_file(opt.save_path.to_string(), data);
}
