use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::fs::read_to_string;
use std::collections::HashMap;
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use std::convert::TryInto;
use std::time::Instant;

use netscan::ScanStatus;
use netscan::{PortScanner, HostScanner};
use netscan::arp;
use default_net;
use super::{option, db, service};
use super::sys;

use ipnet::Ipv4Net;
use indicatif::{ProgressBar, ProgressStyle};
use term_table::{Table, TableStyle};
use term_table::table_cell::{TableCell,Alignment};
use term_table::row::Row;

pub fn handle_port_scan(opt: option::PortOption) {
    opt.show_options();
    println!("Scanning ports... ");
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
    let (tx, rx): (Sender<usize>, Receiver<usize>) = mpsc::channel();
    let port_scanner = thread::spawn(move || {
        port_scanner.run_scan(tx);
        port_scanner
    });
    let pb = ProgressBar::new(opt.port_list.len().try_into().unwrap());
    let pb_style = ProgressStyle::default_bar().template("[{elapsed_precise}] {wide_bar} {pos}/{len} {msg}");
    pb.set_style(pb_style);
    pb.set_message(format!("..."));
    loop {
        match rx.recv(){
            Ok(count) => {
                if count == opt.port_list.len() {
                    pb.finish_with_message("Done");
                    break;
                }else if count == 0 {
                    pb.finish_with_message("Timed out");
                    break;
                }else{
                    pb.set_position(count.try_into().unwrap());
                }
            },
            Err(e) => {
                println!("{}",e);
                break;
            },
        }
    }
    let mut port_scanner = port_scanner.join().unwrap();
    let result = port_scanner.get_result();
    match result.scan_status {
        ScanStatus::Error => {println!("An error occurred during scan");},
        _ => {},
    }
    let tcp_map = db::get_tcp_map();
    let d_start_time = Instant::now();
    let detail_map: HashMap<u16, String> = match opt.include_detail {
        true => {
            println!("Detecting service version... ");
            let target_ip = port_scanner.get_target_ipaddr().clone();
            let open_ports = result.open_ports.clone();
            let accept_invalid_certs = opt.accept_invalid_certs.clone();
            let mut cnt: usize = 0;
            let (tx, rx): (Sender<usize>, Receiver<usize>) = mpsc::channel();
            let d_result = thread::spawn(move || {
                service::detect_service_version(target_ip, open_ports, accept_invalid_certs, tx)
            });
            let pb = ProgressBar::new(result.open_ports.len().try_into().unwrap());
            let pb_style = ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {wide_bar} {pos}/{len} {msg}");
            pb.set_style(pb_style);
            pb.set_message(format!("..."));
            loop {
                match rx.recv(){
                    Ok(count) => {
                        if count == 0 {
                            pb.finish_with_message("Done");
                            break;
                        }else{
                            pb.inc(1);
                            cnt += 1;
                        }
                    },
                    Err(e) => {
                        println!("{}",e);
                        break;
                    },
                }
                if cnt == result.open_ports.len() {
                    pb.finish_with_message("Done");
                    break;
                }
            }
            let detail_map = d_result.join().unwrap();
            detail_map
        },
        false => HashMap::new(),
    };
    let detection_time = Instant::now().duration_since(d_start_time);
    println!();
    if result.open_ports.len() == 0 {
        println!("No open port found on target.");
        return;
    }
    let mut table = Table::new();
    table.max_column_width = 40;
    table.style = TableStyle::simple();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Reports", 3, Alignment::Center)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment(format!("{} open port(s) / scanned {} port(s) ", result.open_ports.len(), opt.port_list.len()), 3, Alignment::Center)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("PORT", 1, Alignment::Left),
        TableCell::new_with_alignment("SERVICE", 1, Alignment::Left),
        TableCell::new_with_alignment("SERVICE VERSION", 1, Alignment::Left)
    ]));
    for port in result.open_ports {
        let service_version: String = match detail_map.get(&port) {
            Some(v) => v.to_string(),
            None => String::from("None"),
        };
        let service = match tcp_map.get(&port.to_string()) {
            Some(service_name) => {
                service_name.to_string()
            },
            None => {
                String::from("Unknown service")
            },
        };
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment(format!("{}", port), 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{}", service), 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{}", service_version.trim_end()), 1, Alignment::Left)
        ]));
    }
    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 40;
    table.style = TableStyle::simple();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Performance", 2, Alignment::Center)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Port Scan Time", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.scan_time), 1, Alignment::Left)
    ]));
    if detail_map.len() > 0 {
        table.add_row(Row::new(vec![
            TableCell::new_with_alignment("Service Detection Time", 1, Alignment::Left),
            TableCell::new_with_alignment(format!("{:?}", detection_time), 1, Alignment::Left)
        ]));
    }
    println!("{}", table.render());
    if !opt.save_path.is_empty() {
        let s_result = port_scanner.get_result();
        save_port_result(&&opt, s_result, &tcp_map);
    }
}

pub fn handle_host_scan(opt: option::HostOption) {
    opt.show_options();
    println!("Scanning... ");
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
    let target_hosts = host_scanner.get_target_hosts();
    host_scanner.set_timeout(opt.timeout);
    host_scanner.set_wait_time(opt.wait_time);
    let (tx, rx): (Sender<usize>, Receiver<usize>) = mpsc::channel();
    let host_scanner = thread::spawn(move || {
        host_scanner.run_scan(tx);
        host_scanner
    });
    let pb = ProgressBar::new(target_hosts.len().try_into().unwrap());
    let pb_style = ProgressStyle::default_bar().template("[{elapsed_precise}] {wide_bar} {pos}/{len} {msg}");
    pb.set_style(pb_style);
    pb.set_message(format!("..."));
    loop {
        match rx.recv(){
            Ok(count) => {
                if count == target_hosts.len() {
                    pb.finish_with_message("Done");
                    break;
                }else if count == 0 {
                    pb.finish_with_message("Timed out");
                    break;
                }else{
                    pb.set_position(count.try_into().unwrap());
                }
            },
            Err(e) => {
                println!("{}",e);
                break;
            },
        }
    }
    let mut host_scanner = host_scanner.join().unwrap();
    let result = host_scanner.get_result();
    match result.scan_status {
        ScanStatus::Error => {println!("An error occurred during scan")},
        _ => {},
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
    let mut table = Table::new();
    table.max_column_width = 40;
    table.style = TableStyle::simple();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Reports", 3, Alignment::Center)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment(format!("{} host(s) up / {} IP address(es)", result.up_hosts.len(), host_scanner.get_target_hosts().len()), 3, Alignment::Center)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("IP ADDR", 1, Alignment::Left),
        TableCell::new_with_alignment("MAC ADDR", 1, Alignment::Left),
        TableCell::new_with_alignment("VENDOR NAME", 1, Alignment::Left)
    ]));
    let oui_map = db::get_oui_map();
    for host in result.up_hosts {
        match host.parse::<Ipv4Addr>(){
            Ok(ipaddr) => {
                let mac_addr: String = arp::get_mac_through_arp(&interface, ipaddr).to_string();
                if mac_addr.len() < 17 {
                    table.add_row(Row::new(vec![
                        TableCell::new_with_alignment(ipaddr.to_string(), 1, Alignment::Left),
                        TableCell::new_with_alignment(mac_addr.clone(), 1, Alignment::Left),
                        TableCell::new_with_alignment("Unknown", 1, Alignment::Left)
                    ]));
                    result_map.insert(ipaddr.to_string(), format!("{} Unknown", mac_addr));
                }else{
                    let prefix8 = mac_addr[0..8].to_uppercase();
                    match oui_map.get(&prefix8) {
                        Some(vendor_name) => {
                            if prefix8 == "00:00:00".to_string() {
                                table.add_row(Row::new(vec![
                                    TableCell::new_with_alignment(ipaddr.to_string(), 1, Alignment::Left),
                                    TableCell::new_with_alignment(mac_addr.clone(), 1, Alignment::Left),
                                    TableCell::new_with_alignment("Unknown", 1, Alignment::Left)
                                ]));
                                result_map.insert(ipaddr.to_string(), format!("{} Unknown", mac_addr));
                            }else{
                                table.add_row(Row::new(vec![
                                    TableCell::new_with_alignment(ipaddr.to_string(), 1, Alignment::Left),
                                    TableCell::new_with_alignment(mac_addr.clone(), 1, Alignment::Left),
                                    TableCell::new_with_alignment(vendor_name.to_string(), 1, Alignment::Left)
                                ]));
                                result_map.insert(ipaddr.to_string(), format!("{} {}", mac_addr, vendor_name));
                            }
                        },
                        None => {
                            if ipaddr.to_string() == default_interface.ipv4[0].to_string() {
                                table.add_row(Row::new(vec![
                                    TableCell::new_with_alignment(ipaddr.to_string(), 1, Alignment::Left),
                                    TableCell::new_with_alignment(mac_addr.clone(), 1, Alignment::Left),
                                    TableCell::new_with_alignment("Own device", 1, Alignment::Left)
                                ]));
                                result_map.insert(ipaddr.to_string(), format!("{} Own device", mac_addr));
                            }else{
                                table.add_row(Row::new(vec![
                                    TableCell::new_with_alignment(ipaddr.to_string(), 1, Alignment::Left),
                                    TableCell::new_with_alignment(mac_addr.clone(), 1, Alignment::Left),
                                    TableCell::new_with_alignment("Unknown", 1, Alignment::Left)
                                ]));
                                result_map.insert(ipaddr.to_string(), format!("{} Unknown", mac_addr));
                            }
                        },
                    }
                }
            },
            Err(_) => {
                table.add_row(Row::new(vec![
                    TableCell::new_with_alignment(host.to_string(), 1, Alignment::Left),
                    TableCell::new_with_alignment("", 1, Alignment::Left),
                    TableCell::new_with_alignment("", 1, Alignment::Left)
                ]));
            },
        }
    }
    println!("{}", table.render());
    let mut table = Table::new();
    table.max_column_width = 40;
    table.style = TableStyle::simple();
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Performance", 2, Alignment::Center)
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Scan Time", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", result.scan_time), 1, Alignment::Left)
    ]));
    println!("{}", table.render());
    if !opt.save_path.is_empty() {
        save_host_result(&opt, result_map);
    }
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