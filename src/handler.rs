use netscan::{PortScanner, HostScanner, ScanStatus};
use crossterm::style::Colorize;
use std::io::{stdout, Write};
use crate::option;
use crate::db;

pub fn handle_port_scan(opt: option::PortOption) {
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
        ScanStatus::Done => {println!("{}", "Done".green())},
        ScanStatus::Timeout => {println!("{}", "Timed out".yellow())},
        _ => {println!("{}", "Error".red())},
    }
    let tcp_map = db::get_tcp_map();
    for port in result.open_ports {
        println!("{},{}",port, tcp_map.get(&port.to_string()).unwrap_or(&String::from("None")));
    }
    println!("{:?}", result.scan_time);
}

pub fn handle_host_scan(opt: option::HostOption) {
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
    println!("{:?}", result.up_hosts);
}
