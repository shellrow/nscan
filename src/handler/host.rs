use clap::ArgMatches;
use indicatif::ProgressBar;
use ipnet::Ipv4Net;
use crate::host::Host;
use crate::json::host::HostScanResult;
use crate::scan::result::ScanResult;
use crate::scan::scanner::HostScanner;
use crate::scan::setting::{HostScanSetting, HostScanType};
use netdev::Interface;
use term_table::row::Row;
use term_table::table_cell::{Alignment, TableCell};
use term_table::{Table, TableStyle};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;

use crate::output;

pub fn handle_hostscan(args: &ArgMatches) {
    output::log_with_time("Initiating host scan...", "INFO");
    let host_args = match args.subcommand_matches("hscan") {
        Some(matches) => matches,
        None => return,
    };
    let target: String = match host_args.get_one::<String>("target") {
        Some(target) => target.to_owned(),
        None => return,
    };
    let scan_type: HostScanType = match host_args.get_one::<String>("protocol") {
        Some(protocol) => HostScanType::from_str(protocol),
        None => HostScanType::IcmpPingScan,
    };
    let timeout = match host_args.get_one::<u64>("timeout") {
        Some(timeout) => Duration::from_millis(*timeout),
        None => Duration::from_millis(10000),
    };
    let port: u16 = match host_args.get_one::<u16>("port") {
        Some(port) => *port,
        None => 80 as u16,
    };
    let default_waittime: Duration = Duration::from_millis(200);
    let wait_time = match host_args.get_one::<u64>("waittime") {
        Some(wait_time) => Duration::from_millis(*wait_time),
        None => default_waittime,
    };
    let send_rate = match host_args.get_one::<u64>("rate") {
        Some(send_rate) => Duration::from_millis(*send_rate),
        None => Duration::from_millis(0),
    };
    let target_ips: Vec<IpAddr> = match Ipv4Net::from_str(&target) {
        Ok(ipv4net) => {
            // convert hosts to Vec<IpAddr>
            ipv4net.hosts().map(|x| IpAddr::V4(x)).collect()
        }
        Err(_) => {
            match Ipv4Addr::from_str(&target) {
                Ok(ip_addr) => {
                    Ipv4Net::new(ip_addr, 24).unwrap().hosts().map(|x| IpAddr::V4(x)).collect()
                }
                Err(_) => {
                    // Check if target is host-list file
                    match std::fs::read_to_string(&target) {
                        Ok(hosts) => {
                            let mut ips: Vec<IpAddr> = Vec::new();
                            for host in hosts.lines() {
                                let host = host.trim();
                                if host.is_empty() {
                                    continue;
                                }
                                match IpAddr::from_str(host) {
                                    Ok(ip) => ips.push(ip),
                                    Err(_) => continue,
                                }
                            }
                            ips
                        }
                        Err(_) => vec![],
                    }
                }
            }
        },
    };
    // Add scan target
    let mut targets: Vec<Host> = Vec::new();
    for ip in target_ips {
        let host: Host = Host::new(ip, String::new()).with_ports(vec![port]);
        targets.push(host);
    }
    let interface: Interface = if let Some(if_name) = args.get_one::<String>("interface") {
        match crate::interface::get_interface_by_name(if_name.to_string()) {
            Some(iface) => iface,
            None => return,
        }
    }else{
        match netdev::get_default_interface() {
            Ok(iface) => iface,
            Err(_) => return,
        }
    };
    let mut scan_setting = HostScanSetting::default()
    .set_if_index(interface.index)
    .set_scan_type(scan_type)
    .set_targets(targets)
    .set_timeout(timeout)
    .set_wait_time(wait_time)
    .set_send_rate(send_rate);
    // Print options
    print_option(&target, &scan_setting, &interface);
    if !host_args.get_flag("random") {        
        scan_setting.randomize_ports();
        scan_setting.randomize_hosts();
    }
    println!("[Progress]");
    // Display progress with indicatif
    let bar = ProgressBar::new(scan_setting.targets.len() as u64);
    //bar.enable_steady_tick(120);
    bar.set_style(output::get_progress_style());
    bar.set_position(0);
    bar.set_message("HostScan");
    let host_scanner = HostScanner::new(scan_setting);
    let rx = host_scanner.get_progress_receiver();
    // Run scan
    let handle = thread::spawn(move || host_scanner.scan());
    // Print progress
    while let Ok(_host) = rx.lock().unwrap().recv() {
        bar.inc(1);
    }
    let mut hostscan_result: ScanResult = handle.join().unwrap();
    bar.finish_with_message(format!("HostScan ({:?})", hostscan_result.scan_time));
    if hostscan_result.hosts.len() == 0 {
        output::log_with_time("No results found", "INFO");
        return;
    }
    hostscan_result.sort_ports();
    hostscan_result.sort_hosts();
    let os_family_map: HashMap<IpAddr, String> = crate::db::get_fingerprint_map(&hostscan_result.fingerprints);
    for host in &mut hostscan_result.hosts {
        host.os_family = os_family_map.get(&host.ip_addr).unwrap_or(&String::new()).to_string();
    }
    let result: HostScanResult = HostScanResult::from_scan_result(&hostscan_result);
    // Print results
    if args.get_flag("json") {
        let json_result = serde_json::to_string_pretty(&result).unwrap();
        println!("{}", json_result);
    }else {
        show_hostscan_result(&result);
    }
    output::log_with_time("Scan completed", "INFO");
    match args.get_one::<PathBuf>("save") {
        Some(file_path) => {
            match crate::fs::save_text(file_path, serde_json::to_string_pretty(&result).unwrap()) {
                Ok(_) => {
                    output::log_with_time(&format!("Saved to {}", file_path.to_string_lossy()), "INFO");
                },
                Err(e) => {
                    output::log_with_time(&format!("Failed to save: {}", e), "ERROR");
                },
            }
        },
        None => {},
    }
}

fn print_option(target: &str, setting: &HostScanSetting, interface: &Interface) {
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.has_top_boarder = false;
    table.has_bottom_boarder = false;
    table.style = TableStyle::blank();
    println!("[Options]");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Protocol", 1, Alignment::Left),
        TableCell::new_with_alignment(setting.protocol.to_str(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("ScanType", 1, Alignment::Left),
        TableCell::new_with_alignment(setting.scan_type.to_str(), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("InterfaceName", 1, Alignment::Left),
        TableCell::new_with_alignment(&interface.name, 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("Timeout", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", setting.timeout), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("WaitTime", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", setting.wait_time), 1, Alignment::Left),
    ]));
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("SendRate", 1, Alignment::Left),
        TableCell::new_with_alignment(format!("{:?}", setting.send_rate), 1, Alignment::Left),
    ]));
    println!("{}", table.render());

    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.has_top_boarder = false;
    table.has_bottom_boarder = false;
    table.style = TableStyle::blank();
    println!("[Target]");
    match Ipv4Net::from_str(&target) {
        Ok(ipv4net) => {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment("Network", 1, Alignment::Left),
                TableCell::new_with_alignment(ipv4net.to_string(), 1, Alignment::Left),
            ]));
        }
        Err(_) => {
            match Ipv4Addr::from_str(&target) {
                Ok(ip_addr) => {
                    let net = Ipv4Net::new(ip_addr, 24).unwrap();
                    table.add_row(Row::new(vec![
                        TableCell::new_with_alignment("Network", 1, Alignment::Left),
                        TableCell::new_with_alignment(net.to_string(), 1, Alignment::Left),
                    ]));
                }
                Err(_) => {
                    table.add_row(Row::new(vec![
                        TableCell::new_with_alignment("List", 1, Alignment::Left),
                        TableCell::new_with_alignment(target, 1, Alignment::Left),
                    ]));
                }
            }
        },
    }
    println!("{}", table.render());
}

fn show_hostscan_result(hostscan_result: &HostScanResult) {
    let oui_map: HashMap<String, String> = crate::db::get_oui_detail_map();
    //let os_family_map: HashMap<IpAddr, String> = crate::db::get_fingerprint_map(&hostscan_result.fingerprints);
    let mut table = Table::new();
    table.max_column_width = 60;
    table.separate_rows = false;
    table.has_top_boarder = false;
    table.has_bottom_boarder = false;
    table.style = TableStyle::blank();
    println!();
    println!("[Up Hosts]");
    table.add_row(Row::new(vec![
        TableCell::new_with_alignment("IP Address", 1, Alignment::Left),
        TableCell::new_with_alignment("Host Name", 1, Alignment::Left),
        TableCell::new_with_alignment("TTL", 1, Alignment::Left),
        TableCell::new_with_alignment("OS Family", 1, Alignment::Left),
        TableCell::new_with_alignment("MAC Address", 1, Alignment::Left),
        TableCell::new_with_alignment("Vendor Name", 1, Alignment::Left),
    ]));
    for host in &hostscan_result.hosts {
        if crate::ip::is_global_addr(&host.ip_addr) {
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(&host.ip_addr.to_string(), 1, Alignment::Left),
                TableCell::new_with_alignment(&host.hostname, 1, Alignment::Left),
                TableCell::new_with_alignment(&host.ttl, 1, Alignment::Left),
                TableCell::new_with_alignment(&host.os_family, 1, Alignment::Left),
                TableCell::new_with_alignment("-", 1, Alignment::Left),
                TableCell::new_with_alignment("-", 1, Alignment::Left),
            ]));
        }else{
            let vendor_name = if host.mac_addr.address().len() > 16 {
                let prefix8 = host.mac_addr.address()[0..8].to_uppercase();
                oui_map.get(&prefix8).unwrap_or(&String::new()).to_string()
            } else {
                oui_map.get(&host.mac_addr.address()).unwrap_or(&String::new()).to_string()
            };
            table.add_row(Row::new(vec![
                TableCell::new_with_alignment(&host.ip_addr.to_string(), 1, Alignment::Left),
                TableCell::new_with_alignment(&host.hostname, 1, Alignment::Left),
                TableCell::new_with_alignment(&host.ttl, 1, Alignment::Left),
                TableCell::new_with_alignment(&host.os_family, 1, Alignment::Left),
                TableCell::new_with_alignment(&host.mac_addr.to_string(), 1, Alignment::Left),
                TableCell::new_with_alignment(vendor_name, 1, Alignment::Left),
            ]));
        }
    }
    println!("{}", table.render());
}