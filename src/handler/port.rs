use crate::fp::MatchResult;
use crate::host::{Host, PortStatus};
use crate::json::port::PortScanResult;
use crate::output;
use crate::scan::result::ScanResult;
use crate::scan::scanner::{PortScanner, ServiceDetector};
use crate::scan::setting::{PortScanSetting, PortScanType, ServiceProbeSetting};
use crate::util::tree::node_label;
use clap::ArgMatches;
use indicatif::{ProgressBar, ProgressDrawTarget};
use netdev::mac::MacAddr;
use netdev::Interface;
use std::net::IpAddr;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use termtree::Tree;

pub fn handle_portscan(args: &ArgMatches) {
    output::log_with_time("Initiating port scan...", "INFO");
    let port_args = match args.subcommand_matches("port") {
        Some(matches) => matches,
        None => return,
    };
    let target: String = match port_args.get_one::<String>("target") {
        Some(target) => target.to_owned(),
        None => return,
    };
    let target_host_name: String;
    let target_ip_addr: IpAddr;
    let target_ports: Vec<u16>;
    if crate::host::is_valid_ip_addr(&target) {
        target_ip_addr = target.parse().unwrap();
        target_host_name = crate::dns::lookup_ip_addr(&target_ip_addr).unwrap_or(target.clone());
    } else {
        target_host_name = target.clone();
        target_ip_addr = match crate::dns::lookup_host_name(&target) {
            Some(ip) => ip,
            None => return,
        };
    }
    if port_args.contains_id("ports") {
        // Use specific ports (delimiter: ',')
        target_ports = port_args
            .get_many::<u16>("ports")
            .unwrap_or_default()
            .copied()
            .collect();
    } else if port_args.contains_id("range") {
        // Use specific range (delimiter: '-')
        // 0: start, 1: end
        let range: Vec<u16> = port_args
            .get_many::<u16>("range")
            .unwrap_or_default()
            .copied()
            .collect();
        target_ports = (range[0]..=range[1]).collect();
    } else if port_args.get_flag("wellknown") {
        // Use well-known ports
        target_ports = crate::db::get_wellknown_ports();
    } else {
        if port_args.get_flag("full") {
            // Use full ports (1-65535)
            target_ports = (1..=65535).collect();
        } else {
            // Use default 1000 ports
            target_ports = crate::db::get_default_ports();
        }
    }
    let interface: netdev::Interface = if let Some(if_name) = args.get_one::<String>("interface") {
        match crate::interface::get_interface_by_name(if_name.to_string()) {
            Some(iface) => iface,
            None => return,
        }
    } else {
        match netdev::get_default_interface() {
            Ok(iface) => iface,
            Err(_) => return,
        }
    };
    // Check reachability by ping (one-shot)
    let default_waittime: Duration;
    if port_args.get_flag("noping") {
        default_waittime = Duration::from_millis(200);
    } else {
        match crate::handler::ping::initial_ping(
            interface.index,
            target_ip_addr,
            target_host_name.clone(),
        ) {
            Ok(rtt) => {
                default_waittime = crate::util::setting::caluculate_wait_time(rtt);
            }
            Err(e) => {
                output::log_with_time(
                    &format!("{} You can disable this initial ping by --noping", e),
                    "ERROR",
                );
                return;
            }
        }
    }
    let scan_type: PortScanType = match port_args.get_one::<String>("scantype") {
        Some(scan_type) => match scan_type.as_str() {
            "CONNECT" => PortScanType::TcpConnectScan,
            _ => PortScanType::TcpSynScan,
        },
        None => PortScanType::TcpSynScan,
    };
    let timeout = match port_args.get_one::<u64>("timeout") {
        Some(timeout) => Duration::from_millis(*timeout),
        None => Duration::from_millis(10000),
    };
    let wait_time = match port_args.get_one::<u64>("waittime") {
        Some(wait_time) => Duration::from_millis(*wait_time),
        None => default_waittime,
    };
    let send_rate = match port_args.get_one::<u64>("rate") {
        Some(send_rate) => Duration::from_millis(*send_rate),
        None => Duration::from_millis(0),
    };
    let target_host: Host =
        Host::new(target_ip_addr, target_host_name.clone()).with_ports(target_ports);
    let mut result: PortScanResult = PortScanResult::new(target_ip_addr, target_host_name);
    let mut scan_setting = PortScanSetting::default()
        .set_if_index(interface.index)
        .set_scan_type(scan_type)
        .add_target(target_host.clone())
        .set_timeout(timeout)
        .set_wait_time(wait_time)
        .set_send_rate(send_rate);
    // Print options
    print_option(&scan_setting, &interface);
    if !port_args.get_flag("random") {
        scan_setting.randomize_ports();
        scan_setting.randomize_hosts();
    }
    if !crate::app::is_quiet_mode() {
        println!("[Progress]");
    }
    // Display progress with indicatif
    let bar = ProgressBar::new(scan_setting.targets[0].ports.len() as u64);
    if crate::app::is_quiet_mode() {
        bar.set_draw_target(ProgressDrawTarget::hidden());
    }
    //bar.enable_steady_tick(120);
    bar.set_style(output::get_progress_style());
    bar.set_position(0);
    bar.set_message("PortScan");
    let port_scanner = PortScanner::new(scan_setting);
    let rx = port_scanner.get_progress_receiver();
    // Run port scan
    let handle = thread::spawn(move || port_scanner.scan());
    // Print port scan progress
    while let Ok(_socket_addr) = rx.lock().unwrap().recv() {
        bar.inc(1);
    }
    let mut portscan_result: ScanResult = handle.join().unwrap();
    bar.finish_with_message(format!("PortScan ({:?})", portscan_result.scan_time));

    if portscan_result.hosts.len() == 0 {
        output::log_with_time("No results found", "INFO");
        return;
    }

    portscan_result.sort_ports();
    portscan_result.sort_hosts();

    // Set port scan result to host
    result.host.ports = portscan_result.hosts[0].get_open_ports();

    // Run service detection
    let probe_setting: ServiceProbeSetting = ServiceProbeSetting::default(
        target_host.ip_addr,
        target_host.hostname,
        portscan_result.hosts[0].get_open_port_numbers(),
    );
    let service_detector = ServiceDetector::new(probe_setting);
    let service_rx = service_detector.get_progress_receiver();
    let bar = ProgressBar::new(portscan_result.hosts[0].get_open_port_numbers().len() as u64);
    if crate::app::is_quiet_mode() {
        bar.set_draw_target(ProgressDrawTarget::hidden());
    }
    bar.enable_steady_tick(120);
    bar.set_style(output::get_progress_style());
    bar.set_position(0);
    bar.set_message("ServiceDetection");
    let sd_start_time = std::time::Instant::now();
    let service_handle = thread::spawn(move || service_detector.run());
    // Print progress
    while let Ok(_socket_addr) = service_rx.lock().unwrap().recv() {
        bar.inc(1);
    }
    let sd_elapsed_time = sd_start_time.elapsed();
    bar.finish_with_message(format!("ServiceDetection ({:?})", sd_elapsed_time));
    let service_result = service_handle.join().unwrap();
    // Set service detection result to host
    for port in &mut result.host.ports {
        if let Some(result) = service_result.get(&port.number) {
            port.service_name = result.service_name.clone();
            port.service_version = result.service_detail.clone().unwrap_or(String::new());
        }
    }
    // OS detection
    if result.host.get_open_port_numbers().len() > 0 {
        if let Some(fingerprint) = portscan_result
            .get_syn_ack_fingerprint(result.host.ip_addr, result.host.get_open_port_numbers()[0])
        {
            let os_fingerprint: MatchResult = crate::fp::get_fingerprint(&fingerprint);
            result.host.os_family = format!("{} ({})", os_fingerprint.family, os_fingerprint.evidence);
        }
    }
    // Set vendor name
    if !crate::ip::is_global_addr(&result.host.ip_addr) {
        if let Some(h) = portscan_result.get_host(result.host.ip_addr) {
            if h.mac_addr != MacAddr::zero() {
                let oui_db = crate::db::OUI_DB.get().unwrap().read().unwrap();
                let vendor_name = match oui_db.lookup(&h.mac_addr.address()) {
                    Some(vendor) => vendor.vendor.to_string(),
                    None => String::new(),
                };
                result.host.mac_addr = h.mac_addr;
                result.host.vendor_name = vendor_name;
            }
        }
    }
    result.host.ttl = portscan_result.hosts[0].ttl;
    result.port_scan_time = portscan_result.scan_time;
    result.service_detection_time = sd_elapsed_time;
    result.total_scan_time = portscan_result.scan_time + sd_elapsed_time;
    result.scan_status = portscan_result.scan_status;
    // Print results
    if args.get_flag("json") {
        let json_result = serde_json::to_string_pretty(&result).unwrap();
        println!("{}", json_result);
    } else {
        show_portscan_result(&result.host);
    }

    output::log_with_time(
        &format!("Total elapsed time {:?} ", result.total_scan_time),
        "INFO",
    );

    match args.get_one::<PathBuf>("save") {
        Some(file_path) => {
            match crate::fs::save_text(file_path, serde_json::to_string_pretty(&result).unwrap()) {
                Ok(_) => {
                    output::log_with_time(
                        &format!("Saved to {}", file_path.to_string_lossy()),
                        "INFO",
                    );
                }
                Err(e) => {
                    output::log_with_time(&format!("Failed to save: {}", e), "ERROR");
                }
            }
        }
        None => {}
    }
}

pub fn print_option(setting: &PortScanSetting, interface: &Interface) {
    if crate::app::is_quiet_mode() {
        return;
    }
    println!();
    let mut tree = Tree::new(node_label("PortScan Config", None, None));
    let mut setting_tree = Tree::new(node_label("Settings", None, None));
    setting_tree.push(node_label(
        "Protocol",
        Some(setting.protocol.to_str()),
        None,
    ));
    setting_tree.push(node_label(
        "ScanType",
        Some(setting.scan_type.to_str()),
        None,
    ));
    setting_tree.push(node_label("InterfaceName", Some(&interface.name), None));
    setting_tree.push(node_label(
        "Timeout",
        Some(format!("{:?}", setting.timeout).as_str()),
        None,
    ));
    setting_tree.push(node_label(
        "WaitTime",
        Some(format!("{:?}", setting.wait_time).as_str()),
        None,
    ));
    setting_tree.push(node_label(
        "SendRate",
        Some(format!("{:?}", setting.send_rate).as_str()),
        None,
    ));
    tree.push(setting_tree);

    let mut target_tree = Tree::new(node_label("Target", None, None));
    for target in &setting.targets {
        target_tree.push(node_label(
            "IP Address",
            Some(&target.ip_addr.to_string()),
            None,
        ));
        if target.ip_addr.to_string() != target.hostname && !target.hostname.is_empty() {
            target_tree.push(node_label("Host Name", Some(&target.hostname), None));
        }
        if target.ports.len() > 10 {
            target_tree.push(node_label(
                "Port",
                Some(format!("{} port(s)", target.ports.len()).as_str()),
                None,
            ));
        } else {
            target_tree.push(node_label(
                "Port",
                Some(format!("{:?}", target.get_ports()).as_str()),
                None,
            ));
        }
    }
    tree.push(target_tree);
    println!("{}", tree);
}

pub fn show_portscan_result(host: &Host) {
    if !crate::app::is_quiet_mode() {
        println!();
    }
    let target_addr: String =
        if host.ip_addr.to_string() != host.hostname && !host.hostname.is_empty() {
            format!("{}({})", host.hostname, host.ip_addr)
        } else {
            host.ip_addr.to_string()
        };
    let mut tree = Tree::new(node_label(
        &format!("PortScan Result - {}", target_addr),
        None,
        None,
    ));
    let mut host_tree = Tree::new(node_label("Host Info", None, None));
    host_tree.push(node_label(
        "IP Address",
        Some(&host.ip_addr.to_string()),
        None,
    ));
    host_tree.push(node_label("Host Name", Some(&host.hostname), None));
    if host.mac_addr != MacAddr::zero() {
        host_tree.push(node_label(
            "MAC Address",
            Some(&host.mac_addr.to_string()),
            None,
        ));
    }
    if !host.vendor_name.is_empty() {
        host_tree.push(node_label("Vendor Name", Some(&host.vendor_name), None));
    }
    if !host.os_family.is_empty() {
        host_tree.push(node_label("OS Family", Some(&host.os_family), None));
    }
    let mut port_info_tree = Tree::new(node_label("Port Info", None, None));
    for port in &host.ports {
        if port.status == PortStatus::Open {
            let mut port_tree = Tree::new(node_label(&port.number.to_string(), None, None));
            port_tree.push(node_label("Status", Some(&port.status.name()), None));
            port_tree.push(node_label("Service Name", Some(&port.service_name), None));
            port_tree.push(node_label(
                "Service Detail",
                Some(&port.service_version),
                None,
            ));
            port_info_tree.push(port_tree);
        }
    }
    host_tree.push(port_info_tree);
    tree.push(host_tree);
    println!("{}", tree);
}
