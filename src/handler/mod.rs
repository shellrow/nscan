pub mod dns;
pub mod host;
pub mod interface;
pub mod ping;
pub mod port;

use crate::fp::MatchResult;
use crate::host::Host;
use crate::json::port::PortScanResult;
use crate::scan::result::ScanResult;
use crate::scan::scanner::{PortScanner, ServiceDetector};
use crate::scan::setting::{PortScanSetting, PortScanType, ServiceProbeSetting};
use clap::ArgMatches;
use indicatif::{ProgressBar, ProgressDrawTarget};
use netdev::mac::MacAddr;
use std::net::IpAddr;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use crate::output;

pub fn default_probe(target_host: &str, args: &ArgMatches) {
    output::log_with_time("Initiating port scan...", "INFO");
    let target_host_name: String;
    let target_ip_addr: IpAddr;
    if crate::host::is_valid_ip_addr(target_host) {
        target_ip_addr = target_host.parse().unwrap();
        target_host_name =
            crate::dns::lookup_ip_addr(&target_ip_addr).unwrap_or(target_host.to_string());
    } else {
        target_host_name = target_host.to_string();
        target_ip_addr = match crate::dns::lookup_host_name(target_host) {
            Some(ip) => ip,
            None => return,
        };
    }
    let target_ports: Vec<u16> = if args.get_flag("full") {
        // Use full ports (1-65535)
        (1..=65535).collect()
    } else {
        // Use default 1000 ports
        crate::db::get_default_ports()
    };
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
    if args.get_flag("noping") {
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
    let target_host: Host =
        Host::new(target_ip_addr, target_host_name.clone()).with_ports(target_ports);
    let mut result: PortScanResult = PortScanResult::new(target_ip_addr, target_host_name);
    let mut scan_setting = PortScanSetting::default()
        .set_if_index(interface.index)
        .set_scan_type(PortScanType::TcpSynScan)
        .add_target(target_host.clone())
        .set_task_timeout(Duration::from_millis(10000))
        .set_wait_time(default_waittime)
        .set_send_rate(Duration::from_millis(0));
    // Print options
    port::print_option(&scan_setting, &interface);
    // Randomize ports and hosts
    scan_setting.randomize_ports();
    scan_setting.randomize_hosts();
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
    bar.enable_steady_tick(Duration::from_millis(120));
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
            result.host.os_family =
                format!("{} ({})", os_fingerprint.family, os_fingerprint.evidence);
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
        port::show_portscan_result(&result.host);
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
