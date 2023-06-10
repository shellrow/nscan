use crate::models::OsFingerprint;
use crate::option::ScanOption;
use crate::option::{TargetInfo};
use crate::result::{HostInfo, HostScanResult, PortScanResult};
use crate::{define, network};
use netscan::async_io::{HostScanner as AsyncHostScanner, PortScanner as AsyncPortScanner};
use netscan::blocking::{HostScanner, PortScanner};
use netscan::os::{Fingerprinter, ProbeResult, ProbeTarget, ProbeType};
use netscan::service::{PortDatabase, ServiceDetector};
use netscan::host::HostInfo as NsHostInfo;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::{thread, vec};

pub fn run_port_scan(
    opt: ScanOption,
    msg_tx: &mpsc::Sender<String>,
) -> netscan::result::PortScanResult {
    let mut port_scanner = match PortScanner::new(opt.src_ip) {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let dst: NsHostInfo = NsHostInfo::new_with_ip_addr(opt.targets[0].ip_addr).with_ports(opt.targets[0].ports.clone()).with_host_name(opt.targets[0].host_name.clone());
    port_scanner.add_target(dst);
    port_scanner.set_scan_type(opt.port_scan_type.to_netscan_type());
    port_scanner.set_timeout(opt.timeout);
    port_scanner.set_wait_time(opt.wait_time);
    port_scanner.set_send_rate(opt.send_rate);
    let rx = port_scanner.get_progress_receiver();
    let handle = thread::spawn(move || port_scanner.scan());
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    let result = handle.join().unwrap();
    result
}

pub async fn run_async_port_scan(
    opt: ScanOption,
    msg_tx: &mpsc::Sender<String>,
) -> netscan::result::PortScanResult {
    let mut port_scanner = match AsyncPortScanner::new(opt.src_ip) {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    let dst: NsHostInfo = NsHostInfo::new_with_ip_addr(opt.targets[0].ip_addr).with_ports(opt.targets[0].ports.clone()).with_host_name(opt.targets[0].host_name.clone());
    port_scanner.add_target(dst);
    port_scanner.set_scan_type(opt.port_scan_type.to_netscan_type());
    port_scanner.set_timeout(opt.timeout);
    port_scanner.set_wait_time(opt.wait_time);
    port_scanner.set_send_rate(opt.send_rate);
    let rx = port_scanner.get_progress_receiver();
    let handle = thread::spawn(move || async_io::block_on(async { port_scanner.scan().await }));
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    let result = handle.join().unwrap();
    result
}

pub fn run_host_scan(
    opt: ScanOption,
    msg_tx: &mpsc::Sender<String>,
) -> netscan::result::HostScanResult {
    let mut host_scanner = match HostScanner::new(opt.src_ip) {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    for target in opt.targets {
        let dst: NsHostInfo = NsHostInfo::new_with_ip_addr(target.ip_addr).with_ports(target.ports).with_host_name(target.host_name);
        host_scanner.add_target(dst);
    }
    host_scanner.set_scan_type(opt.host_scan_type.to_netscan_type());
    host_scanner.set_timeout(opt.timeout);
    host_scanner.set_wait_time(opt.wait_time);
    host_scanner.set_send_rate(opt.send_rate);
    let rx = host_scanner.get_progress_receiver();
    let handle = thread::spawn(move || host_scanner.scan());
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    let result = handle.join().unwrap();
    result
}

pub async fn run_async_host_scan(
    opt: ScanOption,
    msg_tx: &mpsc::Sender<String>,
) -> netscan::result::HostScanResult {
    let mut host_scanner = match AsyncHostScanner::new(opt.src_ip) {
        Ok(scanner) => scanner,
        Err(e) => panic!("Error creating scanner: {}", e),
    };
    for target in opt.targets {
        let dst: NsHostInfo = NsHostInfo::new_with_ip_addr(target.ip_addr).with_ports(target.ports);
        host_scanner.add_target(dst);
    }
    host_scanner.set_scan_type(opt.host_scan_type.to_netscan_type());
    host_scanner.set_timeout(opt.timeout);
    host_scanner.set_wait_time(opt.wait_time);
    host_scanner.set_send_rate(opt.send_rate);
    let rx = host_scanner.get_progress_receiver();
    let handle = thread::spawn(move || async_io::block_on(async { host_scanner.scan().await }));
    while let Ok(socket_addr) = rx.lock().unwrap().recv() {
        match msg_tx.send(socket_addr.to_string()) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    let result = handle.join().unwrap();
    result
}

pub fn run_service_detection(
    targets: Vec<TargetInfo>,
    msg_tx: &mpsc::Sender<String>,
    port_db: Option<PortDatabase>,
) -> HashMap<IpAddr, HashMap<u16, String>> {
    let mut map: HashMap<IpAddr, HashMap<u16, String>> = HashMap::new();
    for target in targets {
        let mut service_detector = ServiceDetector::new();
        service_detector.set_dst_ip(target.ip_addr);
        service_detector.set_dst_name(target.host_name);
        service_detector.set_ports(target.ports);
        let service_map: HashMap<u16, String> = service_detector.detect(port_db.clone());
        map.insert(target.ip_addr, service_map);
        match msg_tx.send(target.ip_addr.to_string()) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    map
}

pub fn run_os_fingerprinting(
    opt: ScanOption,
    targets: Vec<TargetInfo>,
    _msg_tx: &mpsc::Sender<String>,
) -> Vec<ProbeResult> {
    let mut fingerprinter = Fingerprinter::new(opt.src_ip).unwrap();
    fingerprinter.set_wait_time(opt.wait_time);
    for target in targets {
        let probe_target: ProbeTarget = ProbeTarget {
            ip_addr: target.ip_addr,
            open_tcp_ports: target.ports,
            closed_tcp_port: 0,
            open_udp_port: 0,
            closed_udp_port: 33455,
        };
        fingerprinter.add_probe_target(probe_target);
    }
    fingerprinter.add_probe_type(ProbeType::IcmpEchoProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpUnreachableProbe);
    fingerprinter.add_probe_type(ProbeType::TcpProbe);
    let results = fingerprinter.probe();
    results
}

pub async fn run_service_scan(opt: ScanOption, msg_tx: &mpsc::Sender<String>) -> PortScanResult {
    let mut result: PortScanResult = PortScanResult::new();
    // Port Scan
    match msg_tx.send(String::from(define::MESSAGE_START_PORTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    let ps_result: netscan::result::PortScanResult = if opt.async_scan {
        async_io::block_on(async { run_async_port_scan(opt.clone(), &msg_tx).await })
    } else {
        run_port_scan(opt.clone(), &msg_tx)
    };
    match msg_tx.send(String::from(define::MESSAGE_END_PORTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    // Service Detection
    let mut sd_result: HashMap<IpAddr, HashMap<u16, String>> = HashMap::new();
    let mut sd_time: Duration = Duration::from_millis(0);
    if opt.service_detection && ps_result.results.len() > 0 {
        match msg_tx.send(String::from(define::MESSAGE_START_SERVICEDETECTION)) {
            Ok(_) => {}
            Err(_) => {}
        }
        let mut sd_targets: Vec<TargetInfo> = vec![];
        let ip = ps_result.results.first().unwrap().ip_addr;
        let mut target: TargetInfo = TargetInfo::new_with_ip_addr(ip);
        target.host_name = ps_result.results.first().unwrap().host_name.clone();
        target.ports = ps_result.get_open_ports(ip);
        sd_targets.push(target);
        let port_db: PortDatabase = PortDatabase {
            http_ports: opt.http_ports.clone(),
            https_ports: opt.https_ports.clone(),
        };
        let start_time: Instant = Instant::now();
        sd_result = run_service_detection(sd_targets, &msg_tx, Some(port_db));
        sd_time = Instant::now().duration_since(start_time);
        match msg_tx.send(String::from(define::MESSAGE_END_SERVICEDETECTION)) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    // OS Fingerprinting
    let mut od_result: Vec<ProbeResult> = vec![];
    let mut od_time: Duration = Duration::from_millis(0);
    if opt.os_detection && ps_result.results.len() > 0 {
        match msg_tx.send(String::from(define::MESSAGE_START_OSDETECTION)) {
            Ok(_) => {}
            Err(_) => {}
        }
        let ip = ps_result.results.first().unwrap().ip_addr;
        let mut od_targets: Vec<TargetInfo> = vec![];
        let mut target: TargetInfo = TargetInfo::new_with_ip_addr(ip);
        target.ports = ps_result.get_open_ports(ip);
        od_targets.push(target);
        let start_time: Instant = Instant::now();
        od_result = run_os_fingerprinting(opt.clone(), od_targets, &msg_tx);
        od_time = Instant::now().duration_since(start_time);
        match msg_tx.send(String::from(define::MESSAGE_END_OSDETECTION)) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    // return crate::result::PortScanResult
    if ps_result.results.len() > 0 {
        let ip = ps_result.results.first().unwrap().ip_addr;
        let mut ports = ps_result.results.first().unwrap().ports.clone();
        // Sort by port number
        ports.sort_by(|a, b| a.port.cmp(&b.port));
        let tcp_map = opt.tcp_map;
        let t_map: HashMap<u16, String> = HashMap::new();
        let service_map = sd_result.get(&ip).unwrap_or(&t_map);
        // PortInfo
        for port in ports {
            let port_info = crate::result::PortInfo {
                port_number: port.port.clone(),
                port_status: format!("{:?}", port.status),
                service_name: tcp_map
                    .get(&port.port)
                    .unwrap_or(&String::new())
                    .to_string(),
                service_version: service_map
                    .get(&port.port)
                    .unwrap_or(&String::new())
                    .to_string(),
                remark: String::new(),
            };
            result.ports.push(port_info);
        }
        // HostInfo
        let os_fingetprint = if od_result.len() > 0 {
            crate::os::verify_os_fingerprint(od_result[0].tcp_fingerprint.clone())
        } else {
            OsFingerprint::new()
        };
        let host_info = crate::result::HostInfo {
            ip_addr: ip.to_string(),
            host_name: if let Some(target) = opt.targets.first() { target.host_name.clone() } else { network::lookup_ip_addr(ip.to_string()) },
            mac_addr: String::new(),
            vendor_info: String::new(),
            os_name: os_fingetprint.os_name,
            cpe: os_fingetprint.cpe,
        };
        result.host = host_info;
        result.port_scan_time = ps_result.scan_time;
        result.service_detection_time = sd_time;
        result.os_detection_time = od_time;
        result.total_scan_time =
            result.port_scan_time + result.service_detection_time + result.os_detection_time;
    }
    return result;
}

pub async fn run_node_scan(opt: ScanOption, msg_tx: &mpsc::Sender<String>) -> HostScanResult {
    let mut result: HostScanResult = HostScanResult::new();
    result.protocol = opt.protocol;
    if opt.targets.len() > 0 {
        result.port_number = opt.targets[0].ports[0];
    }
    // Host Scan
    match msg_tx.send(String::from(define::MESSAGE_START_HOSTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    let hs_result: netscan::result::HostScanResult = if opt.async_scan {
        async_io::block_on(async { run_async_host_scan(opt.clone(), &msg_tx).await })
    } else {
        run_host_scan(opt.clone(), &msg_tx)
    };
    match msg_tx.send(String::from(define::MESSAGE_END_HOSTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    // Get MAC Addresses (LAN only)
    let start_time: Instant = Instant::now();
    let mut arp_targets: Vec<IpAddr> = vec![];
    for host in hs_result.get_hosts() {
        if network::in_same_network(opt.src_ip, host) {
            arp_targets.push(host);
        }
    }
    match msg_tx.send(String::from(define::MESSAGE_START_LOOKUP)) {
        Ok(_) => {}
        Err(_) => {}
    }
    let mac_map: HashMap<IpAddr, String> =
        network::get_mac_addresses(arp_targets.clone(), opt.src_ip);
    let dns_map: HashMap<IpAddr, String> = network::lookup_ips(hs_result.get_hosts());
    for host in hs_result.hosts {
        let host_info = HostInfo {
            ip_addr: host.ip_addr.to_string(),
            host_name: if host.host_name.is_empty() { dns_map.get(&host.ip_addr).unwrap_or(&String::new()).to_string() } else { host.host_name },
            mac_addr: mac_map
                .get(&host.ip_addr)
                .unwrap_or(&String::new())
                .to_string(),
            vendor_info: if let Some(mac) = mac_map.get(&host.ip_addr) {
                if mac.len() > 16 {
                    let prefix8 = mac[0..8].to_uppercase();
                    opt.oui_map
                        .get(&prefix8)
                        .unwrap_or(&String::new())
                        .to_string()
                } else {
                    opt.oui_map.get(mac).unwrap_or(&String::new()).to_string()
                }
            } else {
                String::new()
            },
            os_name: opt
                .ttl_map
                .get(&network::guess_initial_ttl(host.ttl))
                .unwrap_or(&String::new())
                .to_string(),
            cpe: String::new(),
        };
        result.hosts.push(host_info);
    }
    match msg_tx.send(String::from(define::MESSAGE_END_LOOKUP)) {
        Ok(_) => {}
        Err(_) => {}
    }
    // Sort by IP Address
    result.hosts.sort_by(|a, b| a.ip_addr.cmp(&b.ip_addr));
    let lookup_time: Duration = Instant::now().duration_since(start_time);
    result.host_scan_time = hs_result.scan_time;
    result.lookup_time = lookup_time;
    result.total_scan_time = result.host_scan_time + result.lookup_time;
    return result;
}
