use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use std::sync::mpsc;

use netprobe::fp::Fingerprint;
use netprobe::fp::FingerprintType;
use netprobe::fp::Fingerprinter;
use netprobe::setting::ProbeSetting;
//use netprobe::fp::Fingerprint;
//use netprobe::fp::FingerprintType;
//use netprobe::fp::Fingerprinter;
//use netprobe::setting::ProbeSetting;
use netscan::service::detector::ServiceDetector;
use netscan::service::payload::PayloadBuilder;
use netscan::service::result::ServiceProbeResult;
use netscan::service::setting::ProbeSetting as ServiceProbeSetting;

use crate::option;
use crate::result;
use crate::sys;
use crate::model;
use crate::db;
use crate::define;

pub fn run_port_scan(opt: option::PortScanOption) -> netscan::result::ScanResult {
    let mut port_scanner: netscan::scanner::PortScanner = netscan::scanner::PortScanner::new(opt.src_ip).unwrap();
    for target in opt.targets {
        let dst: netscan::host::HostInfo = netscan::host::HostInfo::new_with_ip_addr(target.ip_addr)
            .with_ports(target.ports.clone())
            .with_host_name(target.host_name.clone());
        port_scanner.scan_setting.add_target(dst);
    }
    port_scanner.scan_setting.scan_type = opt.scan_type.to_netscan_type();
    port_scanner.scan_setting.set_timeout(opt.timeout);
    port_scanner.scan_setting.set_wait_time(opt.wait_time);
    port_scanner.scan_setting.set_send_rate(opt.send_rate);

    let ns_scan_result: netscan::result::ScanResult = port_scanner.sync_scan();
    ns_scan_result
}

pub async fn run_async_port_scan(opt: option::PortScanOption) -> netscan::result::ScanResult {
    let mut port_scanner: netscan::scanner::PortScanner = netscan::scanner::PortScanner::new(opt.src_ip).unwrap();
    for target in opt.targets {
        let dst: netscan::host::HostInfo = netscan::host::HostInfo::new_with_ip_addr(target.ip_addr)
            .with_ports(target.ports.clone())
            .with_host_name(target.host_name.clone());
        port_scanner.scan_setting.add_target(dst);
    }
    port_scanner.scan_setting.scan_type = opt.scan_type.to_netscan_type();
    port_scanner.scan_setting.set_timeout(opt.timeout);
    port_scanner.scan_setting.set_wait_time(opt.wait_time);
    port_scanner.scan_setting.set_send_rate(opt.send_rate);

    let ns_scan_result: netscan::result::ScanResult = async_io::block_on(async { port_scanner.scan().await });
    ns_scan_result
}

pub fn run_service_detection(hosts: Vec<model::Host>) -> HashMap<IpAddr, HashMap<u16, String>> {
    let mut map: HashMap<IpAddr, HashMap<u16, String>> = HashMap::new();
    for host in hosts {
        let mut probe_setting: ServiceProbeSetting = ServiceProbeSetting::default(
            host.ip_addr,
            host.host_name.clone(),
            host.get_open_ports(),
        );
        let http_head = PayloadBuilder::http_head();
        let https_head = PayloadBuilder::https_head(host.host_name);
        let http_ports = db::get_http_ports();
        let https_ports = db::get_https_ports();
        probe_setting.payload_map = HashMap::new();
        for port in http_ports {
            probe_setting.payload_map.insert(port, http_head.clone());
        }
        for port in https_ports {
            probe_setting.payload_map.insert(port, https_head.clone());
        }
        let service_detector = ServiceDetector::new(probe_setting);
        let service_result: HashMap<u16, ServiceProbeResult> = service_detector.detect();
        let mut service_map: HashMap<u16, String> = HashMap::new();
        for (port, probe_result) in service_result {
            if probe_result.service_name.is_empty() {
                continue;
            }
            service_map.insert(port, probe_result.service_detail.unwrap_or(String::new()));
        }
        map.insert(host.ip_addr, service_map);
    }
    map
}

#[allow(dead_code)]
pub fn run_os_fingerprinting(src_ip: IpAddr, target_hosts: Vec<model::Host>) -> Vec<Fingerprint> {
    let mut fingerprints: Vec<Fingerprint> = Vec::new();
    for host in target_hosts {
        let open_port: u16 = if host.get_open_ports().len() > 0 {
            host.get_open_ports()[0]
        } else {
            80
        };
        let interface = crate::interface::get_interface_by_ip(src_ip).unwrap();
        let setting: ProbeSetting = ProbeSetting::fingerprinting(interface, host.ip_addr, Some(open_port), FingerprintType::TcpSynAck).unwrap();
        let fingerprinter: Fingerprinter = Fingerprinter::new(setting, FingerprintType::TcpSynAck);
        let fingerprint: Fingerprint = fingerprinter.probe();
        fingerprints.push(fingerprint);
    }
    fingerprints
}

pub async fn run_service_scan(opt: option::PortScanOption, msg_tx: &mpsc::Sender<String>) -> result::PortScanResult {
    let mut scan_result: result::PortScanResult = result::PortScanResult::new();
    scan_result.probe_id = sys::get_probe_id();
    scan_result.command_type = option::CommandType::PortScan;
    scan_result.protocol = opt.protocol;
    scan_result.scan_type = opt.scan_type;
    scan_result.start_time = sys::get_sysdate();

    let start_time: Instant = Instant::now();
    // Run port scan
    match msg_tx.send(String::from(define::MESSAGE_START_PORTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    let ns_scan_result: netscan::result::ScanResult = if opt.async_scan {
        run_async_port_scan(opt.clone()).await
    } else {
        run_port_scan(opt.clone())
    };
    match msg_tx.send(String::from(define::MESSAGE_END_PORTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    // Run service detection
    let mut service_map: HashMap<IpAddr, HashMap<u16, String>> = HashMap::new();
    if opt.service_detection {
        match msg_tx.send(String::from(define::MESSAGE_START_SERVICEDETECTION)) {
            Ok(_) => {}
            Err(_) => {}
        }
        let mut hosts: Vec<model::Host> = Vec::new();
        for scanned_host in &ns_scan_result.hosts {
            let mut host: model::Host = model::Host::new();
            host.ip_addr = scanned_host.ip_addr;
            host.host_name = scanned_host.host_name.clone();
            for open_port in scanned_host.get_open_ports() {
                host.add_open_port(open_port, String::new());
            }
            hosts.push(host);
        }
        service_map = run_service_detection(hosts);
        match msg_tx.send(String::from(define::MESSAGE_END_SERVICEDETECTION)) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
    scan_result.end_time = sys::get_sysdate();
    scan_result.elapsed_time = start_time.elapsed().as_millis() as u64;

    // Get master data
    let tcp_map: HashMap<u16, String> = db::get_tcp_map();

    // Arp (only for local network)
    let mut arp_targets: Vec<IpAddr> = vec![];
    let mut mac_map: HashMap<IpAddr, String> = HashMap::new(); 
    let mut oui_db: HashMap<String, String> = HashMap::new();
    for host in &ns_scan_result.hosts {
        if crate::ip::in_same_network(opt.src_ip, host.ip_addr) {
            arp_targets.push(host.ip_addr);
        }
    }
    if arp_targets.len() > 0 {
        mac_map = crate::ip::get_mac_addresses(arp_targets, opt.src_ip);
        oui_db = db::get_oui_detail_map();
    }

    // Set results
    match msg_tx.send(String::from(define::MESSAGE_START_CHECK_RESULTS)) {
        Ok(_) => {}
        Err(_) => {}
    }
    for scanned_host in ns_scan_result.hosts {
        let mut node_info: model::NodeInfo = model::NodeInfo::new();
        node_info.ip_addr = scanned_host.ip_addr;
        node_info.host_name = scanned_host.host_name.clone();
        node_info.node_type = model::NodeType::Destination;
        
        for port in scanned_host.ports {
            let mut service_info: model::ServiceInfo = model::ServiceInfo::new();
            service_info.port_number = port.port;
            match port.status {
                netscan::host::PortStatus::Open => {
                    service_info.port_status = model::PortStatus::Open;
                },
                netscan::host::PortStatus::Closed => {
                    service_info.port_status = model::PortStatus::Closed;
                },
                _ => {},
            }
            service_info.service_name = tcp_map.get(&port.port).unwrap_or(&String::new()).clone();

            if service_map.contains_key(&scanned_host.ip_addr) {
                if let Some(service_version) = service_map.get(&scanned_host.ip_addr).unwrap().get(&port.port) {
                    service_info.service_version = service_version.clone();
                }
            }
            node_info.services.push(service_info);
        }

        node_info.ttl = scanned_host.ttl;

        node_info.mac_addr = mac_map.get(&scanned_host.ip_addr).unwrap_or(&String::new()).clone();
        node_info.vendor_info = if let Some(mac) = mac_map.get(&scanned_host.ip_addr) {
            if mac.len() > 16 {
                let prefix8 = mac[0..8].to_uppercase();
                oui_db
                    .get(&prefix8)
                    .unwrap_or(&String::new())
                    .to_string()
            } else {
                oui_db.get(mac).unwrap_or(&String::new()).to_string()
            }
        } else {
            String::new()
        };
        
        // OS detection
        let mut os_fingerprint: model::OsFingerprint = model::OsFingerprint::new();
        let open_ports: Vec<u16> = node_info.get_open_ports();
        for fingerprint in &ns_scan_result.fingerprints {
            match scanned_host.ip_addr {
                IpAddr::V4(ipv4_addr) => {
                    if let Some(ipv4_header) = &fingerprint.ipv4_header {
                        if ipv4_header.source != ipv4_addr {
                            continue;
                        }
                    }
                }
                IpAddr::V6(ipv6_addr) => {
                    if let Some(ipv6_header) = &fingerprint.ipv6_header {
                        if ipv6_header.source != ipv6_addr {
                            continue;
                        }
                    }
                }
            }
            if let Some(tcp_header) = &fingerprint.tcp_header {
                if open_ports.contains(&tcp_header.source) {
                    os_fingerprint = db::verify_os_fingerprint(fingerprint);
                    break;
                }
            }
        }
        if os_fingerprint.os_family.is_empty() {
            if ns_scan_result.fingerprints.len() > 0 {
                os_fingerprint = db::verify_os_fingerprint(&ns_scan_result.fingerprints[0]);
            }
        }

        node_info.cpe = os_fingerprint.cpe;
        node_info.os_name = os_fingerprint.os_name;
        
        scan_result.nodes.push(node_info);
    }
    match msg_tx.send(String::from(define::MESSAGE_END_CHECK_RESULTS)) {
        Ok(_) => {}
        Err(_) => {}
    }
    scan_result.probe_status = result::ProbeStatus::Done;
    scan_result
}

pub fn run_host_scan(opt: option::HostScanOption) -> netscan::result::ScanResult {
    let mut host_scanner = netscan::scanner::HostScanner::new(opt.src_ip).unwrap();
    for target in opt.targets {
        let dst: netscan::host::HostInfo = netscan::host::HostInfo::new_with_ip_addr(target.ip_addr)
            .with_ports(target.ports.clone())
            .with_host_name(target.host_name.clone());
        host_scanner.scan_setting.add_target(dst);
    }
    host_scanner.scan_setting.scan_type = opt.scan_type.to_netscan_type();
    host_scanner.scan_setting.set_timeout(opt.timeout);
    host_scanner.scan_setting.set_wait_time(opt.wait_time);
    host_scanner.scan_setting.set_send_rate(opt.send_rate);

    let ns_scan_result: netscan::result::ScanResult = host_scanner.sync_scan();
    ns_scan_result
}

pub async fn run_async_host_scan(opt: option::HostScanOption) -> netscan::result::ScanResult  {
    let mut host_scanner = netscan::scanner::HostScanner::new(opt.src_ip).unwrap();
    for target in opt.targets {
        let dst: netscan::host::HostInfo = netscan::host::HostInfo::new_with_ip_addr(target.ip_addr)
            .with_ports(target.ports.clone())
            .with_host_name(target.host_name.clone());
        host_scanner.scan_setting.add_target(dst);
    }
    host_scanner.scan_setting.scan_type = opt.scan_type.to_netscan_type();
    host_scanner.scan_setting.set_timeout(opt.timeout);
    host_scanner.scan_setting.set_wait_time(opt.wait_time);
    host_scanner.scan_setting.set_send_rate(opt.send_rate);

    let ns_scan_result: netscan::result::ScanResult = async_io::block_on(async { host_scanner.scan().await });
    ns_scan_result
}

pub async fn run_node_scan(opt: option::HostScanOption, msg_tx: &mpsc::Sender<String>) -> result::HostScanResult {
    let mut scan_result: result::HostScanResult = result::HostScanResult::new();
    scan_result.probe_id = sys::get_probe_id();
    scan_result.command_type = option::CommandType::HostScan;
    scan_result.protocol = opt.protocol;
    scan_result.scan_type = opt.scan_type;
    scan_result.start_time = sys::get_sysdate();
    let start_time: Instant = Instant::now();

    // Run host scan
    match msg_tx.send(String::from(define::MESSAGE_START_HOSTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }
    let ns_scan_result: netscan::result::ScanResult = if opt.async_scan {
        run_async_host_scan(opt.clone()).await
    } else {
        run_host_scan(opt.clone())
    };
    match msg_tx.send(String::from(define::MESSAGE_END_HOSTSCAN)) {
        Ok(_) => {}
        Err(_) => {}
    }

    // lookup
    match msg_tx.send(String::from(define::MESSAGE_START_LOOKUP)) {
        Ok(_) => {}
        Err(_) => {}
    }
    // DNS lookup
    let mut lookup_target_ips: Vec<IpAddr> = vec![];
    let mut dns_map: HashMap<IpAddr, String> = HashMap::new();
    for host in &ns_scan_result.hosts {
        if host.host_name.is_empty() || host.host_name == host.ip_addr.to_string() {
            lookup_target_ips.push(host.ip_addr);
        }else{
            dns_map.insert(host.ip_addr, host.host_name.clone());
        }
    }
    let resolved_map: HashMap<IpAddr, String> = netprobe::dns::lookup_ips(lookup_target_ips);
    for (ip, host_name) in resolved_map {
        if host_name.is_empty() {
            dns_map.insert(ip, ip.to_string());
        }else{
            dns_map.insert(ip, host_name);
        }
    }
    // Arp (only for local network)
    let mut arp_targets: Vec<IpAddr> = vec![];
    let mut mac_map: HashMap<IpAddr, String> = HashMap::new(); 
    let mut oui_db: HashMap<String, String> = HashMap::new();
    for host in &ns_scan_result.hosts {
        if crate::ip::in_same_network(opt.src_ip, host.ip_addr) {
            arp_targets.push(host.ip_addr);
        }
    }
    if arp_targets.len() > 0 {
        mac_map = crate::ip::get_mac_addresses(arp_targets, opt.src_ip);
        oui_db = db::get_oui_detail_map();
    }
    match msg_tx.send(String::from(define::MESSAGE_END_LOOKUP)) {
        Ok(_) => {}
        Err(_) => {}
    }

    scan_result.end_time = sys::get_sysdate();
    scan_result.elapsed_time = start_time.elapsed().as_millis() as u64;

    // Set results
    match msg_tx.send(String::from(define::MESSAGE_START_CHECK_RESULTS)) {
        Ok(_) => {}
        Err(_) => {}
    }
    for scanned_host in ns_scan_result.hosts {
        let mut node_info: model::NodeInfo = model::NodeInfo::new();
        node_info.ip_addr = scanned_host.ip_addr;
        node_info.host_name = dns_map.get(&scanned_host.ip_addr).unwrap_or(&scanned_host.ip_addr.to_string()).clone();
        node_info.node_type = model::NodeType::Destination;
        
        for port in scanned_host.ports {
            let mut service_info: model::ServiceInfo = model::ServiceInfo::new();
            service_info.port_number = port.port;
            match port.status {
                netscan::host::PortStatus::Open => {
                    service_info.port_status = model::PortStatus::Open;
                },
                netscan::host::PortStatus::Closed => {
                    service_info.port_status = model::PortStatus::Closed;
                },
                _ => {},
            }
            node_info.services.push(service_info);
        }

        node_info.ttl = scanned_host.ttl;

        node_info.mac_addr = mac_map.get(&scanned_host.ip_addr).unwrap_or(&String::new()).clone();
        node_info.vendor_info = if let Some(mac) = mac_map.get(&scanned_host.ip_addr) {
            if mac.len() > 16 {
                let prefix8 = mac[0..8].to_uppercase();
                oui_db
                    .get(&prefix8)
                    .unwrap_or(&String::new())
                    .to_string()
            } else {
                oui_db.get(mac).unwrap_or(&String::new()).to_string()
            }
        } else {
            String::new()
        };

        let mut os_fingerprint: model::OsFingerprint = model::OsFingerprint::new();
        for fingerprint in &ns_scan_result.fingerprints {
            match scanned_host.ip_addr {
                IpAddr::V4(ipv4_addr) => {
                    if let Some(ipv4_header) = &fingerprint.ipv4_header {
                        if ipv4_header.source == ipv4_addr {
                            os_fingerprint = db::verify_os_fingerprint(fingerprint);
                            break;
                        }
                    }
                }
                IpAddr::V6(ipv6_addr) => {
                    if let Some(ipv6_header) = &fingerprint.ipv6_header {
                        if ipv6_header.source == ipv6_addr {
                            os_fingerprint = db::verify_os_fingerprint(fingerprint);
                            break;
                        }
                    }
                }
            }
        }
        node_info.cpe = os_fingerprint.cpe;
        if opt.protocol == crate::option::IpNextLevelProtocol::TCP {
            node_info.os_name = os_fingerprint.os_name;
        }else {
            node_info.os_name = os_fingerprint.os_family;
        }
        
        scan_result.nodes.push(node_info);
    }
    match msg_tx.send(String::from(define::MESSAGE_END_CHECK_RESULTS)) {
        Ok(_) => {}
        Err(_) => {}
    }
    scan_result.probe_status = result::ProbeStatus::Done;
    return scan_result;
}
