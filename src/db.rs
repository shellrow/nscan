use cross_socket::packet::ethernet::EthernetPacket;

use crate::define;
use crate::model;
use crate::ip;
use std::collections::HashMap;

pub fn get_oui_detail_map() -> HashMap<String, String> {
    let mut oui_map: HashMap<String, String> = HashMap::new();
    let ds_oui: Vec<model::Oui> = serde_json::from_str(define::OUI_JSON).unwrap_or(vec![]);
    for oui in ds_oui {
        oui_map.insert(oui.mac_prefix, oui.vendor_name_detail);
    }
    oui_map
}

pub fn get_vm_oui_map() -> HashMap<String, String> {
    let mut oui_map: HashMap<String, String> = HashMap::new();
    let ds_oui: Vec<model::Oui> = serde_json::from_str(define::OUI_VM_JSON).unwrap_or(vec![]);
    for oui in ds_oui {
        oui_map.insert(oui.mac_prefix, oui.vendor_name_detail);
    }
    oui_map
}

pub fn get_tcp_map() -> HashMap<u16, String> {
    let mut tcp_map: HashMap<u16, String> = HashMap::new();
    let ds_tcp_service: Vec<model::TcpService> =
        serde_json::from_str(define::TCP_SERVICE_JSON).unwrap_or(vec![]);
    for port in ds_tcp_service {
        tcp_map.insert(port.port, port.service_name);
    }
    tcp_map
}

pub fn get_default_ports() -> Vec<u16> {
    let ds_default_ports: Vec<&str> = define::DEFAULT_PORTS_TXT.trim().split("\n").collect();
    let mut default_ports: Vec<u16> = vec![];
    for r in ds_default_ports {
        match r.trim_end().parse::<u16>() {
            Ok(port) => {
                default_ports.push(port);
            }
            Err(_) => {}
        }
    }
    default_ports
}

pub fn get_wellknown_ports() -> Vec<u16> {
    let ds_wellknown_ports: Vec<&str> = define::WELLKNOWN_PORTS_TXT.trim().split("\n").collect();
    let mut wellknown_ports: Vec<u16> = vec![];
    for r in ds_wellknown_ports {
        match r.trim_end().parse::<u16>() {
            Ok(port) => {
                wellknown_ports.push(port);
            }
            Err(_) => {}
        }
    }
    wellknown_ports
}

pub fn get_http_ports() -> Vec<u16> {
    let ds_http_ports: Vec<&str> = define::HTTP_PORTS_TXT.trim().split("\n").collect();
    let mut http_ports: Vec<u16> = vec![];
    for r in ds_http_ports {
        match r.trim_end().parse::<u16>() {
            Ok(port) => {
                http_ports.push(port);
            }
            Err(_) => {}
        }
    }
    http_ports
}

pub fn get_https_ports() -> Vec<u16> {
    let ds_https_ports: Vec<&str> = define::HTTPS_PORTS_TXT.trim().split("\n").collect();
    let mut https_ports: Vec<u16> = vec![];
    for r in ds_https_ports {
        match r.trim_end().parse::<u16>() {
            Ok(port) => {
                https_ports.push(port);
            }
            Err(_) => {}
        }
    }
    https_ports
}

pub fn get_os_ttl_list() -> Vec<model::OsTtl> {
    let ds_os_ttl: Vec<model::OsTtl> = serde_json::from_str(define::OS_TTL_JSON).unwrap_or(vec![]);
    ds_os_ttl
}

pub fn get_os_fingerprints() -> Vec<model::OsFingerprint> {
    let ds_os_fingerprints: Vec<model::OsFingerprint> =
        serde_json::from_str(define::OS_FINGERPRINT_JSON).unwrap_or(vec![]);
    ds_os_fingerprints
}

pub fn get_os_family_list() -> Vec<String> {
    let ds_os_families: Vec<&str> = define::OS_FAMILY_TXT.trim().split("\n").collect();
    let mut os_families: Vec<String> = vec![];
    for r in ds_os_families {
        os_families.push(r.to_string());
    }
    os_families
}

pub fn is_vm_fingerprint(fingerprint: &model::OsFingerprint) -> bool {
    if fingerprint.os_family == "Player".to_string() && fingerprint.device_type == "specialized".to_string() {
        return true;
    }
    false
}

pub fn in_vm_network(ether_packet: EthernetPacket) -> bool {
    let vm_oui_map: HashMap<String, String> = get_vm_oui_map();
    let mac = ether_packet.source.address();
    if mac.len() > 16 {
        let prefix8 = mac[0..8].to_uppercase();
        vm_oui_map.contains_key(&prefix8)
    } else {
        vm_oui_map.contains_key(&mac)
    }
}

pub fn verify_os_fingerprint(fingerprint: cross_socket::packet::PacketFrame) -> model::OsFingerprint {
    let os_family_list: Vec<String> = get_os_family_list();
    let os_fingerprints: Vec<model::OsFingerprint> = get_os_fingerprints();
    let in_vm: bool = if let Some(ether_packet) = fingerprint.ethernet_packet {
        in_vm_network(ether_packet.clone())
    } else {
        false
    };
    // 1. Select OS Fingerprint that match tcp_window_size and tcp_option_pattern
    let mut matched_fingerprints: Vec<model::OsFingerprint> = vec![];
    for f in &os_fingerprints {
        let mut window_size_match: bool = false;
        let mut option_pattern_match: bool = false;
        if let Some(ref tcp_fingerprint) = fingerprint.tcp_packet {
            if f.tcp_window_size == tcp_fingerprint.window {
                window_size_match = true;
            }
            let option_patterns: Vec<String> = f.tcp_option_pattern.split("|").map(|s| s.to_string()).collect();
            let mut options: Vec<String> = vec![];
            for option in &tcp_fingerprint.options {
                options.push(option.kind.name());
            }
            for option_pattern in option_patterns {
                if option_pattern == options.join("-") {
                    option_pattern_match = true;
                }
            }
            if window_size_match && option_pattern_match {
                matched_fingerprints.push(f.clone());
            }
        }
    }
    if matched_fingerprints.len() == 1 {
        return matched_fingerprints[0].clone();
    }else if matched_fingerprints.len() > 1 {
        // Check VM Fingerprint
        if in_vm {
            for f in &matched_fingerprints {
                if is_vm_fingerprint(f) {
                    let mut vmf = f.clone();
                    vmf.cpe = String::from("(Failed to OS Fingerprinting)");
                    vmf.os_name = format!("{} (Probably in VM Network)", vmf.os_name);
                    return vmf;
                }
            }
        }
        // Search fingerprint that match general OS Family
        matched_fingerprints.reverse();
        for f in matched_fingerprints {
            if os_family_list.contains(&f.os_family) {
                return f;
            }
        }
    }
    // 2. Select OS Fingerprint that match tcp_option_pattern and have most closely tcp_window_size
    let mut matched_fingerprints: Vec<model::OsFingerprint> = vec![];
    for f in os_fingerprints {
        let mut window_size_match: bool = false;
        let mut option_pattern_match: bool = false;
        if let Some(ref tcp_fingerprint) = fingerprint.tcp_packet {
            if tcp_fingerprint.window - 100 < f.tcp_window_size && f.tcp_window_size < tcp_fingerprint.window + 100 {
                window_size_match = true;
            }
            let option_patterns: Vec<String> = f.tcp_option_pattern.split("|").map(|s| s.to_string()).collect();
            let mut options: Vec<String> = vec![];
            for option in &tcp_fingerprint.options {
                options.push(option.kind.name());
            }
            for option_pattern in option_patterns {
                if option_pattern == options.join("-") {
                    option_pattern_match = true;
                }
            }
            if window_size_match && option_pattern_match {
                matched_fingerprints.push(f.clone());
            }
        }
    }
    if matched_fingerprints.len() == 1 {
        return matched_fingerprints[0].clone();
    }else if matched_fingerprints.len() > 1 {
        // Check VM Fingerprint
        if in_vm {
            for f in &matched_fingerprints {
                if is_vm_fingerprint(f) {
                    let mut vmf = f.clone();
                    vmf.cpe = String::from("(Failed to OS Fingerprinting)");
                    vmf.os_name = format!("{} (Probably using VM network interface)", vmf.os_name);
                    return vmf;
                }
            }
        }
        // Search fingerprint that match general OS Family
        matched_fingerprints.reverse();
        for f in matched_fingerprints {
            if os_family_list.contains(&f.os_family) {
                return f;
            }
        }
    }
    // 3. from TTL
    let os_ttl_list: Vec<model::OsTtl> = get_os_ttl_list();
    let initial_ttl = if let Some(ipv4_packet) = fingerprint.ipv4_packet {
        ip::guess_initial_ttl(ipv4_packet.ttl)
    } else {
        if let Some(ipv6_packet) = fingerprint.ipv6_packet {
            ip::guess_initial_ttl(ipv6_packet.hop_limit)
        } else {
            0
        }
    };
    for os_ttl in os_ttl_list {
        if os_ttl.initial_ttl == initial_ttl {
            return model::OsFingerprint {
                cpe: String::from("(Failed to OS Fingerprinting)"),
                os_name: os_ttl.os_description,
                os_vendor: String::new(),
                os_family: os_ttl.os_family,
                os_generation: String::new(),
                device_type: String::new(),
                tcp_window_size: 0,
                tcp_option_pattern: String::new(),
            };
        }
    }
    model::OsFingerprint::new()
}