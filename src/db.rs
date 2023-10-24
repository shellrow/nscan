use cross_socket::packet::ethernet::EthernetPacket;

use crate::define;
use crate::model;
use crate::ip;
use std::collections::HashMap;

pub fn get_oui_detail_map() -> HashMap<String, String> {
    let mut oui_map: HashMap<String, String> = HashMap::new();
    let ds_oui: Vec<model::Oui> = bincode::deserialize(define::OUI_BIN).unwrap_or(vec![]);
    for oui in ds_oui {
        oui_map.insert(oui.mac_prefix, oui.vendor_name_detail);
    }
    oui_map
}

pub fn get_vm_oui_map() -> HashMap<String, String> {
    let mut oui_map: HashMap<String, String> = HashMap::new();
    let ds_oui: Vec<model::Oui> = bincode::deserialize(define::OUI_VM_BIN).unwrap_or(vec![]);
    for oui in ds_oui {
        oui_map.insert(oui.mac_prefix, oui.vendor_name_detail);
    }
    oui_map
}

pub fn get_tcp_map() -> HashMap<u16, String> {
    let mut tcp_map: HashMap<u16, String> = HashMap::new();
    let ds_tcp_service: Vec<model::TcpService> = bincode::deserialize(define::TCP_SERVICE_BIN).unwrap_or(vec![]);
    for port in ds_tcp_service {
        tcp_map.insert(port.port, port.service_name);
    }
    tcp_map
}

pub fn get_default_ports() -> Vec<u16> {
    let default_ports: Vec<u16> = bincode::deserialize(define::DEFAULT_PORTS_BIN).unwrap_or(vec![]);
    default_ports
}

pub fn get_wellknown_ports() -> Vec<u16> {
    let wellknown_ports: Vec<u16> = bincode::deserialize(define::WELLKNOWN_PORTS_BIN).unwrap_or(vec![]);
    wellknown_ports
}

pub fn get_http_ports() -> Vec<u16> {
    let http_ports: Vec<u16> = bincode::deserialize(define::HTTP_PORTS_BIN).unwrap_or(vec![]);
    http_ports
}

pub fn get_https_ports() -> Vec<u16> {
    let https_ports: Vec<u16> = bincode::deserialize(define::HTTPS_PORTS_BIN).unwrap_or(vec![]);
    https_ports
}

pub fn get_os_ttl_list() -> Vec<model::OsTtl> {
    let ds_os_ttl: Vec<model::OsTtl> = bincode::deserialize(define::OS_TTL_BIN).unwrap_or(vec![]);
    ds_os_ttl
}

pub fn get_os_fingerprints() -> Vec<model::OsFingerprint> {
    let ds_os_fingerprints: Vec<model::OsFingerprint> = bincode::deserialize(define::OS_FINGERPRINT_BIN).unwrap_or(vec![]);
    ds_os_fingerprints
}

pub fn get_os_family_list() -> Vec<String> {
    let os_families: Vec<String> = bincode::deserialize(define::OS_FAMILY_BIN).unwrap_or(vec![]);
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
    // 0. Check TTL
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
    let mut tcp_window_size = 0;
    let mut tcp_options: Vec<String> = vec![];
    if let Some(ref tcp_fingerprint) = fingerprint.tcp_packet {
        tcp_window_size = tcp_fingerprint.window;
        for option in &tcp_fingerprint.options {
            tcp_options.push(option.kind.name());
        }
    }
    let tco_option_pattern = tcp_options.join("-");
    let mut os_ttl_info: model::OsTtl = model::OsTtl {
        initial_ttl: initial_ttl,
        os_description: String::new(),
        os_family: String::new(),
    };
    for os_ttl in os_ttl_list {
        if os_ttl.initial_ttl == initial_ttl {
            os_ttl_info.initial_ttl = os_ttl.initial_ttl;
            os_ttl_info.os_description = os_ttl.os_description;
            os_ttl_info.os_family = os_ttl.os_family;
        }
    }
    // 1. Select OS Fingerprint that match tcp_window_size and tcp_option_pattern
    let mut matched_fingerprints: Vec<model::OsFingerprint> = vec![];
    for f in &os_fingerprints {
        let mut window_size_match: bool = false;
        let mut option_pattern_match: bool = false;
        if f.tcp_window_sizes.contains(&tcp_window_size) {
            window_size_match = true;
        }
        for option_pattern in &f.tcp_option_patterns {
            if option_pattern == &tco_option_pattern {
                option_pattern_match = true;
            }
        }
        if window_size_match && option_pattern_match {
            matched_fingerprints.push(f.clone());
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
        for f in &matched_fingerprints {
            if os_ttl_info.os_family == f.os_family.to_lowercase() {
                return f.clone();
            }
        }
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
        for window_size in &f.tcp_window_sizes {
            if tcp_window_size - 100 < *window_size && *window_size < tcp_window_size + 100 {
                window_size_match = true;
            }
        }
        for option_pattern in &f.tcp_option_patterns {
            if option_pattern == &tco_option_pattern {
                option_pattern_match = true;
            }
        }
        if window_size_match && option_pattern_match {
            matched_fingerprints.push(f.clone());
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
        for f in &matched_fingerprints {
            if os_ttl_info.os_family == f.os_family.to_lowercase() {
                return f.clone();
            }
        }
        for f in matched_fingerprints {
            if os_family_list.contains(&f.os_family) {
                return f;
            }
        }
    }
    // 3. from TTL
    return model::OsFingerprint {
        cpe: String::from("(Failed to OS Fingerprinting)"),
        os_name: os_ttl_info.os_description,
        os_vendor: String::new(),
        os_family: os_ttl_info.os_family,
        os_generation: String::new(),
        device_type: String::new(),
        tcp_window_sizes: vec![tcp_window_size],
        tcp_option_patterns: vec![tco_option_pattern],
    };
}