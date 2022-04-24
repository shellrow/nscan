use std::collections::HashMap;
use crate::define;
use crate::model::{OSFingerprint, OuiData, PortData, OsTtl};

pub fn get_oui_map() -> HashMap<String, String> {
    let mut oui_map: HashMap<String, String> = HashMap::new();
    let rs_nscan_oui: Vec<OuiData> = serde_json::from_str(define::NSCAN_OUI).unwrap_or(vec![]);
    for oui in rs_nscan_oui {
        oui_map.insert(oui.mac_prefix, oui.vendor_name_detail);
    }
    oui_map
}

pub fn get_tcp_map() -> HashMap<String, String> {
    let mut tcp_map: HashMap<String, String> = HashMap::new();
    let rs_nscan_tcp_port: Vec<PortData> = serde_json::from_str(define::NSCAN_TCP_PORT).unwrap_or(vec![]);
    for port in rs_nscan_tcp_port {
        tcp_map.insert(port.port_number.to_string(), port.service_name);
    }
    tcp_map
}

pub fn get_default_ports() -> Vec<u16> {
    let rs_nscan_default_ports: Vec<&str> = define::NSCAN_DEFAULT_PORTS.trim().split("\n").collect();
    let mut default_ports: Vec<u16> = vec![];
    for r in rs_nscan_default_ports {
        match r.trim_end().parse::<u16>() {
            Ok(port) => {
                default_ports.push(port);
            },
            Err(_) => {},
        }
    }
    default_ports
}

pub fn get_http_ports() -> Vec<u16> {
    let rs_nscan_http_ports: Vec<&str> = define::NSCAN_HTTP.trim().split("\n").collect();
    let mut http_ports: Vec<u16> = vec![];
    for r in rs_nscan_http_ports {
        match r.trim_end().parse::<u16>() {
            Ok(port) => {
                http_ports.push(port);
            },
            Err(_) => {},
        }
    }
    http_ports
}

pub fn get_https_ports() -> Vec<u16> {
    let rs_nscan_https_ports: Vec<&str> = define::NSCAN_HTTPS.trim().split("\n").collect();
    let mut https_ports: Vec<u16> = vec![];
    for r in rs_nscan_https_ports {
        match r.trim_end().parse::<u16>() {
            Ok(port) => {
                https_ports.push(port);
            },
            Err(_) => {},
        }
    }
    https_ports
}

pub fn get_os_fingerprints() -> Vec<OSFingerprint> {
    let fingerprints: Vec<OSFingerprint> = serde_json::from_str(define::NSCAN_OS).unwrap_or(vec![]);    
    fingerprints
}

#[allow(dead_code)]
pub fn get_os_ttl() -> HashMap<u8, String> {
    let mut ttl_map: HashMap<u8, String> = HashMap::new();
    let rs_nscan_os_ttl: Vec<OsTtl> = serde_json::from_str(define::NSCAN_OS_TTL).unwrap_or(vec![]);
    for os_ttl in rs_nscan_os_ttl {
        ttl_map.insert(os_ttl.initial_ttl, os_ttl.description);
    }
    ttl_map
}
