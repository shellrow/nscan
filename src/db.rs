use crate::define;
use crate::models;
use std::collections::HashMap;

pub fn get_oui_detail_map() -> HashMap<String, String> {
    let mut oui_map: HashMap<String, String> = HashMap::new();
    let ds_oui: Vec<models::Oui> = serde_json::from_str(define::OUI_JSON).unwrap_or(vec![]);
    for oui in ds_oui {
        oui_map.insert(oui.mac_prefix, oui.vendor_name_detail);
    }
    oui_map
}

pub fn get_tcp_map() -> HashMap<u16, String> {
    let mut tcp_map: HashMap<u16, String> = HashMap::new();
    let ds_tcp_service: Vec<models::TcpService> =
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

pub fn get_os_ttl_map() -> HashMap<u8, String> {
    let mut os_ttl_map: HashMap<u8, String> = HashMap::new();
    let ds_os_ttl: Vec<models::OsTtl> = serde_json::from_str(define::OS_TTL_JSON).unwrap_or(vec![]);
    for os_ttl in ds_os_ttl {
        os_ttl_map.insert(os_ttl.initial_ttl, os_ttl.os_description);
    }
    os_ttl_map
}

pub fn get_os_ttl_list() -> Vec<models::OsTtl> {
    let ds_os_ttl: Vec<models::OsTtl> = serde_json::from_str(define::OS_TTL_JSON).unwrap_or(vec![]);
    ds_os_ttl
}

pub fn get_os_fingerprints() -> Vec<models::OsFingerprint> {
    let ds_os_fingerprints: Vec<models::OsFingerprint> =
        serde_json::from_str(define::OS_FINGERPRINT_JSON).unwrap_or(vec![]);
    ds_os_fingerprints
}
