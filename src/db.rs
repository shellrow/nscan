use std::collections::HashMap;
use crate::define;
use crate::model::OSFingerprint;

pub fn get_oui_map() -> HashMap<String, String> {
    let mut rs_nscan_oui: Vec<&str> = define::NSCAN_OUI.trim().split("\n").collect();
    let mut oui_map: HashMap<String, String> = HashMap::new();
    rs_nscan_oui.remove(0);
    for r in rs_nscan_oui {
        let rt = r.replace(" ", "");
        let row: Vec<&str> = rt.trim().split(",").collect();
        if row.len() >= 2 {
            oui_map.insert(row[0].to_string(), row[1].to_string());
        }
    }
    return oui_map;
}

pub fn get_tcp_map() -> HashMap<String, String> {
    let mut rs_nscan_tcp_port: Vec<&str> = define::NSCAN_TCP_PORT.trim().split("\n").collect();
    let mut tcp_map: HashMap<String, String> = HashMap::new();
    rs_nscan_tcp_port.remove(0);
    for r in rs_nscan_tcp_port {
        let rt = r.replace(" ", "");
        let row: Vec<&str> = rt.split(",").collect();
        if row.len() >= 2 {
            tcp_map.insert(row[0].to_string(), row[1].to_string());
        }
    }
    return tcp_map;
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
    return default_ports;
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
    return http_ports;
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
    return https_ports;
}

pub fn get_os_fingerprints() -> Vec<OSFingerprint> {
    let fingerprints: Vec<OSFingerprint> = serde_json::from_str(define::NSCAN_OS).unwrap_or(vec![]);    
    fingerprints
}

pub fn get_os_ttl() -> HashMap<u8, String> {
    let mut rs_nscan_os_ttl: Vec<&str> = define::NSCAN_OS_TTL.trim().split("\n").collect();
    let mut ttl_map: HashMap<u8, String> = HashMap::new();
    rs_nscan_os_ttl.remove(0);
    for r in rs_nscan_os_ttl {
        let row: Vec<&str> = r.trim().split(",").collect();
        if row.len() >= 2 {
            match row[0].parse::<u8>() {
                Ok(ttl) => {
                    ttl_map.insert(ttl, row[1].to_string());
                },
                Err(_) => {},
            }
        }
    }
    ttl_map
}
