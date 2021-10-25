use std::collections::HashMap;
use crate::define;

pub fn get_oui_map() -> HashMap<String, String> {
    let rs_nscan_oui: Vec<&str> = define::NSCAN_OUI.trim().split("\n").collect();
    let mut oui_map: HashMap<String, String> = HashMap::new();
    for r in rs_nscan_oui {
        let rt = r.replace(" ", "");
        let row: Vec<&str> = rt.trim().split("|").collect();
        if row.len() > 2 {
            oui_map.insert(row[1].to_string(), row[2].to_string());
        }
    }
    return oui_map;
}

pub fn get_tcp_map() -> HashMap<String, String> {
    let rs_nscan_tcp_port: Vec<&str> = define::NSCAN_TCP_PORT.trim().split("\n").collect();
    let mut tcp_map: HashMap<String, String> = HashMap::new();
    for r in rs_nscan_tcp_port {
        let rt = r.replace(" ", "");
        let row: Vec<&str> = rt.split("|").collect();
        if row.len() > 2 {
            tcp_map.insert(row[1].to_string(), row[2].to_string());
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