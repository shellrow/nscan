use std::collections::HashMap;

pub const NSCAN_OUI: &str = include_str!("../../data/nscan-oui.txt");
pub const NSCAN_TCP_PORT: &str = include_str!("../../data/nscan-tcp-port.txt");

pub fn get_oui_map() -> HashMap<String, String> {
    let rs_nscan_oui: Vec<&str> = NSCAN_OUI.trim().split("\n").collect();
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
    let rs_nscan_tcp_port: Vec<&str> = NSCAN_TCP_PORT.trim().split("\n").collect();
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