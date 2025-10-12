use crate::config;

/// Get default port list
pub fn get_default_ports() -> Vec<u16> {
    let default_ports: Vec<u16> = serde_json::from_str(config::db::DEFAULT_PORTS_JSON)
        .expect("Invalid default-ports.json format");
    default_ports
}

/// Get well-known port list
pub fn get_wellknown_ports() -> Vec<u16> {
    let wellknown_ports: Vec<u16> = serde_json::from_str(config::db::WELLKNOWN_PORTS_JSON)
        .expect("Invalid wellknown-ports.json format");
    wellknown_ports
}
