use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Oui {
    pub mac_prefix: String,
    pub vendor_name: String,
    pub vendor_name_detail: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpService {
    pub port: u16,
    pub service_name: String,
    pub service_description: String,
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UdpService {
    pub port: u16,
    pub service_name: String,
    pub service_description: String,
    pub wellknown_flag: u32,
    pub default_flag: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsFingerprint {
    pub cpe: String,
    pub os_name: String,
    pub os_vendor: String,
    pub os_family: String,
    pub os_generation: String,
    pub device_type: String,
    pub tcp_window_size: u16,
    pub tcp_option_pattern: String,
}

impl OsFingerprint {
    pub fn new() -> OsFingerprint {
        OsFingerprint {
            cpe: String::new(),
            os_name: String::new(),
            os_vendor: String::new(),
            os_family: String::new(),
            os_generation: String::new(),
            device_type: String::new(),
            tcp_window_size: 0,
            tcp_option_pattern: String::new(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OsTtl {
    pub os_family: String,
    pub os_description: String,
    pub initial_ttl: u8,
}
