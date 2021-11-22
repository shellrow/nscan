use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct OSFingerprint {
    pub id: String,
    pub os_name: String,
    pub version: String,
    pub icmp_echo_code: u8,
    pub icmp_ip_ttl: u8,
    pub icmp_echo_ip_df: bool,
    pub icmp_unreach_ip_df: bool,
    pub icmp_unreach_ip_len: String,
    pub icmp_unreach_data_ip_id_byte_order: String,
    pub tcp_ip_ttl: u8,
    pub tcp_ip_df: bool,
    pub tcp_window_size: Vec<u16>,
    pub tcp_option_order: Vec<String>,
    pub tcp_rst_text_payload: bool,
    pub tcp_ecn_support: bool,
}

impl OSFingerprint {
    pub fn new() -> OSFingerprint {
        OSFingerprint {
            id: String::new(),
            os_name: String::new(),
            version: String::new(),
            icmp_echo_code: 0,
            icmp_ip_ttl: 0,
            icmp_echo_ip_df: false,
            icmp_unreach_ip_df: false,
            icmp_unreach_ip_len: String::from("EQ"),
            icmp_unreach_data_ip_id_byte_order: String::from("EQ"),
            tcp_ip_ttl: 0,
            tcp_ip_df: false,
            tcp_window_size: vec![],
            tcp_option_order: vec![],
            tcp_rst_text_payload: false,
            tcp_ecn_support: false,
        }
    }
}
