use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct OSFingerprint {
    os_name: String,
    version: String,
    icmp_echo_code: u8,
    icmp_ip_ttl: u8,
    icmp_echo_ip_df: bool,
    icmp_unreach_ip_df: bool,
    icmp_unreach_ip_len: String,
    icmp_unreach_data_ip_id_byte_order: String,
    tcp_ip_ttl: u8,
    tcp_ip_df: bool,
    tcp_window_size: Vec<u16>,
    tcp_option_order: Vec<String>,
    tcp_rst_text_payload: bool,
    tcp_ecn_support: bool,
}

pub fn guess_initial_ttl(ttl: u8) -> u8 {
    if ttl <= 64 {
        64
    }else if 64 < ttl && ttl <= 128 {
        128
    }else {
        255
    }
}
