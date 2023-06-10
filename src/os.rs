use crate::models::{OsFingerprint, OsTtl};
use crate::{db, network};
use netscan::os::TcpFingerprint;

pub fn verify_os_fingerprint(fingerprint: TcpFingerprint) -> OsFingerprint {
    let mut result: OsFingerprint = OsFingerprint::new();
    if fingerprint.tcp_syn_ack_fingerprint.len() == 0 {
        return result;
    }
    let mut tcp_options: Vec<String> = vec![];
    for f in &fingerprint.tcp_syn_ack_fingerprint {
        let mut options: Vec<String> = vec![];
        f.tcp_option_order.iter().for_each(|option| {
            options.push(option.name());
        });
        tcp_options.push(options.join("-"));
    }
    let tcp_window_size: u16 = fingerprint.tcp_syn_ack_fingerprint[0].tcp_window_size;
    let tcp_option_pattern: String = tcp_options.join("|");

    // Get OS Fingerprint list
    let os_fingerprints = db::get_os_fingerprints();

    // 1. Select exact match OS fingerprint
    for f in &os_fingerprints {
        if f.tcp_window_size == tcp_window_size && f.tcp_option_pattern == tcp_option_pattern {
            return f.clone();
        }
    }
    // 2. Select OS fingerprint that have most closely tcp_option_pattern
    for f in &os_fingerprints {
        if f.tcp_window_size == tcp_window_size
            && f.tcp_option_pattern.contains(&tcp_option_pattern)
        {
            return f.clone();
        }
    }
    // 3. Select OS fingerprint that most closely approximates
    for f in os_fingerprints {
        if tcp_window_size - 100 < f.tcp_window_size
            && f.tcp_window_size < tcp_window_size + 100
            && f.tcp_option_pattern.contains(&tcp_option_pattern)
        {
            return f;
        }
    }
    // 4. from TTL
    let os_ttl_list: Vec<OsTtl> = db::get_os_ttl_list();
    let initial_ttl = network::guess_initial_ttl(fingerprint.ip_ttl);
    for os_ttl in os_ttl_list {
        if os_ttl.initial_ttl == initial_ttl {
            result.cpe = String::from("(Failed to OS Fingerprinting)");
            result.os_family = os_ttl.os_family;
            result.os_name = os_ttl.os_description;
            return result;
        }
    }
    result
}
