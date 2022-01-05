use std::net::IpAddr;
use std::time::Duration;
use std::collections::HashMap;
use netscan::os::Fingerprinter;
use netscan::os::{ProbeType, ProbeTarget};
use netscan::os::ProbeResult;
use crate::model::OSFingerprint;
use crate::db;

const DEFAULT_ICMP_UNREACH_IP_LEN: u16 = 80;
const DEFAULT_IP_ID: u16 = 4162;

const TCP_OPTION_POINT: u8 = 8;
const TCP_WINDOW_SIZE_POINT: u8 = 4;
const IP_TTL_POINT: u8 = 4;
const ICMP_ECHO_IP_DF_POINT: u8 = 2;
const ICMP_UNREACH_IP_LEN_POINT: u8 = 2;
const VALID_THRESHOLD: u8 = 10;

pub fn guess_initial_ttl(ttl: u8) -> u8 {
    if ttl <= 64 {
        64
    }else if 64 < ttl && ttl <= 128 {
        128
    }else {
        255
    }
}

fn convert_probe_result(probe_result: ProbeResult) -> OSFingerprint {
    let mut fingerprint : OSFingerprint = OSFingerprint::new();
    match probe_result.icmp_echo_result {
        Some(r) => {
            if r.icmp_echo_reply {
                fingerprint.icmp_echo_code = r.icmp_echo_code;
                fingerprint.icmp_ip_ttl = guess_initial_ttl(r.ip_ttl);
                fingerprint.icmp_echo_ip_df = r.ip_df;
            }
        },
        None => {},
    }
    match probe_result.icmp_unreachable_ip_result {
        Some(r) => {
            if r.icmp_unreachable_reply {
                fingerprint.icmp_unreach_ip_df = r.ip_df;
                if r.ip_total_length == DEFAULT_ICMP_UNREACH_IP_LEN {
                    fingerprint.icmp_unreach_ip_len = String::from("EQ");
                }else if r.ip_total_length < DEFAULT_ICMP_UNREACH_IP_LEN {
                    fingerprint.icmp_unreach_ip_len = String::from("SUB");
                }else{
                    fingerprint.icmp_unreach_ip_len = String::from("ADD");
                }
            }
        },
        None => {},
    }
    match probe_result.icmp_unreachable_data_result {
        Some(r) => {
            if r.ip_id == DEFAULT_IP_ID {
                fingerprint.icmp_unreach_data_ip_id_byte_order = String::from("EQ");
            }else{
                fingerprint.icmp_unreach_data_ip_id_byte_order = String::from("RV");
            }
        },
        None => {},
    }
    match probe_result.tcp_syn_ack_result {
        Some(r) => {
            if r.syn_ack_response {
                fingerprint.tcp_ip_ttl = guess_initial_ttl(r.ip_ttl);
                fingerprint.tcp_ip_df = r.ip_df;
            }
        },
        None => {},
    }
    match probe_result.tcp_rst_ack_result {
        Some(r) => {
            if r.rst_ack_response {
                if r.tcp_payload_size > 0 {
                    fingerprint.tcp_rst_text_payload = true;
                }
            }
        },
        None => {},
    }
    match probe_result.tcp_ecn_result {
        Some(r) => {
            if r.syn_ack_ece_response {
                fingerprint.tcp_ecn_support = true;
            }
        },
        None => {},
    }
    match probe_result.tcp_header_result {
        Some(r) => {
            fingerprint.tcp_window_size.push(r.tcp_window_size);
            let mut option_names: Vec<String> = vec![];
            for opt in r.tcp_option_order {
                option_names.push(opt.name());
            }
            fingerprint.tcp_option_order.push(option_names.join(" "));
        },
        None => {},
    }
    return fingerprint;
}

fn create_os_map(mdb: &Vec<OSFingerprint>) -> HashMap<String, u8> {
    let mut os_map: HashMap<String, u8> = HashMap::new();
    for mf in mdb {
        os_map.insert(mf.id.clone(), 0);
    }
    return os_map;
}

// TCP ECN Probe is used for version detection, so it is skipped in simple detection
fn simple_exact_match(fingerprint: &OSFingerprint, mdb: &Vec<OSFingerprint>) -> Option<(String, String)> {
    for mf in mdb {
        if fingerprint.icmp_echo_code != mf.icmp_echo_code {
            continue;
        }
        if fingerprint.icmp_ip_ttl != mf.icmp_ip_ttl {
            continue;
        }
        if fingerprint.icmp_echo_ip_df != mf.icmp_echo_ip_df {
            continue;
        }
        if fingerprint.icmp_unreach_ip_df != mf.icmp_unreach_ip_df {
            continue;
        }
        if fingerprint.icmp_unreach_ip_len != mf.icmp_unreach_ip_len {
            continue;
        }
        if fingerprint.icmp_unreach_data_ip_id_byte_order != mf.icmp_unreach_data_ip_id_byte_order {
            continue;
        }
        if fingerprint.tcp_ip_ttl != mf.tcp_ip_ttl {
            continue;
        }
        if fingerprint.tcp_ip_df != mf.tcp_ip_df {
            continue;
        }
        if fingerprint.tcp_window_size.len() > 0 {
            if !mf.tcp_window_size.contains(&fingerprint.tcp_window_size[0]) {
                continue;
            } 
        }else{
            continue;
        }
        if fingerprint.tcp_option_order.len() > 0 {
            if !mf.tcp_option_order.contains(&fingerprint.tcp_option_order[0]) {
                continue;
            } 
        }else{
            continue;
        }
        if fingerprint.tcp_rst_text_payload != mf.tcp_rst_text_payload {
            continue;
        }
        return Some((mf.os_name.clone(), mf.version.clone()));
    }
    None
}

fn check_tcp_option_order(fingerprint: &OSFingerprint, mdb: &Vec<OSFingerprint>, os_map: &mut HashMap<String, u8>) {
    if fingerprint.tcp_option_order.len() > 0 {
        for mf in mdb {
            if mf.tcp_option_order.contains(&fingerprint.tcp_option_order[0]) {
                os_map.insert(mf.id.clone(), os_map.get(&mf.id).unwrap_or(&0) + TCP_OPTION_POINT);
            }
        }
    }
}

fn check_tcp_window_size(fingerprint: &OSFingerprint, mdb: &Vec<OSFingerprint>, os_map: &mut HashMap<String, u8>) {
    if fingerprint.tcp_window_size.len() > 0 {
        for mf in mdb {
            if mf.tcp_window_size.contains(&fingerprint.tcp_window_size[0]) {
                os_map.insert(mf.id.clone(), os_map.get(&mf.id).unwrap_or(&0) + TCP_WINDOW_SIZE_POINT);
            }
        }
    }
}

fn check_ip_ttl(fingerprint: &OSFingerprint, mdb: &Vec<OSFingerprint>, os_map: &mut HashMap<String, u8>) {
    for mf in mdb {
        if fingerprint.icmp_ip_ttl == mf.icmp_ip_ttl {
            os_map.insert(mf.id.clone(), os_map.get(&mf.id).unwrap_or(&0) + IP_TTL_POINT);   
        }
    }
}

fn check_icmp_echo_ip_df(fingerprint: &OSFingerprint, mdb: &Vec<OSFingerprint>, os_map: &mut HashMap<String, u8>) {
    for mf in mdb {
        if fingerprint.icmp_echo_ip_df == mf.icmp_echo_ip_df {
            os_map.insert(mf.id.clone(), os_map.get(&mf.id).unwrap_or(&0) + ICMP_ECHO_IP_DF_POINT);   
        }
    }
}

fn check_icmp_unreach_ip_len(fingerprint: &OSFingerprint, mdb: &Vec<OSFingerprint>, os_map: &mut HashMap<String, u8>) {
    for mf in mdb {
        if fingerprint.icmp_unreach_ip_len == mf.icmp_unreach_ip_len {
            os_map.insert(mf.id.clone(), os_map.get(&mf.id).unwrap_or(&0) + ICMP_UNREACH_IP_LEN_POINT);   
        }
    }
}

fn get_max<K, V>(map: &HashMap<K, V>) -> Option<&K> where V: Ord,
{
    map.iter().max_by(|a, b| a.1.cmp(&b.1)).map(|(k, _v)| k)
}

fn guess_os(probe_result: ProbeResult) -> (String, String) {
    let mdb: Vec<OSFingerprint> = db::get_os_fingerprints();
    let fingerprint: OSFingerprint = convert_probe_result(probe_result);
    if fingerprint.icmp_ip_ttl == 0 && fingerprint.tcp_ip_ttl == 0 {
        return (String::from("Unknown"), String::from("Unknown"));
    }
    // Check exact match
    if let Some(r) = simple_exact_match(&fingerprint, &mdb){
        return r;
    }
    let mut os_map: HashMap<String, u8> = create_os_map(&mdb);
    // Check TCP Options
    check_tcp_option_order(&fingerprint, &mdb, &mut os_map);
    // Check TCP Window size
    check_tcp_window_size(&fingerprint, &mdb, &mut os_map);
    // Check IP TTL
    check_ip_ttl(&fingerprint, &mdb, &mut os_map);
    // Check ICMP Echo IP don't fragment bit
    check_icmp_echo_ip_df(&fingerprint, &mdb, &mut os_map);
    // Check ICMP Destination Unreachable IP LEN
    check_icmp_unreach_ip_len(&fingerprint, &mdb, &mut os_map);
    if let Some(os_id) = get_max(&os_map) {
        if let Some(p) = os_map.get(os_id) {
            if p < &VALID_THRESHOLD {
                return (String::from("Unknown"), String::from("Unknown"));
            }
        }
        if let Some(f) = mdb.into_iter().find(|f| f.id == os_id.to_string()) {
            return (f.os_name, f.version);
        }
    }
    return (String::from("Unknown"), String::from("Unknown"));
}

pub fn default_os_fingerprinting(src_ip: IpAddr, hosts: Vec<IpAddr>) -> HashMap<IpAddr, (String, String)> {
    let mut map: HashMap<IpAddr, (String, String)> = HashMap::new();
    let mut fingerprinter = Fingerprinter::new(src_ip).unwrap();
    fingerprinter.set_wait_time(Duration::from_millis(200));
    fingerprinter.add_probe_type(ProbeType::IcmpEchoProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpTimestampProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpAddressMaskProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpInformationProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpUnreachableProbe);
    fingerprinter.add_probe_type(ProbeType::TcpSynAckProbe);
    fingerprinter.add_probe_type(ProbeType::TcpRstAckProbe);
    fingerprinter.add_probe_type(ProbeType::TcpEcnProbe);
    for host in hosts {
        let dst: ProbeTarget = ProbeTarget {
            ip_addr: host,
            open_tcp_ports: vec![80,22],
            closed_tcp_port: 443,
            open_udp_port: 161,
            closed_udp_port: 33455,
        };
        fingerprinter.add_probe_target(dst);
    }
    fingerprinter.run_probe();
    for result in fingerprinter.get_probe_results().clone() {
        let os_tuple: (String, String) = guess_os(result.clone());
        map.insert(result.ip_addr, os_tuple);
    }
    return map;
}

pub fn os_fingerprinting(src_ip: IpAddr, dst_ip: IpAddr, open_ports: Vec<u16>, closed_ports: Vec<u16>) -> HashMap<IpAddr, (String, String)> {
    let mut map: HashMap<IpAddr, (String, String)> = HashMap::new();
    let mut fingerprinter = Fingerprinter::new(src_ip).unwrap();
    fingerprinter.set_wait_time(Duration::from_millis(200));
    fingerprinter.add_probe_type(ProbeType::IcmpEchoProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpTimestampProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpAddressMaskProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpInformationProbe);
    fingerprinter.add_probe_type(ProbeType::IcmpUnreachableProbe);
    fingerprinter.add_probe_type(ProbeType::TcpSynAckProbe);
    fingerprinter.add_probe_type(ProbeType::TcpRstAckProbe);
    fingerprinter.add_probe_type(ProbeType::TcpEcnProbe);
    let dst: ProbeTarget = ProbeTarget {
        ip_addr: dst_ip,
        open_tcp_ports: if open_ports.len() > 0 {open_ports}else{vec![80,22]},
        closed_tcp_port: if closed_ports.len() > 0 {closed_ports[0]}else{443},
        open_udp_port: 161,
        closed_udp_port: 33455,
    };
    fingerprinter.add_probe_target(dst);
    fingerprinter.run_probe();
    for result in fingerprinter.get_probe_results().clone() {
        let os_tuple: (String, String) = guess_os(result.clone());
        map.insert(result.ip_addr, os_tuple);
    }
    return map;
}

