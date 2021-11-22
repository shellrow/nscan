use std::net::IpAddr;
use std::time::Duration;
use std::collections::HashMap;
use netscan_os::prober::{Prober};
use netscan_os::setting::{ProbeType, Destination};
use netscan_os::result::ProbeResult;
use crate::model::OSFingerprint;
use crate::db;

const DEFAULT_ICMP_UNREACH_IP_LEN: u16 = 80;
const DEFAULT_IP_ID: u16 = 4162;

const TCP_OPTION_POINT: u8 = 8;
const TCP_WINDOW_SIZE_POINT: u8 = 4;
const IP_TTL_POINT: u8 = 4;
const ICMP_ECHO_IP_DF_POINT: u8 = 2;
const ICMP_UNREACH_IP_LEN_POINT: u8 = 2;

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
                fingerprint.icmp_ip_ttl = r.ip_ttl;
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
                fingerprint.tcp_ip_ttl = r.ip_ttl;
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

fn guess_os(probe_result: ProbeResult) -> (String, String) {
    let mdb: Vec<OSFingerprint> = db::get_os_fingerprints();
    let fingerprint: OSFingerprint = convert_probe_result(probe_result);
    // Check exact match
    if let Some(r) = simple_exact_match(&fingerprint, &mdb){
        return r;
    }
    let mut os_map: HashMap<String, u8> = create_os_map(&mdb);
    // Check TCP Options
    check_tcp_option_order(&fingerprint, &mdb, &mut os_map);
    
    // TODO

    return (String::new(), String::new())
}

pub fn default_os_fingerprinting(src_ip: IpAddr, hosts: Vec<IpAddr>) -> HashMap<IpAddr, (String, String)> {
    let map: HashMap<IpAddr, (String, String)> = HashMap::new();
    let mut prober = Prober::new(src_ip).unwrap();
    prober.set_wait_time(Duration::from_millis(200));
    prober.add_probe_type(ProbeType::IcmpEchoProbe);
    prober.add_probe_type(ProbeType::IcmpTimestampProbe);
    prober.add_probe_type(ProbeType::IcmpAddressMaskProbe);
    prober.add_probe_type(ProbeType::IcmpInformationProbe);
    prober.add_probe_type(ProbeType::IcmpUnreachableProbe);
    prober.add_probe_type(ProbeType::TcpSynAckProbe);
    prober.add_probe_type(ProbeType::TcpRstAckProbe);
    prober.add_probe_type(ProbeType::TcpEcnProbe);
    for host in hosts {
        let dst: Destination = Destination {
            ip_addr: host,
            open_tcp_ports: vec![80,22],
            closed_tcp_port: 443,
            open_udp_port: 161,
            closed_udp_port: 33455,
        };
        prober.add_dst_info(dst);
    }
    prober.run_probe();
    /* for result in prober.get_probe_results() {
        println!("{}", result.ip_addr);
        println!("{:?}", result.icmp_echo_result);
        println!("{:?}", result.icmp_timestamp_result);
        println!("{:?}", result.icmp_address_mask_result);
        println!("{:?}", result.icmp_information_result);
        println!("{:?}", result.icmp_unreachable_ip_result);
        println!("{:?}", result.icmp_unreachable_data_result);
        println!("{:?}", result.tcp_syn_ack_result);
        println!("{:?}", result.tcp_rst_ack_result);
        println!("{:?}", result.tcp_ecn_result);
        println!("{:?}", result.tcp_header_result);
        println!();
    } */
    return map;
}

pub fn os_fingerprinting(src_ip: IpAddr, dst_ip: IpAddr, open_ports: Vec<u16>, closed_ports: u16) {
    let mut prober = Prober::new(src_ip).unwrap();
    prober.set_wait_time(Duration::from_millis(200));
    prober.add_probe_type(ProbeType::IcmpEchoProbe);
    prober.add_probe_type(ProbeType::IcmpTimestampProbe);
    prober.add_probe_type(ProbeType::IcmpAddressMaskProbe);
    prober.add_probe_type(ProbeType::IcmpInformationProbe);
    prober.add_probe_type(ProbeType::IcmpUnreachableProbe);
    prober.add_probe_type(ProbeType::TcpSynAckProbe);
    prober.add_probe_type(ProbeType::TcpRstAckProbe);
    prober.add_probe_type(ProbeType::TcpEcnProbe);
    let dst: Destination = Destination {
        ip_addr: dst_ip,
        open_tcp_ports: open_ports,
        closed_tcp_port: closed_ports,
        open_udp_port: 161,
        closed_udp_port: 33455,
    };
    prober.add_dst_info(dst);
    prober.run_probe();
}

