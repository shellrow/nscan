use std::net::IpAddr;
use std::time::Duration;
use std::collections::HashMap;
use netscan_os::prober::{Prober};
use netscan_os::setting::{ProbeType, Destination};

pub fn guess_initial_ttl(ttl: u8) -> u8 {
    if ttl <= 64 {
        64
    }else if 64 < ttl && ttl <= 128 {
        128
    }else {
        255
    }
}

pub fn default_fingerprinting(src_ip: IpAddr, hosts: Vec<IpAddr>) -> HashMap<IpAddr, (String, String)> {
    let os_map: HashMap<IpAddr, (String, String)> = HashMap::new();
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
            open_udp_port: 123,
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
    return os_map;
}
