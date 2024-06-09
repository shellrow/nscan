use super::result::{PingResult, PingStat};
use crate::probe::{ProbeResult, ProbeStatus, ProbeStatusKind};
use crate::packet::setting::PacketBuildSetting;
use crate::protocol::Protocol;
use crate::host::{PortStatus, NodeType};
use super::setting::PingSetting;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use netdev::Interface;
use nex::datalink::{RawReceiver, RawSender};
use nex::net::mac::MacAddr;
use nex::packet::frame::{Frame, ParseOption};
use nex::packet::icmp::IcmpType;
use nex::packet::icmpv6::Icmpv6Type;
use nex::packet::tcp::TcpFlags;

/// Pinger structure.
///
/// Supports ICMP Ping, TCP Ping, UDP Ping.
#[derive(Clone, Debug)]
pub struct Pinger {
    /// Probe Setting
    pub ping_setting: PingSetting,
    /// Sender for progress messaging
    tx: Arc<Mutex<Sender<ProbeResult>>>,
    /// Receiver for progress messaging
    rx: Arc<Mutex<Receiver<ProbeResult>>>,
}

impl Pinger {
    /// Create new Pinger instance with destination IP address
    pub fn new(setting: PingSetting) -> Result<Pinger, String> {
        // Check interface
        if crate::interface::get_interface_by_index(setting.if_index).is_none() {
            return Err(format!(
                "Pinger::new: unable to get interface. index: {}",
                setting.if_index
            ));
        }
        let (tx, rx) = channel();
        let pinger = Pinger {
            ping_setting: setting,
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        };
        return Ok(pinger);
    }
    /// Run ping
    pub fn ping(&self) -> Result<PingResult, String> {
        run_ping(&self.ping_setting, &self.tx)
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<ProbeResult>>> {
        self.rx.clone()
    }
}

fn run_ping(
    setting: &PingSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> Result<PingResult, String> {
    let interface: Interface = match crate::interface::get_interface_by_index(setting.if_index) {
        Some(interface) => interface,
        None => {
            return Err(format!(
                "run_ping: unable to get interface by index {}",
                setting.if_index
            ))
        }
    };
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(setting.receive_timeout),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    // Create a channel to send/receive packet
    let (mut tx, mut rx) = match nex::datalink::channel(&interface, config) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("run_ping: unable to create channel".to_string()),
        Err(e) => return Err(format!("run_ping: unable to create channel: {}", e)),
    };
    match setting.protocol {
        crate::protocol::Protocol::ICMP => {
            let result = icmp_ping(&mut tx, &mut rx, setting, msg_tx);
            return Ok(result);
        }
        crate::protocol::Protocol::TCP => {
            let result = tcp_ping(&mut tx, &mut rx, setting, msg_tx);
            return Ok(result);
        }
        crate::protocol::Protocol::UDP => {
            let result = udp_ping(&mut tx, &mut rx, setting, msg_tx);
            return Ok(result);
        }
        _ => {
            return Err("run_ping: unsupported protocol".to_string());
        }
    }
}

pub fn icmp_ping(
    tx: &mut Box<dyn RawSender>,
    rx: &mut Box<dyn RawReceiver>,
    setting: &PingSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> PingResult {
    let mut result = PingResult::new();
    result.protocol = Protocol::ICMP;
    let mut parse_option: ParseOption = ParseOption::default();
    if setting.tunnel {
        let payload_offset = if setting.loopback { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    result.start_time = crate::sys::time::get_sysdate();
    let start_time = Instant::now();
    let mut responses: Vec<ProbeResult> = Vec::new();
    let packet_setting: PacketBuildSetting = PacketBuildSetting::from_ping_setting(setting);
    let icmp_packet: Vec<u8> = crate::packet::icmp::build_icmp_packet(packet_setting.clone());
    for seq in 1..setting.count + 1 {
        //let icmp_packet: Vec<u8> = crate::packet::icmp::build_icmp_packet(PacketBuildSetting::from_ping_setting(setting));
        let send_time = Instant::now();
        match tx.send(&icmp_packet) {
            Some(_) => {}
            None => {},
        }
        loop {
            match rx.next() {
                Ok(packet) => {
                    let recv_time: Duration = Instant::now().duration_since(send_time);
                    let frame: Frame = Frame::from_bytes(&packet, parse_option.clone());
                    // Datalink
                    let mut mac_addr: MacAddr = MacAddr::zero();
                    if let Some(datalink_layer) = &frame.datalink {
                        // Ethernet
                        if let Some(ethernet_header) = &datalink_layer.ethernet {
                            mac_addr = ethernet_header.source;
                        }
                    }
                    if let Some(ip_layer) = &frame.ip {
                        // IPv4
                        if let Some(ipv4_header) = &ip_layer.ipv4 {
                            if IpAddr::V4(ipv4_header.source) != setting.dst_ip || IpAddr::V4(ipv4_header.destination) != packet_setting.src_ip {
                                continue;
                            }
                            // IPv4 ICMP
                            if let Some(icmp_header) = &ip_layer.icmp {
                                if icmp_header.icmp_type == IcmpType::EchoReply {
                                    let probe_result: ProbeResult = ProbeResult {
                                        seq: seq,
                                        mac_addr: mac_addr,
                                        ip_addr: setting.dst_ip,
                                        host_name: setting.dst_hostname.clone(),
                                        port_number: None,
                                        port_status: None,
                                        ttl: ipv4_header.ttl,
                                        hop: crate::ip::guess_initial_ttl(ipv4_header.ttl)
                                            - ipv4_header.ttl,
                                        rtt: recv_time,
                                        probe_status: ProbeStatus::new(),
                                        protocol: Protocol::ICMP,
                                        node_type: NodeType::Destination,
                                        sent_packet_size: icmp_packet.len(),
                                        received_packet_size: packet.len(),
                                    };
                                    responses.push(probe_result.clone());
                                    match msg_tx.lock() {
                                        Ok(lr) => match lr.send(probe_result) {
                                            Ok(_) => {}
                                            Err(_) => {}
                                        },
                                        Err(_) => {}
                                    }
                                    break;
                                }
                            }
                        }
                        // IPv6
                        if let Some(ipv6_header) = &ip_layer.ipv6 {
                            if IpAddr::V6(ipv6_header.source) != setting.dst_ip || IpAddr::V6(ipv6_header.destination) != packet_setting.src_ip {
                                continue;
                            }
                            // ICMPv6
                            if let Some(icmpv6_header) = &ip_layer.icmpv6 {
                                if icmpv6_header.icmpv6_type == Icmpv6Type::EchoReply {
                                    let probe_result: ProbeResult = ProbeResult {
                                        seq: seq,
                                        mac_addr: mac_addr,
                                        ip_addr: setting.dst_ip,
                                        host_name: setting.dst_hostname.clone(),
                                        port_number: None,
                                        port_status: None,
                                        ttl: ipv6_header.hop_limit,
                                        hop: crate::ip::guess_initial_ttl(ipv6_header.hop_limit)
                                            - ipv6_header.hop_limit,
                                        rtt: recv_time,
                                        probe_status: ProbeStatus::new(),
                                        protocol: Protocol::ICMP,
                                        node_type: NodeType::Destination,
                                        sent_packet_size: icmp_packet.len(),
                                        received_packet_size: packet.len(),
                                    };
                                    responses.push(probe_result.clone());
                                    match msg_tx.lock() {
                                        Ok(lr) => match lr.send(probe_result) {
                                            Ok(_) => {}
                                            Err(_) => {}
                                        },
                                        Err(_) => {}
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(_e) => {
                    let probe_result = ProbeResult::timeout(
                        seq,
                        setting.dst_ip,
                        setting.dst_hostname.clone(),
                        Protocol::ICMP,
                        icmp_packet.len(),
                    );
                    responses.push(probe_result.clone());
                    match msg_tx.lock() {
                        Ok(lr) => match lr.send(probe_result) {
                            Ok(_) => {}
                            Err(_) => {}
                        },
                        Err(_) => {}
                    }
                    break;
                }
            }
            let wait_time: Duration = Instant::now().duration_since(send_time);
            if wait_time > setting.receive_timeout {
                let probe_result = ProbeResult::timeout(
                    seq,
                    setting.dst_ip,
                    setting.dst_hostname.clone(),
                    Protocol::ICMP,
                    icmp_packet.len(),
                );
                responses.push(probe_result.clone());
                match msg_tx.lock() {
                    Ok(lr) => match lr.send(probe_result) {
                        Ok(_) => {}
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
                break;
            }
        }
        if seq < setting.count {
            std::thread::sleep(setting.send_rate);
        }
    }
    let probe_time = Instant::now().duration_since(start_time);
    result.end_time = crate::sys::time::get_sysdate();
    result.elapsed_time = probe_time;
    let received_count: usize = responses
        .iter()
        .filter(|r| r.probe_status.kind == ProbeStatusKind::Done)
        .count();
    if received_count == 0 {
        result.probe_status = ProbeStatus::with_error_message("No response".to_string());
    }else {
        let ping_stat: PingStat = PingStat {
            responses: responses.clone(),
            probe_time: probe_time,
            transmitted_count: setting.count as usize,
            received_count: received_count,
            min: responses
                .iter()
                .map(|r| r.rtt)
                .min()
                .unwrap_or(Duration::from_millis(0)),
            avg: responses
                .iter()
                .fold(Duration::from_millis(0), |acc, r| acc + r.rtt)
                / received_count as u32,
            max: responses
                .iter()
                .map(|r| r.rtt)
                .max()
                .unwrap_or(Duration::from_millis(0)),
        };
        result.stat = ping_stat;
        result.probe_status = ProbeStatus::new();
    }
    result
}

pub fn tcp_ping(
    tx: &mut Box<dyn RawSender>,
    rx: &mut Box<dyn RawReceiver>,
    setting: &PingSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> PingResult {
    let mut result = PingResult::new();
    result.protocol = Protocol::ICMP;
    let mut parse_option: ParseOption = ParseOption::default();
    if setting.tunnel {
        let payload_offset = if setting.loopback { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    result.start_time = crate::sys::time::get_sysdate();
    let start_time = Instant::now();
    let mut responses: Vec<ProbeResult> = Vec::new();
    let packet_setting: PacketBuildSetting = PacketBuildSetting::from_ping_setting(setting);
    let tcp_packet: Vec<u8> = crate::packet::tcp::build_tcp_syn_packet(packet_setting.clone());
    for seq in 1..setting.count + 1 {
        //let tcp_packet: Vec<u8> = crate::packet::tcp::build_tcp_packet(setting.clone(), None);
        let send_time = Instant::now();
        match tx.send(&tcp_packet) {
            Some(_) => {}
            None => {},
        }
        loop {
            match rx.next() {
                Ok(packet) => {
                    let recv_time: Duration = Instant::now().duration_since(send_time);
                    let frame: Frame = Frame::from_bytes(&packet, parse_option.clone());
                    // Datalink
                    let mut mac_addr: MacAddr = MacAddr::zero();
                    if let Some(datalink_layer) = &frame.datalink {
                        // Ethernet
                        if let Some(ethernet_header) = &datalink_layer.ethernet {
                            mac_addr = ethernet_header.source;
                        }
                    }
                    // So deep nested... but this is simplest way to check TCP packet safely.
                    if let Some(ip_layer) = &frame.ip {
                        if let Some(ipv4_header) = &ip_layer.ipv4 {
                            if IpAddr::V4(ipv4_header.source) != setting.dst_ip || IpAddr::V4(ipv4_header.destination) != packet_setting.src_ip {
                                continue;
                            }
                        }
                        if let Some(ipv6_header) = &ip_layer.ipv6 {
                            if IpAddr::V6(ipv6_header.source) != setting.dst_ip || IpAddr::V6(ipv6_header.destination) != packet_setting.src_ip {
                                continue;
                            }
                        }
                        if let Some(transport_layer) = &frame.transport {
                            if let Some(tcp_header) = &transport_layer.tcp {
                                if let Some(port) = setting.dst_port {
                                    if tcp_header.source != port {
                                        continue;
                                    }
                                }
                                let mut probe_result: ProbeResult = ProbeResult {
                                    seq: seq,
                                    mac_addr: mac_addr,
                                    ip_addr: setting.dst_ip,
                                    host_name: setting.dst_hostname.clone(),
                                    port_number: Some(tcp_header.source),
                                    port_status: None,
                                    ttl: 0,
                                    hop: 0,
                                    rtt: recv_time,
                                    probe_status: ProbeStatus::new(),
                                    protocol: Protocol::TCP,
                                    node_type: NodeType::Destination,
                                    sent_packet_size: tcp_packet.len(),
                                    received_packet_size: packet.len(),
                                };
                                if tcp_header.flags == TcpFlags::SYN | TcpFlags::ACK {
                                    probe_result.port_status = Some(PortStatus::Open);
                                    if let Some(ipv4) = &ip_layer.ipv4 {
                                        if IpAddr::V4(ipv4.source) != setting.dst_ip {
                                            continue;
                                        }
                                        probe_result.ttl = ipv4.ttl;
                                        probe_result.hop =
                                            crate::ip::guess_initial_ttl(ipv4.ttl) - ipv4.ttl;
                                    } else if let Some(ipv6) = &ip_layer.ipv6 {
                                        if IpAddr::V6(ipv6.source) != setting.dst_ip {
                                            continue;
                                        }
                                        probe_result.ttl = ipv6.hop_limit;
                                        probe_result.hop =
                                            crate::ip::guess_initial_ttl(ipv6.hop_limit)
                                                - ipv6.hop_limit;
                                    }
                                    responses.push(probe_result.clone());
                                    match msg_tx.lock() {
                                        Ok(lr) => match lr.send(probe_result) {
                                            Ok(_) => {}
                                            Err(_) => {}
                                        },
                                        Err(_) => {}
                                    }
                                    break;
                                } else if tcp_header.flags == TcpFlags::RST | TcpFlags::ACK {
                                    probe_result.port_status = Some(PortStatus::Closed);
                                    if let Some(ipv4) = &ip_layer.ipv4 {
                                        if IpAddr::V4(ipv4.source) != setting.dst_ip {
                                            continue;
                                        }
                                        probe_result.ttl = ipv4.ttl;
                                        probe_result.hop =
                                            crate::ip::guess_initial_ttl(ipv4.ttl) - ipv4.ttl;
                                    } else if let Some(ipv6) = &ip_layer.ipv6 {
                                        if IpAddr::V6(ipv6.source) != setting.dst_ip {
                                            continue;
                                        }
                                        probe_result.ttl = ipv6.hop_limit;
                                        probe_result.hop =
                                            crate::ip::guess_initial_ttl(ipv6.hop_limit)
                                                - ipv6.hop_limit;
                                    }
                                    responses.push(probe_result.clone());
                                    match msg_tx.lock() {
                                        Ok(lr) => match lr.send(probe_result) {
                                            Ok(_) => {}
                                            Err(_) => {}
                                        },
                                        Err(_) => {}
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(_e) => {
                    let mut probe_result = ProbeResult::timeout(
                        seq,
                        setting.dst_ip,
                        setting.dst_hostname.clone(),
                        Protocol::TCP,
                        tcp_packet.len(),
                    );
                    probe_result.port_number = setting.dst_port;
                    responses.push(probe_result.clone());
                    match msg_tx.lock() {
                        Ok(lr) => match lr.send(probe_result) {
                            Ok(_) => {}
                            Err(_) => {}
                        },
                        Err(_) => {}
                    }
                    break;
                }
            }
            let wait_time: Duration = Instant::now().duration_since(send_time);
            if wait_time > setting.receive_timeout {
                let mut probe_result = ProbeResult::timeout(
                    seq,
                    setting.dst_ip,
                    setting.dst_hostname.clone(),
                    Protocol::TCP,
                    tcp_packet.len(),
                );
                probe_result.port_number = setting.dst_port;
                responses.push(probe_result.clone());
                match msg_tx.lock() {
                    Ok(lr) => match lr.send(probe_result) {
                        Ok(_) => {}
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
                break;
            }
        }
        if seq < setting.count {
            std::thread::sleep(setting.send_rate);
        }
    }
    let probe_time = Instant::now().duration_since(start_time);
    result.end_time = crate::sys::time::get_sysdate();
    result.elapsed_time = probe_time;
    let received_count: usize = responses
        .iter()
        .filter(|r| r.probe_status.kind == ProbeStatusKind::Done)
        .count();
    if received_count == 0 {
        result.probe_status = ProbeStatus::with_error_message("No response".to_string());
    }else {
        let ping_stat: PingStat = PingStat {
            responses: responses.clone(),
            probe_time: probe_time,
            transmitted_count: setting.count as usize,
            received_count: received_count,
            min: responses
                .iter()
                .map(|r| r.rtt)
                .min()
                .unwrap_or(Duration::from_millis(0)),
            avg: responses
                .iter()
                .fold(Duration::from_millis(0), |acc, r| acc + r.rtt)
                / received_count as u32,
            max: responses
                .iter()
                .map(|r| r.rtt)
                .max()
                .unwrap_or(Duration::from_millis(0)),
        };
        result.stat = ping_stat;
        result.probe_status = ProbeStatus::new();
    }
    result
}

pub fn udp_ping(
    tx: &mut Box<dyn RawSender>,
    rx: &mut Box<dyn RawReceiver>,
    setting: &PingSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> PingResult {
    let mut result = PingResult::new();
    result.protocol = Protocol::UDP;
    let mut parse_option: ParseOption = ParseOption::default();
    if setting.tunnel {
        let payload_offset = if setting.loopback { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    result.start_time = crate::sys::time::get_sysdate();
    let start_time = Instant::now();
    let mut responses: Vec<ProbeResult> = Vec::new();
    let packet_setting: PacketBuildSetting = PacketBuildSetting::from_ping_setting(setting);
    let udp_packet: Vec<u8> = crate::packet::udp::build_udp_packet(packet_setting.clone());
    for seq in 1..setting.count + 1 {
        //let udp_packet: Vec<u8> = crate::packet::udp::build_udp_packet(setting.clone(), None);
        let send_time = Instant::now();
        match tx.send(&udp_packet) {
            Some(_) => {}
            None => {},
        }
        loop {
            match rx.next() {
                Ok(packet) => {
                    let recv_time: Duration = Instant::now().duration_since(send_time);
                    let frame: Frame = Frame::from_bytes(&packet, parse_option.clone());
                    // Datalink
                    let mut mac_addr: MacAddr = MacAddr::zero();
                    if let Some(datalink_layer) = &frame.datalink {
                        // Ethernet
                        if let Some(ethernet_header) = &datalink_layer.ethernet {
                            mac_addr = ethernet_header.source;
                        }
                    }
                    if let Some(ip_layer) = &frame.ip {
                        // IPv4
                        if let Some(ipv4_header) = &ip_layer.ipv4 {
                            if IpAddr::V4(ipv4_header.source) != setting.dst_ip || IpAddr::V4(ipv4_header.destination) != packet_setting.src_ip {
                                continue;
                            }
                            // ICMP
                            if let Some(icmp_header) = &ip_layer.icmp {
                                if icmp_header.icmp_type == IcmpType::DestinationUnreachable {
                                    let probe_result: ProbeResult = ProbeResult {
                                        seq: seq,
                                        mac_addr: mac_addr,
                                        ip_addr: setting.dst_ip,
                                        host_name: setting.dst_hostname.clone(),
                                        port_number: setting.dst_port,
                                        port_status: Some(PortStatus::Closed),
                                        ttl: ipv4_header.ttl,
                                        hop: crate::ip::guess_initial_ttl(ipv4_header.ttl)
                                            - ipv4_header.ttl,
                                        rtt: recv_time,
                                        probe_status: ProbeStatus::new(),
                                        protocol: Protocol::UDP,
                                        node_type: NodeType::Destination,
                                        sent_packet_size: udp_packet.len(),
                                        received_packet_size: packet.len(),
                                    };
                                    responses.push(probe_result.clone());
                                    match msg_tx.lock() {
                                        Ok(lr) => match lr.send(probe_result) {
                                            Ok(_) => {}
                                            Err(_) => {}
                                        },
                                        Err(_) => {}
                                    }
                                    break;
                                }
                            }
                        }
                        // IPv6
                        if let Some(ipv6_header) = &ip_layer.ipv6 {
                            if IpAddr::V6(ipv6_header.destination) != packet_setting.src_ip {
                                continue;
                            }
                            // ICMPv6
                            if let Some(icmpv6_header) = &ip_layer.icmpv6 {
                                if icmpv6_header.icmpv6_type == Icmpv6Type::DestinationUnreachable {
                                    let probe_result: ProbeResult = ProbeResult {
                                        seq: seq,
                                        mac_addr: mac_addr,
                                        ip_addr: setting.dst_ip,
                                        host_name: setting.dst_hostname.clone(),
                                        port_number: setting.dst_port,
                                        port_status: Some(PortStatus::Closed),
                                        ttl: ipv6_header.hop_limit,
                                        hop: crate::ip::guess_initial_ttl(ipv6_header.hop_limit)
                                            - ipv6_header.hop_limit,
                                        rtt: recv_time,
                                        probe_status: ProbeStatus::new(),
                                        protocol: Protocol::UDP,
                                        node_type: NodeType::Destination,
                                        sent_packet_size: udp_packet.len(),
                                        received_packet_size: packet.len(),
                                    };
                                    responses.push(probe_result.clone());
                                    match msg_tx.lock() {
                                        Ok(lr) => match lr.send(probe_result) {
                                            Ok(_) => {}
                                            Err(_) => {}
                                        },
                                        Err(_) => {}
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                Err(_e) => {
                    let probe_result = ProbeResult::timeout(
                        seq,
                        setting.dst_ip,
                        setting.dst_hostname.clone(),
                        Protocol::UDP,
                        udp_packet.len(),
                    );
                    responses.push(probe_result.clone());
                    match msg_tx.lock() {
                        Ok(lr) => match lr.send(probe_result) {
                            Ok(_) => {}
                            Err(_) => {}
                        },
                        Err(_) => {}
                    }
                    break;
                }
            }
            let wait_time: Duration = Instant::now().duration_since(send_time);
            if wait_time > setting.receive_timeout {
                let probe_result = ProbeResult::timeout(
                    seq,
                    setting.dst_ip,
                    setting.dst_hostname.clone(),
                    Protocol::UDP,
                    udp_packet.len(),
                );
                responses.push(probe_result.clone());
                match msg_tx.lock() {
                    Ok(lr) => match lr.send(probe_result) {
                        Ok(_) => {}
                        Err(_) => {}
                    },
                    Err(_) => {}
                }
                break;
            }
        }
        if seq < setting.count {
            std::thread::sleep(setting.send_rate);
        }
    }
    let probe_time = Instant::now().duration_since(start_time);
    result.end_time = crate::sys::time::get_sysdate();
    result.elapsed_time = probe_time;
    let received_count: usize = responses
        .iter()
        .filter(|r| r.probe_status.kind == ProbeStatusKind::Done)
        .count();
    if received_count == 0 {
        result.probe_status = ProbeStatus::with_error_message("No response".to_string());
    }else {
        let ping_stat: PingStat = PingStat {
            responses: responses.clone(),
            probe_time: probe_time,
            transmitted_count: setting.count as usize,
            received_count: received_count,
            min: responses
                .iter()
                .map(|r| r.rtt)
                .min()
                .unwrap_or(Duration::from_millis(0)),
            avg: responses
                .iter()
                .fold(Duration::from_millis(0), |acc, r| acc + r.rtt)
                / received_count as u32,
            max: responses
                .iter()
                .map(|r| r.rtt)
                .max()
                .unwrap_or(Duration::from_millis(0)),
        };
        result.stat = ping_stat;
        result.probe_status = ProbeStatus::new();
    }
    result
}
