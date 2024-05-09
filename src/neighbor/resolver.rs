use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use netdev::interface::Interface;
use nex::datalink::{FrameReceiver, FrameSender};
use nex::packet::arp::ArpOperation;
use nex::packet::frame::{Frame, ParseOption};
use nex::packet::icmpv6::Icmpv6Type;

use crate::host::NodeType;
use crate::packet::setting::PacketBuildSetting;
use crate::probe::{ProbeResult, ProbeStatus};
use crate::protocol::Protocol;
use super::result::DeviceResolveResult;
use super::setting::AddressResolveSetting;

/// Device Resolver structure.
///
/// Supports ARP and NDP.
pub struct DeviceResolver {
    /// Probe Setting
    pub probe_setting: AddressResolveSetting,
    /// Sender for progress messaging
    tx: Arc<Mutex<Sender<ProbeResult>>>,
    /// Receiver for progress messaging
    rx: Arc<Mutex<Receiver<ProbeResult>>>,
}

impl DeviceResolver {
    /// Create new DeviceResolver instance with setting
    pub fn new(setting: AddressResolveSetting) -> Result<DeviceResolver, String> {
        // Check interface
        if crate::interface::get_interface_by_index(setting.if_index).is_none() {
            return Err(format!(
                "Pinger::new: unable to get interface. index: {}",
                setting.if_index
            ));
        }
        let (tx, rx) = channel();
        let pinger = DeviceResolver {
            probe_setting: setting,
            tx: Arc::new(Mutex::new(tx)),
            rx: Arc::new(Mutex::new(rx)),
        };
        return Ok(pinger);
    }
    /// Run arp/ndp
    pub fn resolve(&self) -> Result<DeviceResolveResult, String> {
        run_resolver(&self.probe_setting, &self.tx)
    }
    /// Get progress receiver
    pub fn get_progress_receiver(&self) -> Arc<Mutex<Receiver<ProbeResult>>> {
        self.rx.clone()
    }
}

fn run_resolver(
    setting: &AddressResolveSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> Result<DeviceResolveResult, String> {
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
        crate::protocol::Protocol::ARP => {
            let result = run_arp(&mut tx, &mut rx, setting, msg_tx);
            return Ok(result);
        }
        crate::protocol::Protocol::NDP => {
            let result = run_ndp(&mut tx, &mut rx, setting, msg_tx);
            return Ok(result);
        }
        _ => {
            return Err("run_ping: unsupported protocol".to_string());
        }
    }
}

pub(crate) fn run_arp(
    tx: &mut Box<dyn FrameSender>,
    rx: &mut Box<dyn FrameReceiver>,
    setting: &AddressResolveSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> DeviceResolveResult {
    let mut result = DeviceResolveResult::new();
    result.protocol = Protocol::ARP;
    let mut parse_option: ParseOption = ParseOption::default();
    if setting.tunnel {
        let payload_offset = if setting.loopback { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    result.start_time = crate::sys::time::get_sysdate();
    let start_time = Instant::now();
    let mut responses: Vec<ProbeResult> = Vec::new();
    let packet_setting: PacketBuildSetting = PacketBuildSetting::from_address_resolve_settomg(setting);
    let arp_packet: Vec<u8> = crate::packet::arp::build_arp_packet(packet_setting.clone());
    for seq in 1..setting.count + 1 {
        let send_time = Instant::now();
        match tx.send(&arp_packet) {
            Some(_) => {}
            None => {},
        }
        loop {
            match rx.next() {
                Ok(packet) => {
                    let recv_time: Duration = Instant::now().duration_since(send_time);
                    let frame: Frame = Frame::from_bytes(&packet, parse_option.clone());
                    // Datalink
                    if let Some(datalink_layer) = &frame.datalink {
                        // Ethernet
                        if let Some(_ethernet_header) = &datalink_layer.ethernet {
                            // ARP
                            if let Some(arp_header) = &datalink_layer.arp {
                                if IpAddr::V4(arp_header.sender_proto_addr) != setting.dst_ip || IpAddr::V4(arp_header.target_proto_addr) != packet_setting.src_ip {
                                    continue;
                                }
                                if arp_header.operation == ArpOperation::Reply {
                                    let probe_result: ProbeResult = ProbeResult {
                                        seq: seq,
                                        mac_addr: arp_header.sender_hw_addr,
                                        ip_addr: setting.dst_ip,
                                        host_name: setting.dst_hostname.clone(),
                                        port_number: None,
                                        port_status: None,
                                        ttl: 0,
                                        hop: 0,
                                        rtt: recv_time,
                                        probe_status: ProbeStatus::new(),
                                        protocol: Protocol::ARP,
                                        node_type: NodeType::Destination,
                                        sent_packet_size: arp_packet.len(),
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
                        Protocol::ARP,
                        arp_packet.len(),
                    );
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
                    Protocol::ARP,
                    arp_packet.len(),
                );
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
    if responses.len() > 0 {
        result.probe_status = ProbeStatus::new();
    } else {
        result.probe_status = ProbeStatus::with_error_message("No response".to_string());
    }
    result.results = responses;
    result
}

pub(crate) fn run_ndp(
    tx: &mut Box<dyn FrameSender>,
    rx: &mut Box<dyn FrameReceiver>,
    setting: &AddressResolveSetting,
    msg_tx: &Arc<Mutex<Sender<ProbeResult>>>,
) -> DeviceResolveResult {
    let mut result = DeviceResolveResult::new();
    result.protocol = Protocol::NDP;
    let mut parse_option: ParseOption = ParseOption::default();
    if setting.tunnel {
        let payload_offset = if setting.loopback { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    result.start_time = crate::sys::time::get_sysdate();
    let start_time = Instant::now();
    let mut responses: Vec<ProbeResult> = Vec::new();
    let packet_setting: PacketBuildSetting = PacketBuildSetting::from_address_resolve_settomg(setting);
    let ndp_packet: Vec<u8> = crate::packet::ndp::build_ndp_packet(packet_setting.clone());
    for seq in 1..setting.count + 1 {
        let send_time = Instant::now();
        match tx.send(&ndp_packet) {
            Some(_) => {}
            None => {},
        }
        loop {
            match rx.next() {
                Ok(packet) => {
                    let recv_time: Duration = Instant::now().duration_since(send_time);
                    let frame: Frame = Frame::from_bytes(&packet, parse_option.clone());
                    // Datalink
                    if let Some(datalink_layer) = &frame.datalink {
                        // Ethernet
                        if let Some(ethernet_header) = &datalink_layer.ethernet {
                            if let Some(ip_layer) = &frame.ip {
                                // IPv6
                                if let Some(ipv6_header) = &ip_layer.ipv6 {
                                    if IpAddr::V6(ipv6_header.source) != setting.dst_ip || IpAddr::V6(ipv6_header.destination) != packet_setting.src_ip {
                                        continue;
                                    }
                                    // ICMPv6
                                    if let Some(icmpv6_header) = &ip_layer.icmpv6 {
                                        if icmpv6_header.icmpv6_type
                                            == Icmpv6Type::NeighborAdvertisement
                                        {
                                            let probe_result: ProbeResult = ProbeResult {
                                                seq: seq,
                                                mac_addr: ethernet_header.source,
                                                ip_addr: setting.dst_ip,
                                                host_name: setting.dst_hostname.clone(),
                                                port_number: None,
                                                port_status: None,
                                                ttl: ipv6_header.hop_limit,
                                                hop: crate::ip::guess_initial_ttl(
                                                    ipv6_header.hop_limit,
                                                ) - ipv6_header.hop_limit,
                                                rtt: recv_time,
                                                probe_status: ProbeStatus::new(),
                                                protocol: Protocol::NDP,
                                                node_type: NodeType::Destination,
                                                sent_packet_size: ndp_packet.len(),
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
                    }
                }
                Err(_e) => {
                    let probe_result = ProbeResult::timeout(
                        seq,
                        setting.dst_ip,
                        setting.dst_hostname.clone(),
                        Protocol::NDP,
                        ndp_packet.len(),
                    );
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
                    Protocol::NDP,
                    ndp_packet.len(),
                );
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
    if responses.len() > 0 {
        result.probe_status = ProbeStatus::new();
    } else {
        result.probe_status = ProbeStatus::with_error_message("No response".to_string());
    }
    result.results = responses;
    result
}
