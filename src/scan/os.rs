use crate::db::model::OsDbIndex;
use crate::fp::MatchResult;
use crate::packet::frame::PacketFrame;
use crate::pcap::PacketCaptureOptions;
use crate::scan::setting::OsProbeSetting;
use netdev::Interface;
use nex::datalink::RawSender;
use nex::packet::ip::IpNextProtocol;
use nex::packet::tcp::TcpFlags;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use anyhow::Result;

use super::packet::build_portscan_packet;

pub(crate) fn send_probe_packets(
    tx: &mut Box<dyn RawSender>,
    interface: &Interface,
    probe_setting: &OsProbeSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) {
    // Acquire message sender lock
    let ptx_lock = match ptx.lock() {
        Ok(ptx) => ptx,
        Err(e) => {
            eprintln!("Failed to lock ptx: {}", e);
            return;
        }
    };
    for port in &probe_setting.ports {
        let packet =
            build_portscan_packet(&interface, probe_setting.ip_addr, *port, false);
        match tx.send(&packet) {
            Some(_) => {
                // Notify packet sent
                match ptx_lock.send(SocketAddr::new(probe_setting.ip_addr, *port)) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("Failed to send message: {}", e);
                    }
                }
                if !probe_setting.send_rate.is_zero() {
                    thread::sleep(probe_setting.send_rate);
                }
            }
            None => {
                eprintln!("Failed to send packet");
            }
        }
    }
    // Drop message sender lock
    drop(ptx_lock);
}

pub(crate) fn run_os_probe(
    probe_setting: &OsProbeSetting,
    ptx: &Arc<Mutex<Sender<SocketAddr>>>,
) -> Result<MatchResult> {
    let interface = match crate::interface::get_interface_by_index(probe_setting.if_index) {
        Some(interface) => interface,
        None => anyhow::bail!("Interface not found with index {}", probe_setting.if_index),
    };
    // Create sender
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(probe_setting.wait_time),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };
    let (mut tx, mut rx) = match nex::datalink::channel(&interface, config) {
        Ok(nex::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => anyhow::bail!("Unsupported channel type for OS detection"),
        Err(e) => return Err(anyhow::format_err!("Failed to create channel: {}", e)),
    };
    let mut capture_options: PacketCaptureOptions = PacketCaptureOptions {
        interface_index: interface.index,
        interface_name: interface.name.clone(),
        src_ips: HashSet::new(),
        dst_ips: HashSet::new(),
        src_ports: HashSet::new(),
        dst_ports: HashSet::new(),
        ether_types: HashSet::new(),
        ip_protocols: HashSet::new(),
        capture_timeout: probe_setting.task_timeout,
        read_timeout: probe_setting.wait_time,
        promiscuous: false,
        receive_undefined: false,
        tunnel: interface.is_tun(),
        loopback: interface.is_loopback(),
    };
    capture_options.src_ips.insert(probe_setting.ip_addr);
    capture_options.src_ports.extend(probe_setting.ports.clone());
    capture_options
        .ip_protocols
        .insert(IpNextProtocol::Tcp);
    let stop: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let stop_handle = Arc::clone(&stop);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::new(Mutex::new(vec![]));
    let receive_packets: Arc<Mutex<Vec<PacketFrame>>> = Arc::clone(&packets);
    // Spawn pcap thread
    let pcap_handler = thread::spawn(move || {
        let packets: Vec<PacketFrame> =
            crate::pcap::start_capture(&mut rx, capture_options, &stop_handle);
        // Notify that pcap is ready
        match ready_tx.send(()) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("Failed to send ready signal: {:?}", e);
            }
        }
        match receive_packets.lock() {
            Ok(mut receive_packets) => {
                for p in packets {
                    receive_packets.push(p);
                }
            }
            Err(e) => {
                eprintln!("Failed to lock receive_packets: {}", e);
            }
        }
    });
    // Wait for listener to start
    let _ = ready_rx;
    // Send probe packets
    send_probe_packets(
        &mut tx,
        &interface,
        &probe_setting,
        ptx,
    );
    thread::sleep(probe_setting.wait_time);
    // Stop pcap
    match stop.lock() {
        Ok(mut stop) => {
            *stop = true;
        }
        Err(e) => {
            eprintln!("Failed to lock stop: {}", e);
        }
    }
    // Wait for listener to stop
    match pcap_handler.join() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Failed to join pcap_handler: {:?}", e);
        }
    }
    
    let idx = OsDbIndex::from(crate::db::get_os_family_db());
    let ttl_table = crate::db::get_family_ttl_map();
    match packets.lock() {
        Ok(packets) => {
            for fingerprint in packets.iter() {
                if let Some(ipv4_packet) = &fingerprint.ipv4_header {
                    if ipv4_packet.source == probe_setting.ip_addr {
                        if let Some(tcp_packet) = &fingerprint.tcp_header {
                            if probe_setting.ports.contains(&tcp_packet.source)
                                && tcp_packet.flags == TcpFlags::SYN | TcpFlags::ACK
                            {
                                let r = crate::fp::classify(fingerprint, &idx, &ttl_table);
                                if r.family.as_str() != crate::fp::OsFamily::Unknown.as_str() {
                                    return Ok(r);
                                }
                            }
                        }
                    }
                } else if let Some(ipv6_packet) = &fingerprint.ipv6_header {
                    if ipv6_packet.source == probe_setting.ip_addr {
                        if let Some(tcp_packet) = &fingerprint.tcp_header {
                            if probe_setting.ports.contains(&tcp_packet.source)
                                && tcp_packet.flags == TcpFlags::SYN | TcpFlags::ACK
                            {
                                let r = crate::fp::classify(fingerprint, &idx, &ttl_table);
                                if r.family.as_str() != crate::fp::OsFamily::Unknown.as_str() {
                                    return Ok(r);
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to lock packets: {}", e);
        }
    }
    // If no match found, return unknown
    Ok(MatchResult {
        family: crate::fp::OsFamily::Unknown.as_str().to_string(),
        confidence: 0,
        evidence: "No matching OS fingerprint found".to_string(),
    })
}
