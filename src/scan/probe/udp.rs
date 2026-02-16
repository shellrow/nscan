use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::capture::pcap::PacketCaptureOptions;
use crate::endpoint::{EndpointResult, OsGuess};
use crate::{
    config::default::DEFAULT_BASE_TARGET_UDP_PORT, output::ScanResult, probe::ProbeSetting,
};
use anyhow::Result;
use futures::future::poll_fn;
use netdev::{Interface, MacAddr};
use nex::datalink::async_io::{async_channel, AsyncChannel, AsyncRawSender};
use nex::packet::frame::Frame;
use nex::packet::ip::IpNextProtocol;
use tracing_indicatif::span_ext::IndicatifSpanExt;

/// Send UDP packets for host scanning.
pub async fn send_hostscan_packets(
    tx: &mut Box<dyn AsyncRawSender>,
    interface: &Interface,
    scan_setting: &ProbeSetting,
) {
    let header_span = tracing::info_span!("udp_host_scan");
    header_span.pb_set_style(&crate::output::progress::get_progress_style());
    header_span.pb_set_message("HostScan");
    header_span.pb_set_length(scan_setting.target_endpoints.len() as u64);
    header_span.pb_set_position(0);
    header_span.pb_start();

    for target in &scan_setting.target_endpoints {
        let packet = crate::packet::udp::build_udp_packet(
            &interface,
            target.ip,
            DEFAULT_BASE_TARGET_UDP_PORT,
            false,
        );
        // Send a packet using poll_fn.
        match poll_fn(|cx| tx.poll_send(cx, &packet)).await {
            Ok(_) => {
                if !scan_setting.send_rate.is_zero() {
                    tokio::time::sleep(scan_setting.send_rate).await;
                }
            }
            Err(e) => eprintln!("Failed to send packet: {}", e),
        }
        header_span.pb_inc(1);
    }
    drop(header_span);
}

/// Run a UDP host scan based on the provided probe settings.
pub async fn run_host_scan(setting: ProbeSetting) -> Result<ScanResult> {
    let interface = match crate::interface::get_interface_by_index(setting.if_index) {
        Some(interface) => interface,
        None => return Err(anyhow::anyhow!("Interface not found")),
    };
    // Create sender
    let config = nex::datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: Some(setting.wait_time),
        write_timeout: None,
        channel_type: nex::datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
    };

    let AsyncChannel::Ethernet(mut tx, mut rx) = async_channel(&interface, config)? else {
        unreachable!();
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
        capture_timeout: setting.task_timeout,
        read_timeout: setting.wait_time,
        promiscuous: false,
        receive_undefined: false,
        tunnel: interface.is_tun(),
        loopback: interface.is_loopback(),
    };
    for endpoint in &setting.target_endpoints {
        capture_options.src_ips.insert(endpoint.ip);
    }
    capture_options.ip_protocols.insert(IpNextProtocol::Udp);
    capture_options.ip_protocols.insert(IpNextProtocol::Icmp);
    capture_options.ip_protocols.insert(IpNextProtocol::Icmpv6);

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();

    let capture_handle: tokio::task::JoinHandle<_> = tokio::spawn(async move {
        crate::capture::pcap::start_capture(&mut rx, capture_options, ready_tx, &mut stop_rx).await
    });

    // Wait for listener to start
    let _ = ready_rx;
    let start_time = std::time::Instant::now();
    // Send probe packets
    send_hostscan_packets(&mut tx, &interface, &setting).await;
    tokio::time::sleep(setting.wait_time).await;
    // Stop pcap
    let _ = stop_tx.send(());
    let frames = capture_handle
        .await
        .map_err(|e| anyhow::anyhow!("capture task join error: {}", e))?;
    let dns_map = setting.get_dns_map();
    let mut result = parse_hostscan_result(frames, &interface, &dns_map);
    result.scan_time = start_time.elapsed();
    Ok(result)
}

/// Parse host scan results from captured packets.
fn parse_hostscan_result(
    packets: Vec<Frame>,
    iface: &Interface,
    dns_map: &HashMap<IpAddr, String>,
) -> ScanResult {
    let if_ipv4_set: HashSet<Ipv4Addr> = iface.ipv4_addrs().into_iter().collect();
    let if_ipv6_set: HashSet<Ipv6Addr> = iface.ipv6_addrs().into_iter().collect();
    let mut result: ScanResult = ScanResult::new();
    let mut endpoint_map: HashMap<IpAddr, EndpointResult> = HashMap::new();
    for p in packets {
        if p.ip.is_none() {
            continue;
        }
        let mut mac_addr: MacAddr;
        if let Some(datalink) = &p.datalink {
            if let Some(ethernet_frame) = &datalink.ethernet {
                if ethernet_frame.destination != iface.mac_addr.unwrap_or(MacAddr::zero()) {
                    continue;
                }
                mac_addr = ethernet_frame.source;
            } else {
                mac_addr = MacAddr::zero();
            }
        } else {
            mac_addr = MacAddr::zero();
        }
        let ip_addr: IpAddr;
        let ttl: u8;
        if let Some(ip) = &p.ip {
            // Expect ICMP or ICMPv6 Port Unreachable
            if ip.icmp.is_none() && ip.icmpv6.is_none() {
                continue;
            }
            if let Some(ipv4_packet) = &ip.ipv4 {
                if if_ipv4_set.contains(&ipv4_packet.source) {
                    mac_addr = iface.mac_addr.unwrap_or(MacAddr::zero());
                    ttl = crate::util::ip::initial_ttl(ipv4_packet.ttl);
                } else {
                    ttl = ipv4_packet.ttl;
                }
                ip_addr = IpAddr::V4(ipv4_packet.source);
            } else if let Some(ipv6_packet) = &ip.ipv6 {
                if if_ipv6_set.contains(&ipv6_packet.source) {
                    mac_addr = iface.mac_addr.unwrap_or(MacAddr::zero());
                    ttl = crate::util::ip::initial_ttl(ipv6_packet.hop_limit);
                } else {
                    ttl = ipv6_packet.hop_limit;
                }
                ip_addr = IpAddr::V6(ipv6_packet.source);
            } else {
                continue;
            }
        } else {
            continue;
        }

        let vendor_name_opt = crate::db::oui::lookup_vendor_name(&mac_addr);

        endpoint_map.entry(ip_addr).or_insert(EndpointResult {
            ip: ip_addr,
            hostname: dns_map.get(&ip_addr).cloned(),
            ports: BTreeMap::new(),
            mac_addr: Some(mac_addr),
            vendor_name: vendor_name_opt,
            os: OsGuess::default().with_ttl_observed(ttl),
            tags: Vec::new(),
            cpes: Vec::new(),
        });

        result.fingerprints.push(p.clone());
    }
    for (_ip, endpoint) in endpoint_map {
        result.endpoints.push(endpoint);
    }
    result
}
