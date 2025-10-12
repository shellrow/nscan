use std::collections::HashSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use futures::stream::StreamExt;
use futures::future::poll_fn;
use netdev::MacAddr;
use nex::packet::frame::{Frame, ParseOption};
use nex::packet::icmp::IcmpType;
use nex::packet::icmpv6::Icmpv6Type;
use crate::endpoint::NodeType;
use crate::ping::result::PingStat;
use crate::probe::{ProbeStatus, ProbeStatusKind};
use crate::{ping::{result::PingResult, setting::PingSetting}, probe::ProbeResult, protocol::Protocol};
use anyhow::Result;
use nex::datalink::async_io::{async_channel, AsyncChannel};
use tracing_indicatif::span_ext::IndicatifSpanExt;

/// Run ICMP Ping and return the results.
pub async fn run_icmp_ping(setting: &PingSetting) -> Result<PingResult> {
    let mut result = PingResult::new();
    result.protocol = Protocol::Icmp;

    let interface = match crate::interface::get_interface_by_index(setting.if_index) {
        Some(interface) => interface,
        None => return Err(anyhow::anyhow!("Interface not found")),
    };
    let src_ip_set: HashSet<IpAddr> = interface.ip_addrs().iter().map(|ip| ip.clone()).collect();
    // Create sender
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

    let AsyncChannel::Ethernet(mut tx, mut rx) = async_channel(&interface, config)?
    else {
        unreachable!();
    };

    let mut responses: Vec<ProbeResult> = Vec::new();

    let mut parse_option: ParseOption = ParseOption::default();
    if interface.is_tun() || (cfg!(any(target_os = "macos", target_os = "ios")) && interface.is_loopback()) {
        let payload_offset = if interface.is_loopback() { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }

    let header_span = tracing::info_span!("ping");
    header_span.pb_set_style(&crate::output::progress::get_progress_style());
    header_span.pb_set_message(&format!("ping ({})", setting.dst_ip));
    header_span.pb_set_length(setting.count as u64);
    header_span.pb_set_position(0);
    header_span.pb_start();
    
    let start_time = Instant::now();
    let icmp_packet = crate::packet::icmp::build_icmp_packet(&interface, setting.dst_ip, false);
    for seq in 1..setting.count + 1 {
        let send_time = Instant::now();
        match poll_fn(|cx| tx.poll_send(cx, &icmp_packet)).await {
            Ok(_) => {
            },
            Err(e) => eprintln!("Failed to send packet: {}", e),
        }
        loop {
            match tokio::time::timeout(setting.receive_timeout, rx.next()).await {
                Ok(Some(Ok(packet))) => {
                    let rtt = send_time.elapsed();
                    let frame = match Frame::from_buf(&packet, parse_option.clone()) {
                        Some(frame) => frame,
                        None => {
                            eprintln!("Failed to parse packet: {:?}", packet);
                            continue;
                        }
                    };
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
                            if IpAddr::V4(ipv4_header.source) == setting.dst_ip
                                && src_ip_set.contains(&IpAddr::V4(ipv4_header.destination))
                            {
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
                                            hop: crate::util::ip::initial_ttl(ipv4_header.ttl)
                                                - ipv4_header.ttl,
                                            rtt: rtt,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::Icmp,
                                            node_type: NodeType::Destination,
                                            sent_packet_size: icmp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        tracing::info!("Reply from {}, bytes={} RTT={:?} TTL={}", setting.dst_ip, packet.len(), rtt, ipv4_header.ttl);
                                        responses.push(probe_result);
                                        header_span.pb_inc(1);
                                        break;
                                    }
                                }
                            }
                        }
                        // IPv6
                        if let Some(ipv6_header) = &ip_layer.ipv6 {
                            if IpAddr::V6(ipv6_header.source) == setting.dst_ip
                                && src_ip_set.contains(&IpAddr::V6(ipv6_header.destination))
                            {
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
                                            hop: crate::util::ip::initial_ttl(ipv6_header.hop_limit)
                                                - ipv6_header.hop_limit,
                                            rtt: rtt,
                                            probe_status: ProbeStatus::new(),
                                            protocol: Protocol::Icmp,
                                            node_type: NodeType::Destination,
                                            sent_packet_size: icmp_packet.len(),
                                            received_packet_size: packet.len(),
                                        };
                                        tracing::info!("Reply from {}, bytes={} RTT={:?} TTL={}", setting.dst_ip, packet.len(), rtt, ipv6_header.hop_limit);
                                        responses.push(probe_result);
                                        header_span.pb_inc(1);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                },
                Ok(Some(Err(e))) => {
                    tracing::error!("Failed to receive packet: {}", e);
                    header_span.pb_inc(1);
                    break;
                },
                Ok(None) => {
                    tracing::error!("Channel closed");
                    header_span.pb_inc(1);
                    break;
                },
                Err(_) => {
                    tracing::error!("Request timeout for seq {}", seq);
                    let probe_result = ProbeResult::timeout(
                        seq,
                        setting.dst_ip,
                        setting.dst_hostname.clone(),
                        Protocol::Icmp,
                        icmp_packet.len(),
                    );
                    responses.push(probe_result);

                    header_span.pb_inc(1);
                    break;
                }
            }

            let elapsed_time: Duration = send_time.elapsed();
            if elapsed_time > setting.receive_timeout {
                tracing::error!("Request timeout for seq {}", seq);
                let probe_result = ProbeResult::timeout(
                    seq,
                    setting.dst_ip,
                    setting.dst_hostname.clone(),
                    Protocol::Icmp,
                    icmp_packet.len(),
                );
                responses.push(probe_result);

                header_span.pb_inc(1);
                break;
            }
        }
        if !setting.send_rate.is_zero() {
            tokio::time::sleep(setting.send_rate).await;
        }
    }

    // Finish header span
    drop(header_span);

    let elapsed_time = start_time.elapsed();
    let received_count: usize = responses
        .iter()
        .filter(|r| r.probe_status.kind == ProbeStatusKind::Done)
        .count();

    let min_opt = if received_count > 0 {
        let min = responses
            .iter()
            .map(|r| r.rtt)
            .min()
            .unwrap_or(Duration::from_millis(0));
        Some(min)
    } else {
        None
    };

    let avg_opt = if received_count > 0 {
        let total = responses
            .iter()
            .map(|r| r.rtt)
            .fold(Duration::from_millis(0), |acc, rtt| acc + rtt);
        Some(total / received_count as u32)
    } else {
        None
    };

    let max_opt = if received_count > 0 {
        let max = responses
            .iter()
            .map(|r| r.rtt)
            .max()
            .unwrap_or(Duration::from_millis(0));
        Some(max)
    } else {
        None
    };

    let ping_stat: PingStat = PingStat {
        responses: responses.clone(),
        probe_time: elapsed_time,
        transmitted_count: setting.count as usize,
        received_count: received_count,
        min: min_opt,
        avg: avg_opt,
        max: max_opt,
    };

    result.probe_status = ProbeStatus::new();
    result.elapsed_time = elapsed_time;
    result.ip_addr = setting.dst_ip;
    result.hostname = setting.dst_hostname.clone();
    result.port_number = setting.dst_port;
    result.protocol = Protocol::Icmp;
    result.stat = ping_stat;

    Ok(result)
}
