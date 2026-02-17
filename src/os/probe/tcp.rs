use futures::stream::StreamExt;
use futures::future::poll_fn;
use nex::datalink::async_io::{async_channel, AsyncChannel};
use nex::packet::frame::{Frame, ParseOption};
use tracing_indicatif::span_ext::IndicatifSpanExt;
use std::collections::BTreeMap;
use anyhow::Result;
use crate::config::default::DEFAULT_LOCAL_TCP_PORT;
use crate::endpoint::{EndpointResult, OsGuess, Port, PortResult, PortState, ServiceInfo, TransportProtocol};
use crate::output::port::OsProbeResult;
use crate::probe::ProbeSetting;

/// Run OS detection probe using TCP SYN packets and return the results.
pub async fn run_os_probe(
    setting: ProbeSetting,
) -> Result<OsProbeResult> {
    let mut result = OsProbeResult::new();
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

    let AsyncChannel::Ethernet(mut tx, mut rx) = async_channel(&interface, config)?
    else {
        unreachable!();
    };

    let mut parse_option: ParseOption = ParseOption::default();
    if interface.is_tun() || (cfg!(any(target_os = "macos", target_os = "ios")) && interface.is_loopback()) {
        let payload_offset = if interface.is_loopback() { 14 } else { 0 };
        parse_option.from_ip_packet = true;
        parse_option.offset = payload_offset;
    }
    let start_time = std::time::Instant::now();
    for target in setting.target_endpoints {
        let header_span = tracing::info_span!("os_probe");
        header_span.pb_set_style(&crate::output::progress::get_progress_style());
        header_span.pb_set_message(&format!("OS Probe ({})", target.ip));
        header_span.pb_set_length(target.ports.len() as u64);
        header_span.pb_set_position(0);
        header_span.pb_start();

        let mut detected: bool = false;
        for port in &target.ports {
            let packet = crate::packet::tcp::build_tcp_syn_packet(
                &interface,
                target.ip,
                port.number,
                false,
            )?;

            // Send a packet using poll_fn.
            match poll_fn(|cx| tx.poll_send(cx, &packet)).await {
                Ok(_) => {
                    // TODO!
                }
                Err(e) => tracing::error!("Failed to send packet: {}", e),
            }
            loop {
                match tokio::time::timeout(setting.wait_time, rx.next()).await {
                    Ok(Some(Ok(packet))) => {
                        let frame = match Frame::from_buf(&packet, parse_option.clone()) {
                            Some(frame) => frame,
                            None => {
                                eprintln!("Failed to parse packet: {:?}", packet);
                                continue;
                            }
                        };
                        if frame.ip.is_none() || frame.transport.is_none() {
                            continue;
                        }
                        let ttl: u8;
                        let ip = frame.ip.as_ref().unwrap();
                        if let Some(ipv4) = &ip.ipv4 {
                            if ipv4.source != target.ip {
                                continue;
                            }
                            ttl = ipv4.ttl;
                        } else if let Some(ipv6) = &ip.ipv6 {
                            if ipv6.source != target.ip {
                                continue;
                            }
                            ttl = ipv6.hop_limit;
                        } else {
                            continue;
                        }
                        if let Some(transport) = &frame.transport {
                            if let Some(tcp) = &transport.tcp {
                                if tcp.destination != DEFAULT_LOCAL_TCP_PORT {
                                    continue;
                                }
                                if tcp.options.len() == 0 {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                        tracing::debug!("Matching frame...: {:?}", frame.transport.as_ref().unwrap().tcp);
                        match crate::os::match_tcpip_signatures(&frame) {
                           Some(os_match) => {
                                let port_result = PortResult {
                                    port: Port::new(port.number, TransportProtocol::Tcp),
                                    state: PortState::Open,
                                    service: ServiceInfo::default(),
                                    rtt_ms: None,
                                };
                                let endpoint_result = EndpointResult {
                                    ip: target.ip,
                                    hostname: target.hostname.clone(),
                                    ports: BTreeMap::from([(port_result.port.clone(), port_result)]),
                                    mac_addr: target.mac_addr,
                                    vendor_name: None,
                                    os: OsGuess {
                                        family: Some(os_match.family),
                                        confidence: Some(os_match.confidence as f32),
                                        ttl_observed: Some(ttl),
                                    },
                                    tags: target.tags.clone(),
                                    cpes: os_match.cpes,
                                };
                                result.endpoints.push(endpoint_result);
                                result.fingerprints.push(frame);

                                detected = true;
                                break;
                           }
                           None => {
                               tracing::debug!("No matching OS found");
                           }
                       }
                    }
                    Ok(Some(Err(e))) => {
                        tracing::error!("Failed to receive packet: {}", e);
                    }
                    Ok(None) => {
                        break;
                    }
                    Err(e) => {
                        tracing::debug!("Timeout while waiting for response: {}", e);
                        break;
                    }
                }
            }
            if detected {
                break;
            }
            header_span.pb_inc(1);
        }
        drop(header_span);
    }
    result.probe_time = start_time.elapsed();
    Ok(result)
}
