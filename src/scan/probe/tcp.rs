use anyhow::Result;
use futures::future::poll_fn;
use futures::stream::{self, StreamExt};
use netdev::{Interface, MacAddr};
use nex::datalink::async_io::{AsyncChannel, AsyncRawSender, async_channel};
use nex::packet::frame::Frame;
use nex::packet::ip::IpNextProtocol;
use nex::packet::tcp::TcpFlags;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::TcpStream;
use tracing_indicatif::span_ext::IndicatifSpanExt;

use crate::capture::pcap::PacketCaptureOptions;
use crate::cli::PortScanMethod;
use crate::endpoint::{
    EndpointResult, OsGuess, Port, PortResult, PortState, ServiceInfo, TransportProtocol,
};
use crate::output::ScanResult;
use crate::probe::ProbeSetting;

/// Run a TCP connect scan based on the provided probe settings.
pub async fn run_connect_scan(setting: ProbeSetting) -> Result<ScanResult> {
    let concurrency = setting.port_concurrency.max(1);
    let connect_timeout = setting.connect_timeout;
    let deadline = tokio::time::Instant::now() + setting.task_timeout;
    let start_time = std::time::Instant::now();
    let mut endpoint_map: BTreeMap<IpAddr, EndpointResult> = BTreeMap::new();
    let mut work_items: Vec<(IpAddr, Port)> = Vec::new();

    for target in setting.target_endpoints {
        endpoint_map.insert(
            target.ip,
            EndpointResult {
                ip: target.ip,
                hostname: target.hostname,
                ports: BTreeMap::new(),
                mac_addr: target.mac_addr,
                vendor_name: None,
                os: OsGuess::default(),
                tags: target.tags,
                cpes: Vec::new(),
            },
        );
        for port in target.ports {
            work_items.push((target.ip, port));
        }
    }

    if work_items.is_empty() {
        let mut result = ScanResult::new();
        result.endpoints = endpoint_map.into_values().collect();
        result.scan_time = start_time.elapsed();
        result.fingerprints = Vec::new();
        return Ok(result);
    }

    let header_span = tracing::info_span!("tcp_connect_scan");
    header_span.pb_set_style(&crate::output::progress::get_progress_style());
    header_span.pb_set_message("TCP PortScan");
    header_span.pb_set_length(work_items.len() as u64);
    header_span.pb_set_position(0);
    header_span.pb_start();

    let mut connect_stream = stream::iter(work_items)
        .map(move |(ip, port)| async move {
            let socket_addr = SocketAddr::new(ip, port.number);
            let mut port_result = PortResult {
                port,
                state: PortState::Filtered,
                service: ServiceInfo::default(),
                rtt_ms: None,
            };

            let started = std::time::Instant::now();
            match tokio::time::timeout(connect_timeout, TcpStream::connect(socket_addr)).await {
                Ok(Ok(stream)) => {
                    port_result.state = PortState::Open;
                    port_result.rtt_ms =
                        Some(started.elapsed().as_millis().min(u32::MAX as u128) as u32);
                    drop(stream);
                }
                Ok(Err(error)) => port_result.state = classify_connect_error(&error)?,
                Err(_) => {}
            }

            Ok::<_, anyhow::Error>((ip, port_result))
        })
        .buffer_unordered(concurrency);

    while let Some(item) = tokio::time::timeout_at(deadline, connect_stream.next())
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "port scan deadline exceeded; split the scan or increase --task-timeout-ms"
            )
        })?
    {
        let (ip, port_result) = item?;
        if let Some(endpoint) = endpoint_map.get_mut(&ip) {
            endpoint.upsert_port(port_result);
        }
        header_span.pb_inc(1);
    }

    drop(header_span);

    let mut result = ScanResult::new();
    result.endpoints = endpoint_map.into_values().collect();
    result.scan_time = start_time.elapsed();
    result.fingerprints = Vec::new();
    Ok(result)
}

/// Send TCP SYN packets for port scanning.
pub async fn send_portscan_packets(
    tx: &mut Box<dyn AsyncRawSender>,
    interface: &Interface,
    scan_setting: &ProbeSetting,
) -> Result<()> {
    for target in &scan_setting.target_endpoints {
        let header_span = tracing::info_span!("tcp_syn_scan");
        header_span.pb_set_style(&crate::output::progress::get_progress_style());
        header_span.pb_set_message(&format!("PortScan ({})", target.ip));
        header_span.pb_set_length(target.ports.len() as u64);
        header_span.pb_set_position(0);
        header_span.pb_start();

        for port in &target.ports {
            let packet = match crate::packet::tcp::build_tcp_syn_packet(
                interface,
                target.ip,
                port.number,
                false,
            ) {
                Ok(packet) => packet,
                Err(e) => {
                    tracing::error!(
                        "Failed to build TCP SYN packet for {}:{}: {}",
                        target.ip,
                        port.number,
                        e
                    );
                    return Err(e);
                }
            };

            // Send a packet using poll_fn.
            match poll_fn(|cx| tx.poll_send(cx, &packet)).await {
                Ok(_) => {
                    if !scan_setting.send_rate.is_zero() {
                        tokio::time::sleep(scan_setting.send_rate).await;
                    }
                }
                Err(e) => return Err(e.into()),
            }
            header_span.pb_inc(1);
        }
        drop(header_span);
    }
    Ok(())
}

/// Send TCP SYN packets for host scanning.
pub async fn send_hostscan_packets(
    tx: &mut Box<dyn AsyncRawSender>,
    interface: &Interface,
    scan_setting: &ProbeSetting,
) -> Result<()> {
    let header_span = tracing::info_span!("tcp_syn_host_scan");
    header_span.pb_set_style(&crate::output::progress::get_progress_style());
    header_span.pb_set_message("HostScan");
    header_span.pb_set_length(scan_setting.target_endpoints.len() as u64);
    header_span.pb_set_position(0);
    header_span.pb_start();

    for target in &scan_setting.target_endpoints {
        for port in &target.ports {
            let packet = match crate::packet::tcp::build_tcp_syn_packet(
                interface,
                target.ip,
                port.number,
                false,
            ) {
                Ok(packet) => packet,
                Err(e) => {
                    tracing::error!(
                        "Failed to build TCP SYN packet for {}:{}: {}",
                        target.ip,
                        port.number,
                        e
                    );
                    return Err(e);
                }
            };

            // Send a packet using poll_fn.
            match poll_fn(|cx| tx.poll_send(cx, &packet)).await {
                Ok(_) => {
                    if !scan_setting.send_rate.is_zero() {
                        tokio::time::sleep(scan_setting.send_rate).await;
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        header_span.pb_inc(1);
    }
    drop(header_span);
    Ok(())
}

/// Run a TCP SYN scan based on the provided probe settings.
pub async fn run_syn_scan(setting: ProbeSetting) -> Result<ScanResult> {
    let interface = match crate::interface::get_interface_by_index(setting.if_index) {
        Some(interface) => interface,
        None => return Err(anyhow::anyhow!("Interface not found")),
    };
    // Create sender
    let mut config = nex::datalink::Config::default();
    config.write_buffer_size = 4096;
    config.read_buffer_size = 4096;
    config.read_timeout = Some(setting.wait_time);
    config.write_timeout = None;
    config.channel_type = nex::datalink::ChannelType::Layer2;
    config.bpf_fd_attempts = 1000;
    config.linux_fanout = None;
    config.promiscuous = false;

    let AsyncChannel::Ethernet(mut tx, mut rx) = async_channel(&interface.clone().into(), config)?
    else {
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
    for endpoint in setting.target_endpoints.clone() {
        capture_options.src_ips.insert(endpoint.ip);
        capture_options
            .src_ports
            .extend(endpoint.ports.iter().map(|p| p.number));
    }
    capture_options.ip_protocols.insert(IpNextProtocol::Tcp);
    capture_options
        .dst_ports
        .insert(crate::config::default::DEFAULT_LOCAL_TCP_PORT);
    capture_options
        .dst_ips
        .extend(interface.ipv4_addrs().into_iter().map(IpAddr::V4));
    capture_options
        .dst_ips
        .extend(interface.ipv6_addrs().into_iter().map(IpAddr::V6));

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();

    let capture_handle: tokio::task::JoinHandle<_> = tokio::spawn(async move {
        crate::capture::pcap::start_capture(&mut rx, capture_options, ready_tx, &mut stop_rx).await
    });

    // Wait for listener to start
    ready_rx
        .await
        .map_err(|_| anyhow::anyhow!("packet capture failed to start"))?;
    let start_time = std::time::Instant::now();
    // Send probe packets
    let send_result = tokio::time::timeout(
        setting.task_timeout,
        send_portscan_packets(&mut tx, &interface, &setting),
    )
    .await;
    if !matches!(send_result, Ok(Ok(()))) {
        capture_handle.abort();
        send_result.map_err(|_| anyhow::anyhow!("packet transmission deadline exceeded"))??;
    }
    tokio::time::sleep(setting.wait_time).await;
    // Stop pcap
    let _ = stop_tx.send(());
    let frames = capture_handle
        .await
        .map_err(|e| anyhow::anyhow!("capture task join error: {}", e))??;
    let dns_map = setting.get_dns_map();
    let mut result = parse_portscan_result(frames, &interface, &dns_map);
    let mut endpoints: BTreeMap<_, _> =
        result.endpoints.into_iter().map(|ep| (ep.ip, ep)).collect();
    for target in &setting.target_endpoints {
        let endpoint = endpoints.entry(target.ip).or_insert_with(|| {
            let mut endpoint = EndpointResult::new(target.ip);
            endpoint.hostname = target.hostname.clone();
            endpoint
        });
        let target_ports: HashSet<_> = target.ports.iter().copied().collect();
        endpoint.ports.retain(|port, _| target_ports.contains(port));
        for port in &target.ports {
            endpoint.ports.entry(*port).or_insert(PortResult {
                port: *port,
                state: PortState::Filtered,
                service: ServiceInfo::default(),
                rtt_ms: None,
            });
        }
    }
    result.endpoints = endpoints.into_values().collect();
    result.scan_time = start_time.elapsed();
    Ok(result)
}

/// Run a TCP port scan using the specified probe settings and method.
pub async fn run_port_scan(setting: ProbeSetting, method: PortScanMethod) -> Result<ScanResult> {
    match method {
        PortScanMethod::Connect => run_connect_scan(setting).await,
        PortScanMethod::Syn => run_syn_scan(setting).await,
    }
}

/// Run a TCP host scan based on the provided probe settings.
pub async fn run_host_scan(setting: ProbeSetting) -> Result<ScanResult> {
    let interface = match crate::interface::get_interface_by_index(setting.if_index) {
        Some(interface) => interface,
        None => return Err(anyhow::anyhow!("Interface not found")),
    };
    // Create sender
    let mut config = nex::datalink::Config::default();
    config.write_buffer_size = 4096;
    config.read_buffer_size = 4096;
    config.read_timeout = Some(setting.wait_time);
    config.write_timeout = None;
    config.channel_type = nex::datalink::ChannelType::Layer2;
    config.bpf_fd_attempts = 1000;
    config.linux_fanout = None;
    config.promiscuous = false;

    let AsyncChannel::Ethernet(mut tx, mut rx) = async_channel(&interface.clone().into(), config)?
    else {
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
        capture_options
            .src_ports
            .extend(endpoint.ports.iter().map(|p| p.number));
    }
    capture_options.ip_protocols.insert(IpNextProtocol::Tcp);
    capture_options
        .dst_ports
        .insert(crate::config::default::DEFAULT_LOCAL_TCP_PORT);
    capture_options
        .dst_ips
        .extend(interface.ipv4_addrs().into_iter().map(IpAddr::V4));
    capture_options
        .dst_ips
        .extend(interface.ipv6_addrs().into_iter().map(IpAddr::V6));

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel();

    let capture_handle: tokio::task::JoinHandle<_> = tokio::spawn(async move {
        crate::capture::pcap::start_capture(&mut rx, capture_options, ready_tx, &mut stop_rx).await
    });

    // Wait for listener to start
    ready_rx
        .await
        .map_err(|_| anyhow::anyhow!("packet capture failed to start"))?;
    let start_time = std::time::Instant::now();
    // Send probe packets
    let send_result = tokio::time::timeout(
        setting.task_timeout,
        send_hostscan_packets(&mut tx, &interface, &setting),
    )
    .await;
    if !matches!(send_result, Ok(Ok(()))) {
        capture_handle.abort();
        send_result.map_err(|_| anyhow::anyhow!("packet transmission deadline exceeded"))??;
    }
    tokio::time::sleep(setting.wait_time).await;
    // Stop pcap
    let _ = stop_tx.send(());
    let frames = capture_handle
        .await
        .map_err(|e| anyhow::anyhow!("capture task join error: {}", e))??;
    let dns_map = setting.get_dns_map();
    let mut result = parse_hostscan_result(frames, &interface, &dns_map);
    result.scan_time = start_time.elapsed();
    Ok(result)
}

/// Parse port scan results from captured packets.
fn parse_portscan_result(
    packets: Vec<Frame>,
    iface: &Interface,
    dns_map: &HashMap<IpAddr, String>,
) -> ScanResult {
    let mut result: ScanResult = ScanResult::new();
    let mut socket_set: HashSet<SocketAddr> = HashSet::new();
    let mut endpoint_map: HashMap<IpAddr, EndpointResult> = HashMap::new();
    for p in packets {
        if p.ip.is_none() || p.transport.is_none() {
            continue;
        }
        let mac_addr: MacAddr;
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
        let port: PortResult;
        if let Some(ip) = &p.ip {
            if let Some(ipv4_packet) = &ip.ipv4 {
                ip_addr = IpAddr::V4(ipv4_packet.source);
                ttl = ipv4_packet.ttl;
            } else if let Some(ipv6_packet) = &ip.ipv6 {
                ip_addr = IpAddr::V6(ipv6_packet.source);
                ttl = ipv6_packet.hop_limit;
            } else {
                continue;
            }
        } else {
            continue;
        }
        if let Some(transport) = &p.transport {
            if let Some(tcp_packet) = &transport.tcp {
                if socket_set.contains(&SocketAddr::new(ip_addr, tcp_packet.source)) {
                    continue;
                }
                let f = tcp_packet.flags;
                if (f & TcpFlags::RST) != 0 {
                    port = PortResult {
                        port: Port::new(tcp_packet.source, TransportProtocol::Tcp),
                        state: PortState::Closed,
                        service: ServiceInfo::default(),
                        rtt_ms: None,
                    };
                } else if (f & (TcpFlags::SYN | TcpFlags::ACK)) == (TcpFlags::SYN | TcpFlags::ACK) {
                    port = PortResult {
                        port: Port::new(tcp_packet.source, TransportProtocol::Tcp),
                        state: PortState::Open,
                        service: ServiceInfo::default(),
                        rtt_ms: None,
                    };
                } else {
                    continue;
                }
            } else {
                continue;
            }
        } else {
            continue;
        }
        endpoint_map
            .entry(ip_addr)
            .or_insert(EndpointResult {
                ip: ip_addr,
                hostname: dns_map.get(&ip_addr).cloned(),
                ports: BTreeMap::new(),
                mac_addr: Some(mac_addr),
                vendor_name: None,
                os: OsGuess::default().with_ttl_observed(ttl),
                tags: Vec::new(),
                cpes: Vec::new(),
            })
            .ports
            .insert(port.port, port.clone());

        result.fingerprints.push(p.clone());
        socket_set.insert(SocketAddr::new(ip_addr, port.port.number));
    }
    for (ip, endpoint) in endpoint_map {
        let mut ep = EndpointResult::new(ip);
        ep.hostname = endpoint.hostname;
        ep.mac_addr = endpoint.mac_addr;
        ep.vendor_name = endpoint.vendor_name;
        ep.os = endpoint.os;
        ep.tags = endpoint.tags;
        for (_port, port_result) in endpoint.ports {
            ep.upsert_port(port_result);
        }
        result.endpoints.push(ep);
    }
    result
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
    let mut socket_set: HashSet<SocketAddr> = HashSet::new();
    let mut endpoint_map: HashMap<IpAddr, EndpointResult> = HashMap::new();
    for p in packets {
        if p.ip.is_none() || p.transport.is_none() {
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
        let port: PortResult;
        if let Some(ip) = &p.ip {
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
        if let Some(transport) = &p.transport {
            if let Some(tcp_packet) = &transport.tcp {
                if socket_set.contains(&SocketAddr::new(ip_addr, tcp_packet.source)) {
                    continue;
                }
                let f = tcp_packet.flags;
                if (f & (TcpFlags::SYN | TcpFlags::ACK)) == (TcpFlags::SYN | TcpFlags::ACK) {
                    port = PortResult {
                        port: Port::new(tcp_packet.source, TransportProtocol::Tcp),
                        state: PortState::Open,
                        service: ServiceInfo::default(),
                        rtt_ms: None,
                    };
                } else if f & TcpFlags::RST != 0 {
                    port = PortResult {
                        port: Port::new(tcp_packet.source, TransportProtocol::Tcp),
                        state: PortState::Closed,
                        service: ServiceInfo::default(),
                        rtt_ms: None,
                    };
                } else {
                    continue;
                }
            } else {
                continue;
            }
        } else {
            continue;
        }

        let vendor_name_opt = crate::db::oui::lookup_vendor_name(&mac_addr);

        let os_guess = OsGuess::default().with_ttl_observed(ttl);
        let cpes = Vec::new();

        endpoint_map
            .entry(ip_addr)
            .or_insert(EndpointResult {
                ip: ip_addr,
                hostname: dns_map.get(&ip_addr).cloned(),
                ports: BTreeMap::new(),
                mac_addr: Some(mac_addr),
                vendor_name: vendor_name_opt,
                os: os_guess,
                tags: Vec::new(),
                cpes,
            })
            .ports
            .insert(port.port, port.clone());

        result.fingerprints.push(p.clone());
        socket_set.insert(SocketAddr::new(ip_addr, port.port.number));
    }
    for (ip, endpoint) in endpoint_map {
        let mut ep = EndpointResult::new(ip);
        ep.hostname = endpoint.hostname;
        ep.mac_addr = endpoint.mac_addr;
        ep.vendor_name = endpoint.vendor_name;
        ep.os = endpoint.os;
        ep.cpes = endpoint.cpes;
        ep.tags = endpoint.tags;
        for (_port, port_result) in endpoint.ports {
            ep.upsert_port(port_result);
        }
        result.endpoints.push(ep);
    }
    result
}

/// Only an explicit refusal proves a TCP port is closed.
fn classify_connect_error(error: &std::io::Error) -> Result<PortState> {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::ConnectionRefused => Ok(PortState::Closed),
        ErrorKind::TimedOut
        | ErrorKind::HostUnreachable
        | ErrorKind::NetworkUnreachable
        | ErrorKind::PermissionDenied => Ok(PortState::Filtered),
        _ => Err(anyhow::anyhow!("TCP connect failed: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Error, ErrorKind},
        time::Duration,
    };

    #[test]
    fn connection_errors_preserve_uncertainty() {
        assert_eq!(
            classify_connect_error(&Error::from(ErrorKind::ConnectionRefused)).unwrap(),
            PortState::Closed
        );
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
        ] {
            assert_eq!(
                classify_connect_error(&Error::from(kind)).unwrap(),
                PortState::Filtered
            );
        }
        assert!(classify_connect_error(&Error::from(ErrorKind::OutOfMemory)).is_err());
    }

    #[tokio::test]
    async fn connect_scan_reports_local_open_and_refused_ports() {
        let open = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = Port::new(open.local_addr().unwrap().port(), TransportProtocol::Tcp);
        let closed_port = Port::new(closed.local_addr().unwrap().port(), TransportProtocol::Tcp);
        drop(closed);
        let mut endpoint = crate::endpoint::Endpoint::new("127.0.0.1".parse().unwrap());
        endpoint.upsert_port(open_port);
        endpoint.upsert_port(closed_port);
        let result = run_connect_scan(ProbeSetting {
            target_endpoints: vec![endpoint],
            if_index: 0,
            host_concurrency: 1,
            port_concurrency: 2,
            task_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_secs(1),
            wait_time: Duration::ZERO,
            send_rate: Duration::ZERO,
        })
        .await
        .unwrap();
        assert_eq!(result.endpoints[0].ports[&open_port].state, PortState::Open);
        assert_eq!(
            result.endpoints[0].ports[&closed_port].state,
            PortState::Closed
        );
        assert!(result.endpoints[0].ports[&open_port].rtt_ms.is_some());
    }
}
